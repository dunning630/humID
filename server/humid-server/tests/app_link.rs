//! The app core's client adapter (crates/humid-link) against the running units, in process:
//! the real humid-core (software gate) seals a document, humid-link carries it over HTP/2
//! through front to core (and core to keys), and the document opens again from what came
//! back. The envelope crosses as binary chunks; the share only ever as sealed boxes.

mod common;

use common::*;
use humid_core::gate::{Prompt, Purpose};
use humid_core::soft_gate::{SoftGate, SoftMode};
use humid_core::store::MemStore;
use humid_core::{Core, DocMeta};
use humid_htp::msg::{HeaderName, Method};
use humid_htp::{CHUNK, Unit};
use humid_link::{Body, Link, LinkError};
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster, OuterTransport};
use humid_server::wire::{B64, Id};
use serde_json::{Value, json};

fn link(c: &Cluster, unit: Unit) -> Link<OuterTransport> {
    let root = humid_pq2::DualVerifyingKey::from_bytes(&c.root.to_bytes()).unwrap();
    let clock = c.clock.clone();
    Link::new(
        unit,
        root,
        humid_server::htp::statement_key_of,
        OuterTransport::new(c.front_addr, &c.front_identity.ca).unwrap(),
        Box::new(move || u64::try_from(clock.now()).unwrap()),
    )
}

#[tokio::test]
async fn humid_core_seals_and_opens_a_document_over_htp2() {
    let c = Cluster::start(|_| {}).await.unwrap();
    // One account seed. The testkit phone derives the account keys from it as humid-core
    // does (CORE.md §2) and signs in; humid-core receives it through its own join path, so
    // the document it seals belongs to the account the server knows.
    let seed = humid_pq2::Secret32::random().unwrap();
    let phone = Phone {
        account: std::sync::Arc::new(humid_server::crypto::MlDsaSecret::from_seed(
            &humid_pq2::kdf::<32>("HUMID-PQ2 account-dsa", &[seed.expose()], &[]).unwrap(),
        )),
        account_kem: std::sync::Arc::new(humid_server::crypto::KemSecret::from_seed(
            &humid_pq2::kdf::<96>("HUMID-PQ2 account-kem", &[seed.expose()], &[]).unwrap(),
        )),
        ..Phone::new().unwrap()
    };
    let mut a = App::new(&c).await.unwrap();
    a.register(&phone).await.unwrap();

    let mut core = Core::new(
        SoftGate::new(SoftMode::PublicTarget, 8),
        MemStore::default(),
    )
    .unwrap();
    let join = core.begin_join(phone.account_id().0).unwrap();
    let req = humid_core::JoinRequest::decode(&join.request).unwrap();
    let grant = [&seed.expose()[..], &0u32.to_be_bytes()].concat(); // seed ‖ no documents
    let sealed_seed = humid_pq2::seal_to(
        &req.join_kem,
        humid_pq2::ObjectType::JOIN_SEED,
        &[&req.account_id, &req.device_id(), &req.binding().unwrap()],
        &grant,
    )
    .unwrap();
    core.finish_join(&Prompt::new(Purpose::Enroll, "test"), &sealed_seed, b"ch")
        .unwrap();
    assert_eq!(core.identity().unwrap().account_id(), phone.account_id().0);
    let kem = keys_kem(&a).await;
    let kem = humid_pq2::KemPublicKey::from_bytes(&kem.to_bytes()).unwrap();

    // a 2.5 MiB document: three chunks each way
    let data: Vec<u8> = (0..(5 * CHUNK / 2)).map(|i| (i * 7 % 251) as u8).collect();
    let mut envelope = vec![];
    let receipt = core
        .seal_document(
            &Prompt::new(Purpose::Seal, "test"),
            &DocMeta {
                name: "passport.pdf".into(),
                media_type: "application/pdf".into(),
            },
            &mut &data[..],
            &mut envelope,
            &kem,
            b"ch",
        )
        .unwrap();
    assert!(envelope.len() > 2 * CHUNK);

    // the upload's proof and binary parts travel through the testkit's link
    let id = Id(receipt.doc_id);
    let body = json!({
        "object": id,
        "envelope_hash": B64(receipt.envelope_hash.to_vec()),
        "manifest_hash": B64(receipt.manifest_hash.to_vec()),
        "sealed_share_hash": B64(humid_pq2::sha3_512(&receipt.share_upload).to_vec()),
        "index": B64(vec![7u8; 64]),
    });
    let signed = a.sign(&phone, "POST", "/v1/objects", &body).unwrap();
    let _: Value = a
        .core(
            "POST",
            "/v1/objects",
            &json!({ "signed": signed, "envelope": B64(envelope.clone()), "sealed_share": B64(receipt.share_upload.clone()) }),
        )
        .await
        .unwrap();
    assert_eq!(c.keys.count_rows("shares").await.unwrap(), 1);
    // front relayed the 2.5 MiB envelope as top-class frames and never saw a byte of it
    let all = c.tap.all_bytes();
    assert!(!all.windows(64).any(|w| w == &envelope[100_000..100_064]));

    // open: humid-core's share request, a proof, the sealed share back, then the chunks
    let st = core
        .begin_open(&Prompt::new(Purpose::Open, "test"), &receipt.slot, b"ch")
        .unwrap();
    a.refill().await.unwrap();
    let path = format!("/v1/objects/{id}/open");
    let ob = json!({ "object": id, "share_request": B64(st.share_request.clone()) });
    let signed = a.sign(&phone, "POST", &path, &ob).unwrap();
    let r: Value = a
        .core("POST", &path, &json!({ "signed": signed }))
        .await
        .unwrap();
    let sealed = B64::decode(r["sealed_share"].as_str().unwrap()).unwrap();
    let ticket = r["ticket"].as_str().unwrap().to_string();
    let n = r["chunks"].as_u64().unwrap();
    let mut got = vec![];
    for i in 0..n {
        let (status, b) = a
            .core_raw(
                "GET",
                &format!("/v1/objects/{id}/chunks/{i}"),
                &[("x-humid-ticket", &ticket)],
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        got.extend_from_slice(&b);
    }
    assert_eq!(got, envelope);
    let mut view = vec![];
    let o = core
        .finish_open(st.handle, &sealed, &mut &got[..], &mut view)
        .unwrap();
    assert_eq!(o.meta.name, "passport.pdf");
    assert_eq!(view, data, "the document opens from what HTP/2 carried");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn the_link_pins_resumes_and_keeps_its_nonce_pool() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut l = link(&c, Unit::Core);
    l.connect().await.unwrap();
    let th = l.th().unwrap();

    // register and sign in with humid-link directly (the app's own path)
    let reg = json!({
        "account_vk": B64(phone.account.public().to_bytes()),
        "kem_pk": B64(phone.account_kem.public().to_bytes()),
        "pop": phone.register_pop(&th).unwrap(),
        "enrolment": phone.enrolment(&th).unwrap(),
    });
    l.request(
        Method::Post,
        "/v1/auth/register",
        &serde_json::to_vec(&reg).unwrap(),
    )
    .await
    .unwrap();
    let ch = l
        .request(
            Method::Post,
            "/v1/auth/challenge",
            &serde_json::to_vec(
                &json!({ "account": phone.account_id(), "device": phone.device_id() }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let ch: Value = serde_json::from_slice(&ch.body).unwrap();
    let ch = B64::decode(ch["challenge"].as_str().unwrap()).unwrap();
    let login = phone.login(&th, &ch, 0).unwrap();
    let r = l
        .request(
            Method::Post,
            "/v1/auth/login",
            &serde_json::to_vec(&login).unwrap(),
        )
        .await
        .unwrap();
    let r: Value = serde_json::from_slice(&r.body).unwrap();
    let token = B64::decode(r["token"].as_str().unwrap()).unwrap();
    let nonces: Vec<[u8; 32]> = r["nonces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            B64::decode(n.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    l.signed_in(&token, &nonces);
    assert_eq!(l.nonces_left(), 8);

    // a step-up in one round trip: reserve, sign, send
    let st = l.step_up().await.unwrap();
    let body = br#"{"window_h":8,"max_window_h":8,"grace_min":60}"#;
    let signed = phone
        .step_up(
            "POST",
            "/v1/checkin/arm",
            &st.th,
            st.seq,
            &st.nonce,
            c.clock.now(),
            body,
        )
        .unwrap();
    let proof = humid_htp::parts::Proof {
        method: "POST".into(),
        path: "/v1/checkin/arm".into(),
        th: st.th,
        seq: st.seq,
        device: phone.device_id().0,
        nonce: st.nonce,
        at: u64::try_from(c.clock.now()).unwrap(),
        mode: 0,
        device_sig: signed.proof.device_sig.0.clone(),
        live_p256: signed.proof.live_p256.0.clone(),
        live_mldsa: None,
        body: body.to_vec(),
    };
    let calls_before = c.tap.seen.lock().unwrap().len();
    let r = l
        .call(
            Some(st.rid),
            Method::Post,
            "/v1/checkin/arm",
            Body::Parts {
                proof: Some(Box::new(proof)),
                json: b"",
                blobs: &[],
            },
            &[],
        )
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        c.tap.seen.lock().unwrap().len(),
        calls_before + 1,
        "one round trip"
    );
    assert_eq!(l.nonces_left(), 7);

    // one delta /sync refills the pool
    let s = l.request(Method::Post, "/v1/sync", b"{}").await.unwrap();
    let s: Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(s["nonces"].as_array().unwrap().len(), 8);

    // lock and unlock: a resumption, not a full handshake; the sign-in holds
    l.lock();
    l.connect().await.unwrap();
    assert_eq!((l.handshakes(), l.resumptions()), (1, 1));
    assert_eq!(
        l.th().unwrap(),
        th,
        "the transcript the sign-in names carries over"
    );
    let r = l
        .call(
            None,
            Method::Get,
            "/v1/me",
            Body::Raw(b""),
            &[(HeaderName::Session, &token)],
        )
        .await
        .unwrap();
    assert_eq!(r.status, 200);

    // a link pinned to another root refuses the server outright
    let mut wrong = {
        let other = humid_server::hsm::SoftHsm::ephemeral().unwrap();
        use humid_server::hsm::Hsm;
        let root = humid_pq2::DualVerifyingKey::from_bytes(
            &other
                .dual_public(humid_server::hsm::KeyRef::IdentityRoot)
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        let clock = c.clock.clone();
        Link::new(
            Unit::Core,
            root,
            humid_server::htp::statement_key_of,
            OuterTransport::new(c.front_addr, &c.front_identity.ca).unwrap(),
            Box::new(move || u64::try_from(clock.now()).unwrap()),
        )
    };
    assert_eq!(
        wrong.connect().await.err(),
        Some(LinkError::IdentityChanged)
    );
    c.stop().await.unwrap();
}
