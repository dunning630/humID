//! Integration tests: the units in-process over real internal TLS, end to end.

mod common;

use common::*;
use humid_server::core::ledger;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::wire::{B64, Id};
use serde_json::{Value, json};

#[tokio::test]
async fn register_upload_open_chunks_sync_delete() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();

    // upload a 2.5 MiB document: core has the envelope, keys the share, neither the other
    let (doc, up) = upload(&mut app, &phone, 5 << 19).await.unwrap();
    assert_eq!(up["object"], json!(doc.id));

    // open: the share comes back sealed to the one-time key, and it is the one uploaded
    let (share, opened, ticket) = open(&mut app, &phone, &doc.id).await.unwrap();
    assert!(share.ct_eq(&doc.share));
    assert_eq!(opened["chunks"], 3);

    // logged before release: object.opened is committed, with the proof hash, before the share left
    let ev = events(&app).await;
    assert_eq!(
        ev,
        [
            "account.created",
            "device.added",
            "object.sealed",
            "object.opened"
        ]
    );
    let last = entries(&app).await.pop().unwrap();
    assert!(
        last["proof"].as_str().is_some_and(|p| p.len() == 64),
        "the open names the live check's proof"
    );

    // chunks, with the ticket; a dropped connection resumes without a new live check
    let t = B64::encode(&ticket);
    let mut got = vec![];
    for n in 0..3 {
        let (status, bytes) = app
            .core_raw(
                "GET",
                &format!("/v1/objects/{}/chunks/{n}", doc.id),
                &[("x-humid-ticket", &t)],
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        got.extend_from_slice(&bytes);
    }
    assert_eq!(got, doc.envelope);
    let (status, _) = app
        .core_raw(
            "GET",
            &format!("/v1/objects/{}/chunks/0", doc.id),
            &[("x-humid-ticket", "AAAA")],
        )
        .await
        .unwrap();
    assert_eq!(status, 403, "no ticket, no bytes");

    // the ticket lapses 60 s after its last use
    c.clock.advance(61_000);
    let (status, _) = app
        .core_raw(
            "GET",
            &format!("/v1/objects/{}/chunks/0", doc.id),
            &[("x-humid-ticket", &t)],
        )
        .await
        .unwrap();
    assert_eq!(status, 403);

    // /sync: one round trip for items, ledger and devices; then only deltas
    let s: Value = app.core("POST", "/v1/sync", &json!({})).await.unwrap();
    assert_eq!(s["changed"].as_array().unwrap().len(), 1);
    assert_eq!(s["ledger"].as_array().unwrap().len(), 4);
    assert!(s["devices"].is_array());
    assert_eq!(
        s["nonces"].as_array().unwrap().len(),
        8,
        "the step-up nonce pool comes with every sync"
    );
    let rev = s["object_rev"].as_i64().unwrap();
    let s2: Value = app
        .core(
            "POST",
            "/v1/sync",
            &json!({ "object_rev": rev, "ledger_seq": 4, "devices_rev": s["devices_rev"] }),
        )
        .await
        .unwrap();
    assert!(s2["changed"].as_array().unwrap().is_empty());
    assert!(s2["ledger"].as_array().unwrap().is_empty());
    assert!(s2["devices"].is_null());

    // delete: keys destroys the share; core keeps a tombstone for /sync
    app.refill().await.unwrap();
    let path = format!("/v1/objects/{}", doc.id);
    let signed = app
        .sign(&phone, "DELETE", &path, &json!({ "object": doc.id }))
        .unwrap();
    let _: Value = app
        .core("DELETE", &path, &json!({ "signed": signed }))
        .await
        .unwrap();
    let s3: Value = app
        .core("POST", "/v1/sync", &json!({ "object_rev": rev }))
        .await
        .unwrap();
    assert_eq!(s3["deleted"], json!([doc.id]));
    let keys_has: i64 = c.keys_db_count("shares").await;
    assert_eq!(keys_has, 0);
    c.stop().await.unwrap();
}

trait KeysDb {
    async fn keys_db_count(&self, table: &str) -> i64;
}
impl KeysDb for Cluster {
    async fn keys_db_count(&self, table: &str) -> i64 {
        // keys' schema is private to the unit; count through its own pool
        humid_server::testkit::cluster::keys_count(self, table).await
    }
}

#[tokio::test]
async fn a_nonce_is_good_for_one_committed_action() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let (doc, _) = upload(&mut app, &phone, 100).await.unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let body = json!({ "object": doc.id, "to": B64(once.public().to_bytes()) });
    let path = format!("/v1/objects/{}/open", doc.id);
    let signed = app.sign(&phone, "POST", &path, &body).unwrap();
    let _: Value = app
        .core("POST", &path, &json!({ "signed": signed }))
        .await
        .unwrap();
    let again = app
        .core::<_, Value>("POST", &path, &json!({ "signed": signed }))
        .await
        .unwrap_err();
    assert_eq!(again.code_str(), "step_up_used");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn a_session_token_only_works_in_its_own_htp_session() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let mut other = App::new(&c).unwrap();
    other.token = app.token.clone(); // a front that copied the token into another HTP session
    let e = other
        .core::<_, Value>("GET", "/v1/me", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code_str(), "no_session");
    let me: Value = app.core("GET", "/v1/me", &json!({})).await.unwrap();
    assert_eq!(me["account"], json!(phone.account_id()));
    c.stop().await.unwrap();
}

#[tokio::test]
async fn device_link_then_removal() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();

    // the new phone asks to join
    let tablet = phone.sibling().unwrap();
    let mut new = App::new(&c).unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let l: Value = new
        .core("POST", "/v1/links", &json!({ "device_vk": B64(tablet.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()), "platform": "tablet" }))
        .await
        .unwrap();
    let code = l["code"].as_str().unwrap().to_string();

    // before approval it can't enrol
    let enrol = json!({ "enrolment": tablet.enrolment(&new.th).unwrap(), "evidence": { "via": "link", "code": code } });
    assert_eq!(
        new.core::<_, Value>("POST", "/v1/devices", &enrol)
            .await
            .unwrap_err()
            .code_str(),
        "not_approved"
    );

    // the existing phone approves it with a live check
    let approve = json!({ "device_vk": B64(tablet.device.public().to_bytes()), "envelope": B64(vec![1u8; 2000]) });
    let path = format!("/v1/links/{code}/approve");
    let signed = app.sign(&phone, "POST", &path, &approve).unwrap();
    let _: Value = app
        .core("POST", &path, &json!({ "signed": signed }))
        .await
        .unwrap();
    let res: Value = new
        .core("GET", &format!("/v1/links/{code}/result"), &json!({}))
        .await
        .unwrap();
    assert_eq!(res["status"], "approved");

    let d: Value = new.core("POST", "/v1/devices", &enrol).await.unwrap();
    assert_eq!(d["via"], "link");
    // the link is spent
    assert_eq!(
        new.core::<_, Value>("POST", "/v1/devices", &enrol)
            .await
            .unwrap_err()
            .code_str(),
        "not_approved"
    );
    new.login(&tablet, 0).await.unwrap();

    // remove the tablet from the phone
    let path = format!("/v1/devices/{}", tablet.device_id());
    let signed = app.sign(&phone, "DELETE", &path, &json!({})).unwrap();
    let _: Value = app
        .core("DELETE", &path, &json!({ "signed": signed }))
        .await
        .unwrap();
    assert_eq!(
        new.core::<_, Value>("GET", "/v1/me", &json!({}))
            .await
            .unwrap_err()
            .code_str(),
        "session_expired",
        "a removed device's sessions end"
    );
    let ev = events(&app).await;
    assert!(ev.ends_with(&[
        "device.link_approved".into(),
        "device.added".into(),
        "device.removed".into()
    ]));
    c.stop().await.unwrap();
}

#[tokio::test]
async fn hardened_recovery_card_and_witness_wait_and_veto() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    // two witnesses
    let w1 = Phone::new().unwrap();
    let w2 = Phone::new().unwrap();
    let mut aw1 = App::new(&c).unwrap();
    aw1.register(&w1).await.unwrap();
    let mut aw2 = App::new(&c).unwrap();
    aw2.register(&w2).await.unwrap();

    // holder-only by default: nothing can be stored
    let card = json!({ "lookup": B64(vec![9u8; 32]), "blob": B64(vec![1u8; 100]) });
    let s = a.sign(&alice, "PUT", "/v1/recovery/card", &card).unwrap();
    assert_eq!(
        a.core::<_, Value>("PUT", "/v1/recovery/card", &json!({ "signed": s }))
            .await
            .unwrap_err()
            .code_str(),
        "holder_only"
    );

    // choose hardened (the account key's own chained statement)
    let body: Value =
        serde_json::from_slice(&alice.mode_body("hardened", 1, &[0u8; 64]).unwrap()).unwrap();
    let s = a.sign(&alice, "PUT", "/v1/recovery/mode", &body).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/mode", &json!({ "signed": s }))
        .await
        .unwrap();
    let s = a.sign(&alice, "PUT", "/v1/recovery/card", &card).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/card", &json!({ "signed": s }))
        .await
        .unwrap();
    let wit = json!({ "threshold": 2, "witnesses": [
        { "account": w1.account_id(), "envelope": B64(vec![2u8; 100]) },
        { "account": w2.account_id(), "envelope": B64(vec![3u8; 100]) },
    ]});
    let s = a
        .sign(&alice, "PUT", "/v1/recovery/witnesses", &wit)
        .unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/witnesses", &json!({ "signed": s }))
        .await
        .unwrap();

    // alice loses her phone; a new one starts a recovery
    let newphone = alice.sibling().unwrap();
    let n = App::new(&c).unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let r: Value = n
        .core("POST", "/v1/recovery/requests", &json!({ "device_vk": B64(newphone.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) }))
        .await
        .unwrap();
    let req = r["request"].as_str().unwrap().to_string();
    let code = r["code"].as_str().unwrap().to_string();
    let st: Value = n
        .core(
            "POST",
            &format!("/v1/recovery/requests/{req}/card"),
            &json!({ "lookup": B64(vec![9u8; 32]) }),
        )
        .await
        .unwrap();
    assert_eq!(st["status"], "collecting", "one proof is never enough");

    // both witnesses help, each with their own live check
    for (app, w) in [(&mut aw1, &w1), (&mut aw2, &w2)] {
        let body = json!({ "account": alice.account_id(), "envelope": B64(vec![4u8; 100]) });
        let path = format!("/v1/recovery/help/{code}");
        let s = app.sign(w, "POST", &path, &body).unwrap();
        let _: Value = app
            .core("POST", &path, &json!({ "signed": s }))
            .await
            .unwrap();
    }
    let st: Value = n
        .core("GET", &format!("/v1/recovery/requests/{req}"), &json!({}))
        .await
        .unwrap();
    assert_eq!(st["status"], "waiting");
    let enrol = json!({ "enrolment": newphone.enrolment(&n.th).unwrap(), "evidence": { "via": "recovery", "request": req } });
    assert_eq!(
        n.core::<_, Value>("POST", "/v1/devices", &enrol)
            .await
            .unwrap_err()
            .code_str(),
        "not_approved",
        "not before the wait"
    );

    // alice still has another device: she sees the alert and vetoes
    let al: Value = a
        .core("GET", "/v1/recovery/alerts", &json!({}))
        .await
        .unwrap();
    let reference = al["alerts"][0]["ref"].as_str().unwrap().to_string();
    // ...but first let the wait run out on a second request to prove release works
    c.clock.advance(72 * 3_600_000 + 1);
    let st: Value = n
        .core("GET", &format!("/v1/recovery/requests/{req}"), &json!({}))
        .await
        .unwrap();
    assert_eq!(st["status"], "released");
    assert_eq!(
        st["pieces"].as_array().unwrap().len(),
        3,
        "card part + two witness pieces, sealed to the new phone"
    );
    a.login(&alice, 0).await.unwrap(); // 72 h later: a new session (15 min idle limit)
    let path = format!("/v1/recovery/alerts/{reference}/cancel");
    let s = a.sign(&alice, "POST", &path, &json!({})).unwrap();
    let _: Value = a
        .core("POST", &path, &json!({ "signed": s }))
        .await
        .unwrap();
    assert_eq!(
        n.core::<_, Value>("POST", "/v1/devices", &enrol)
            .await
            .unwrap_err()
            .code_str(),
        "not_approved",
        "a veto stops it even after the wait"
    );
    c.stop().await.unwrap();
}

#[tokio::test]
async fn recovery_release_enrols_exactly_the_named_device() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let w1 = Phone::new().unwrap();
    let w2 = Phone::new().unwrap();
    let mut aw1 = App::new(&c).unwrap();
    aw1.register(&w1).await.unwrap();
    let mut aw2 = App::new(&c).unwrap();
    aw2.register(&w2).await.unwrap();
    let body: Value =
        serde_json::from_slice(&alice.mode_body("hardened", 1, &[0u8; 64]).unwrap()).unwrap();
    let s = a.sign(&alice, "PUT", "/v1/recovery/mode", &body).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/mode", &json!({ "signed": s }))
        .await
        .unwrap();
    let card = json!({ "lookup": B64(vec![5u8; 32]), "blob": B64(vec![1u8; 100]) });
    let s = a.sign(&alice, "PUT", "/v1/recovery/card", &card).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/card", &json!({ "signed": s }))
        .await
        .unwrap();
    let wit = json!({ "threshold": 2, "witnesses": [
        { "account": w1.account_id(), "envelope": B64(vec![2u8; 100]) },
        { "account": w2.account_id(), "envelope": B64(vec![3u8; 100]) },
    ]});
    let s = a
        .sign(&alice, "PUT", "/v1/recovery/witnesses", &wit)
        .unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/witnesses", &json!({ "signed": s }))
        .await
        .unwrap();

    let newphone = alice.sibling().unwrap();
    let n = App::new(&c).unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let r: Value = n.core("POST", "/v1/recovery/requests", &json!({ "device_vk": B64(newphone.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) })).await.unwrap();
    let (req, code) = (
        r["request"].as_str().unwrap().to_string(),
        r["code"].as_str().unwrap().to_string(),
    );
    let _: Value = n
        .core(
            "POST",
            &format!("/v1/recovery/requests/{req}/card"),
            &json!({ "lookup": B64(vec![5u8; 32]) }),
        )
        .await
        .unwrap();
    for (app, w) in [(&mut aw1, &w1), (&mut aw2, &w2)] {
        let body = json!({ "account": alice.account_id(), "envelope": B64(vec![4u8; 100]) });
        let path = format!("/v1/recovery/help/{code}");
        let s = app.sign(w, "POST", &path, &body).unwrap();
        let _: Value = app
            .core("POST", &path, &json!({ "signed": s }))
            .await
            .unwrap();
    }
    c.clock.advance(72 * 3_600_000 + 1);
    // a thief with the account seed tries to ride the released request with another device key
    let thief = alice.sibling().unwrap();
    let mut t = App::new(&c).unwrap();
    let steal = json!({ "enrolment": thief.enrolment(&t.th).unwrap(), "evidence": { "via": "recovery", "request": req } });
    assert_eq!(
        t.core::<_, Value>("POST", "/v1/devices", &steal)
            .await
            .unwrap_err()
            .code_str(),
        "not_approved"
    );
    let enrol = json!({ "enrolment": newphone.enrolment(&n.th).unwrap(), "evidence": { "via": "recovery", "request": req } });
    let d: Value = n.core("POST", "/v1/devices", &enrol).await.unwrap();
    assert_eq!(d["via"], "recovery");
    a.login(&alice, 0).await.unwrap();
    assert!(
        events(&a)
            .await
            .ends_with(&["device.added".into(), "recovery.completed".into()])
    );
    t.th.clear();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn ledger_chain_and_public_log_proofs_verify() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    for _ in 0..3 {
        upload(&mut app, &phone, 50).await.unwrap();
    }
    // the account's chain links up from genesis
    let r: Value = app
        .core("GET", "/v1/ledger/events?since=0", &json!({}))
        .await
        .unwrap();
    let mut prev = ledger::GENESIS.to_vec();
    for e in r["entries"].as_array().unwrap() {
        let body = B64::decode(e["body"].as_str().unwrap()).unwrap();
        let p = B64::decode(e["prev"].as_str().unwrap()).unwrap();
        assert_eq!(p, prev);
        let h =
            ledger::entry_hash(&phone.account_id(), e["seq"].as_i64().unwrap(), &p, &body).unwrap();
        assert_eq!(
            B64::decode(e["hash"].as_str().unwrap()).unwrap(),
            h.to_vec()
        );
        prev = h.to_vec();
    }
    // dual-signed checkpoint, then an inclusion proof that verifies against it
    let cp = ledger::cut(c.core_db(), c.core_hsm.as_ref(), c.clock.now())
        .await
        .unwrap()
        .unwrap();
    let lk =
        humid_server::crypto::DualPublic::from_bytes(&c.policy.policy.unit_keys.ledger).unwrap();
    assert!(
        lk.verifies(
            humid_server::crypto::label::TLOG_CHECKPOINT,
            &ledger::checkpoint_message(cp.size, &cp.root, cp.at).unwrap(),
            &cp.sig
        ),
        "both halves verify"
    );
    let inc: Value = app
        .core("GET", "/v1/ledger/inclusion", &json!({}))
        .await
        .unwrap();
    let leaf = ledger::leaf_hash(
        &phone.account_id(),
        inc["seq"].as_i64().unwrap(),
        &B64::decode(inc["hash"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let proof: Vec<[u8; 64]> = inc["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            B64::decode(p.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let root: [u8; 64] = cp.root.0.clone().try_into().unwrap();
    assert!(
        ledger::verify_inclusion(
            &leaf,
            inc["leaf"].as_u64().unwrap(),
            cp.size as u64,
            &proof,
            &root
        )
        .unwrap()
    );
    // consistency between two sizes
    let cons: Value = app
        .core(
            "GET",
            &format!("/tlog/consistency?from=2&to={}", cp.size),
            &json!({}),
        )
        .await
        .unwrap();
    assert!(!cons["proof"].as_array().unwrap().is_empty());
    c.stop().await.unwrap();
}

#[tokio::test]
async fn checkin_arm_check_miss_lock_then_erase() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let (keep, _) = upload(&mut app, &phone, 64).await.unwrap();
    let (gone, _) = upload(&mut app, &phone, 64).await.unwrap();
    let arm = json!({ "window_h": 1, "max_window_h": 2, "grace_min": 15, "keep": [keep.id] });
    let s = app.sign(&phone, "POST", "/v1/checkin/arm", &arm).unwrap();
    let st: Value = app
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    assert_eq!(st["state"], "armed");
    // check in once
    c.clock.advance(50 * 60_000);
    app.login(&phone, 0).await.unwrap(); // past the 15 min idle limit: sign in again
    let s = app
        .sign(&phone, "POST", "/v1/checkin/check", &json!({}))
        .unwrap();
    let st: Value = app
        .core("POST", "/v1/checkin/check", &json!({ "signed": s }))
        .await
        .unwrap();
    assert_eq!(st["state"], "armed");
    // miss it: locked, nothing opens
    c.clock.advance(61 * 60_000);
    app.login(&phone, 0).await.unwrap();
    assert_eq!(
        err_code(open(&mut app, &phone, &gone.id).await),
        "checkin_missed"
    );
    // miss the grace too: erased; the decoy stays
    c.clock.advance(15 * 60_000);
    c.keys.tick().await.unwrap();
    app.login(&phone, 0).await.unwrap();
    assert_eq!(
        err_code(open(&mut app, &phone, &gone.id).await),
        "vault_erased"
    );
    let (share, _, _) = open(&mut app, &phone, &keep.id).await.unwrap();
    assert!(
        share.ct_eq(&keep.share),
        "a document kept out of the fuse still opens"
    );
    // core drops the erased envelopes on keys' signed word, and says the server asserted it
    assert_eq!(
        humid_server::core::checkin::sweep_erased(&c.core)
            .await
            .unwrap(),
        1
    );
    let ids: Vec<Id> = {
        let s: Value = app.core("POST", "/v1/sync", &json!({})).await.unwrap();
        s["changed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| serde_json::from_value(i["id"].clone()).unwrap())
            .collect()
    };
    assert_eq!(ids, vec![keep.id]);
    let last = entries(&app)
        .await
        .into_iter()
        .rev()
        .find(|e| e["type"] == "checkin.erased")
        .unwrap();
    assert_eq!(
        last["asserted"], "server",
        "an erase isn't dressed up as a live check"
    );
    c.stop().await.unwrap();
}

#[tokio::test]
async fn duress_sign_in_erases_an_armed_vault_and_locks_down() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let (doc, _) = upload(&mut app, &phone, 64).await.unwrap();
    let s = app
        .sign(
            &phone,
            "POST",
            "/v1/checkin/arm",
            &json!({ "window_h": 8, "max_window_h": 8, "grace_min": 60 }),
        )
        .unwrap();
    let _: Value = app
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    // forced unlock: the duress gesture
    let mut forced = App::new(&c).unwrap();
    forced.login(&phone, 1).await.unwrap();
    // looks ordinary, but the vault is erased and sensitive changes are "busy"
    assert_eq!(
        c.keys.status(&phone.account_id()).await.unwrap().state,
        "erased"
    );
    let tablet = phone.sibling().unwrap();
    let path = format!("/v1/devices/{}", tablet.device_id());
    let s = forced.sign(&phone, "DELETE", &path, &json!({})).unwrap();
    assert_eq!(
        forced
            .core::<_, Value>("DELETE", &path, &json!({ "signed": s }))
            .await
            .unwrap_err()
            .code_str(),
        "busy"
    );
    app.refill().await.unwrap();
    assert_eq!(
        err_code(open(&mut app, &phone, &doc.id).await),
        "vault_erased"
    );
    c.stop().await.unwrap();
}

#[tokio::test]
async fn messaging_post_tokens_relay_tick_ack() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let keys: Value = app
        .anon("GET", "/v1/post-tokens/keys", &json!({}))
        .await
        .unwrap();
    let kid = keys["keys"][0]["kid"].as_str().unwrap().to_string();
    let pk = humid_server::crypto::blind::PublicKey::from_spki(
        &B64::decode(keys["keys"][0]["spki"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    // blind two token messages; one live check approves exactly these
    let msgs = [[1u8; 32], [2u8; 32]];
    let blinded: Vec<_> = msgs.iter().map(|m| pk.client_blind(m).unwrap()).collect();
    let body = json!({ "action": "post-tokens", "blinded": blinded.iter().map(|b| B64(b.0.clone())).collect::<Vec<_>>() });
    let s = app.sign(&phone, "POST", "/v1/live/attest", &body).unwrap();
    let signed_body = s.body.clone();
    let st: Value = app
        .core("POST", "/v1/live/attest", &json!({ "signed": s }))
        .await
        .unwrap();
    // the anonymous session takes core's statement to anon (no account crosses)
    let anon_app = App::new(&c).unwrap();
    let req = json!({ "statement": st["statement"], "signed_body": signed_body, "kid": kid });
    let t: Value = anon_app
        .anon("POST", "/v1/post-tokens", &req)
        .await
        .unwrap();
    assert_eq!(
        anon_app
            .anon::<_, Value>("POST", "/v1/post-tokens", &req)
            .await
            .unwrap_err()
            .code_str(),
        "step_up_used",
        "one live check buys one batch"
    );
    let sigs: Vec<Vec<u8>> = t["blind_sigs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| B64::decode(s.as_str().unwrap()).unwrap())
        .collect();
    let tokens: Vec<Value> = msgs
        .iter()
        .zip(&blinded)
        .zip(&sigs)
        .map(|((m, (_, state)), sig)| {
            let (r, s) = pk.client_finalize(state, sig, m).unwrap();
            json!({ "kid": kid, "msg": B64(m.to_vec()), "randomizer": B64(r.to_vec()), "sig": B64(s) })
        })
        .collect();

    // deposit with a post token
    let boxid = vec![0xABu8; 16];
    let ack_token = vec![7u8; 32];
    let ack_hash = humid_server::anon::relay::token_hash(b"ack", &ack_token).unwrap();
    let dep = json!({ "token": tokens[0], "box": B64(boxid.clone()), "ack_hash": B64(ack_hash), "wire": B64(vec![0u8; 4096]) });
    let _: Value = anon_app
        .anon("POST", "/v1/relay/deposit", &dep)
        .await
        .unwrap();
    assert_eq!(
        anon_app
            .anon::<_, Value>("POST", "/v1/relay/deposit", &dep)
            .await
            .unwrap_err()
            .code_str(),
        "token_spent"
    );

    // a tick reads (fixed size), twice: nothing is deleted on fetch
    let prefix = humid_server::anon::relay::prefix_of(&boxid, 16);
    let mut slots = vec![json!({ "prefix": prefix, "after": 0 })];
    slots.extend((1..16).map(|i| json!({ "prefix": i, "after": 0 })));
    let tick = json!({ "slots": slots });
    let raw1 = c
        .to_anon
        .raw(
            "POST",
            "/v1/relay/tick",
            &[],
            serde_json::to_vec(&tick).unwrap(),
        )
        .await
        .unwrap();
    let raw2 = c
        .to_anon
        .raw(
            "POST",
            "/v1/relay/tick",
            &[],
            serde_json::to_vec(&tick).unwrap(),
        )
        .await
        .unwrap();
    let r1: Value = serde_json::from_slice(&raw1.1).unwrap();
    assert_eq!(r1["got"].as_array().unwrap().len(), 1);
    assert_eq!(
        raw1.1.len(),
        raw2.1.len(),
        "every tick reply is the same size"
    );
    let empty: Value = anon_app.anon("POST", "/v1/relay/tick", &json!({ "slots": (0..16).map(|i| json!({ "prefix": 100 + i, "after": 0 })).collect::<Vec<_>>() })).await.unwrap();
    assert!(empty["got"].as_array().unwrap().is_empty());
    let id = r1["got"][0]["id"].as_i64().unwrap();
    // a wrong ack deletes nothing; the right one deletes
    let n: Value = anon_app
        .anon(
            "POST",
            "/v1/relay/ack",
            &json!({ "acks": [{ "id": id, "token": B64(vec![8u8; 32]) }] }),
        )
        .await
        .unwrap();
    assert_eq!(n["deleted"], 0);
    let n: Value = anon_app
        .anon(
            "POST",
            "/v1/relay/ack",
            &json!({ "acks": [{ "id": id, "token": B64(ack_token) }] }),
        )
        .await
        .unwrap();
    assert_eq!(n["deleted"], 1);
    let r3: Value = anon_app
        .anon("POST", "/v1/relay/tick", &tick)
        .await
        .unwrap();
    assert!(r3["got"].as_array().unwrap().is_empty());
    c.stop().await.unwrap();
}
