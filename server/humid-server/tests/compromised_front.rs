//! The compromised-front suite (audit H1, H2, M1, M2, M3; SERVER.md §11).
//!
//! The attacker holds front: its internal TLS certificate, every HTP session, every byte that
//! crosses it. Often also a copy of the victim's account seed (malware once). These tests
//! prove that core and keys refuse every request that carries no valid holder proof, and that
//! front can't reach keys at all. Where keys is tested directly, it gets a *genuine* core
//! statement, which is stronger than this threat needs: keys refuses even then without the
//! holder's own live proof.

mod common;

use common::*;
use humid_server::api::keys as k;
use humid_server::crypto::KemSecret;
use humid_server::hsm::{KeyRef, SoftHsm};
use humid_server::proofs::{self, DuressProof};
use humid_server::statement;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::wire::{B64, Id};
use serde_json::{Value, json};

async fn setup() -> (Cluster, Phone) {
    (Cluster::start(|_| {}).await.unwrap(), Phone::new().unwrap())
}

fn core_statement<T: serde::Serialize>(c: &Cluster, kind: &str, facts: &T) -> B64 {
    statement::sign(
        c.core_hsm.as_ref(),
        KeyRef::CoreStatement,
        kind,
        c.clock.now(),
        facts,
    )
    .unwrap()
}

fn nonce() -> [u8; 32] {
    humid_server::crypto::random::<32>().unwrap()
}

async fn ledger_len(c: &Cluster, account: &Id) -> i64 {
    let db = c.core_db().conn().await.unwrap();
    db.query_one(
        "SELECT count(*) FROM ledger_entries WHERE account = $1",
        &[&account.as_bytes()],
    )
    .await
    .unwrap()
    .get(0)
}

async fn device_count(c: &Cluster, account: &Id) -> i64 {
    let db = c.core_db().conn().await.unwrap();
    db.query_one(
        "SELECT count(*) FROM devices WHERE account = $1 AND revoked_at IS NULL",
        &[&account.as_bytes()],
    )
    .await
    .unwrap()
    .get(0)
}

async fn locked_down(c: &Cluster, account: &Id) -> bool {
    let db = c.core_db().conn().await.unwrap();
    db.query_one(
        "SELECT lockdown_at IS NOT NULL FROM accounts WHERE id = $1",
        &[&account.as_bytes()],
    )
    .await
    .unwrap()
    .get(0)
}

/* ------------------------------ the split ------------------------------ */

#[tokio::test]
async fn front_cannot_even_connect_to_keys() {
    let (c, _) = setup().await;
    for path in ["/v1/kem-key", "/healthz"] {
        let e = c.front_to_keys.get::<Value>(path, &[]).await.unwrap_err();
        assert_eq!(
            e.code_str(),
            "unit_unavailable",
            "keys refuses front's certificate at the TLS layer ({path})"
        );
    }
    let e = c
        .front_to_keys
        .post::<_, Value>("/v1/duress", &[], &json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code_str(), "unit_unavailable");
    // anon can't reach core either (and anon's certificate is never front's)
    c.stop().await.unwrap();
}

/* ------------------------- H1: device enrolment ------------------------- */

#[tokio::test]
async fn enrolment_without_an_approval_is_refused_even_with_a_copied_seed() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let acct = alice.account_id();
    let before = (device_count(&c, &acct).await, ledger_len(&c, &acct).await);

    // The attacker copied alice's account seed and has a phone of its own: its certificate is
    // genuinely signed by alice's account key. That is exactly what 4.x accepted (H1).
    let thief = alice.sibling().unwrap();
    let mut t = App::new(&c).unwrap();
    let en = thief.enrolment(&t.th).unwrap();
    assert!(
        proofs::check_enrolment(&en, Some(&acct), &t.th, false).is_ok(),
        "the certificate itself is valid: only the evidence can stop it"
    );

    // 1. a link it opened itself, never approved by alice
    let once = KemSecret::generate().unwrap();
    let (_, start) = join(&thief, &acct, &once);
    let l: Value = t.core("POST", "/v1/links", &start).await.unwrap();
    let r = t
        .core::<_, Value>(
            "POST",
            "/v1/devices",
            &json!({ "enrolment": en, "evidence": { "via": "link", "code": l["code"] } }),
        )
        .await;
    assert_eq!(err_code(r), "not_approved");

    // 2. a link alice DID approve, but for another device key (her tablet)
    let tablet = alice.sibling().unwrap();
    let tb = App::new(&c).unwrap();
    let once2 = KemSecret::generate().unwrap();
    let (jr2, start2) = join(&tablet, &acct, &once2);
    let l2: Value = tb.core("POST", "/v1/links", &start2).await.unwrap();
    let code = l2["code"].as_str().unwrap().to_string();
    let path = format!("/v1/links/{code}/approve");
    let s = a
        .sign(&alice, "POST", &path, &approval(&jr2, vec![1; 500]))
        .unwrap();
    let _: Value = a
        .core("POST", &path, &json!({ "signed": s }))
        .await
        .unwrap();
    let r = t
        .core::<_, Value>(
            "POST",
            "/v1/devices",
            &json!({ "enrolment": en, "evidence": { "via": "link", "code": code } }),
        )
        .await;
    assert_eq!(
        err_code(r),
        "not_approved",
        "an approval names one device key"
    );

    // 3. a recovery that doesn't exist, and one that is still collecting proofs
    let r = t.core::<_, Value>("POST", "/v1/devices", &json!({ "enrolment": en, "evidence": { "via": "recovery", "request": B64(vec![7; 16]) } })).await;
    assert_eq!(err_code(r), "not_approved");
    let req: Value = t.core("POST", "/v1/recovery/requests", &json!({ "device_vk": B64(thief.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) })).await.unwrap();
    let r = t.core::<_, Value>("POST", "/v1/devices", &json!({ "enrolment": en, "evidence": { "via": "recovery", "request": req["request"] } })).await;
    assert_eq!(err_code(r), "not_approved");

    // 4. there is no "on front's word" route: no "via register", no internal enrol
    let r = t
        .core::<_, Value>(
            "POST",
            "/v1/devices",
            &json!({ "enrolment": en, "evidence": { "via": "register" } }),
        )
        .await;
    assert_eq!(err_code(r), "bad_json");
    let body = json!({
        "account_vk": B64(thief.account.public().to_bytes()), "kem_pk": B64(thief.account_kem.public().to_bytes()),
        "pop": thief.register_pop(&t.th).unwrap(), "enrolment": en,
    });
    assert_eq!(
        err_code(t.core::<_, Value>("POST", "/v1/auth/register", &body).await),
        "identity_exists",
        "registration never adds a device to an existing account"
    );
    for p in [
        "/internal/devices",
        "/v1/internal/devices",
        "/v1/devices/approve",
    ] {
        let (status, _) = c.to_core.raw("POST", p, &[], b"{}".to_vec()).await.unwrap();
        assert!(status == 404 || status == 405, "{p} -> {status}");
    }

    assert_eq!(
        (
            device_count(&c, &acct).await,
            ledger_len(&c, &acct).await - 1
        ),
        (before.0, before.1),
        "no device joined; only alice's own approval was logged"
    );
    t.th.clear();
    c.stop().await.unwrap();
}

/* --------------------- H2 and opening: key shares --------------------- */

#[tokio::test]
async fn core_refuses_an_open_without_the_holders_live_proof() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 100).await.unwrap();
    let acct = alice.account_id();
    let path = format!("/v1/objects/{}/open", doc.id);
    let n0 = ledger_len(&c, &acct).await;
    let attacker_key = KemSecret::generate().unwrap();

    // no proof at all
    assert_eq!(
        err_code(a.core::<_, Value>("POST", &path, &json!({})).await),
        "bad_json"
    );
    // a proof for another action (front re-targets a delete approval at an open)
    // (same body shape as an open, so only the approved action differs)
    let del = a
        .sign(
            &alice,
            "DELETE",
            &format!("/v1/objects/{}", doc.id),
            &open_body(&alice, &doc.id, &attacker_key),
        )
        .unwrap();
    assert_eq!(
        err_code(
            a.core::<_, Value>("POST", &path, &json!({ "signed": del }))
                .await
        ),
        "step_up_mismatch"
    );
    // front swaps the one-time key for its own after the phone signed: the body is covered
    let mut swapped = a
        .sign(
            &alice,
            "POST",
            &path,
            &open_body(&alice, &doc.id, &KemSecret::generate().unwrap()),
        )
        .unwrap();
    swapped.body = B64(serde_json::to_vec(&open_body(&alice, &doc.id, &attacker_key)).unwrap());
    assert_eq!(
        err_code(
            a.core::<_, Value>("POST", &path, &json!({ "signed": swapped }))
                .await
        ),
        "bad_proof"
    );
    // a proof from a device that isn't enrolled (copied seed, own phone), in alice's session
    let thief = alice.sibling().unwrap();
    let mut forged = a
        .sign(
            &thief,
            "POST",
            &path,
            &open_body(&alice, &doc.id, &attacker_key),
        )
        .unwrap();
    assert_eq!(
        err_code(
            a.core::<_, Value>("POST", &path, &json!({ "signed": forged.clone() }))
                .await
        ),
        "bad_proof"
    );
    forged.proof.device = alice.device_id(); // claim to be alice's device: the signature doesn't match its key
    assert_eq!(
        err_code(
            a.core::<_, Value>("POST", &path, &json!({ "signed": forged }))
                .await
        ),
        "bad_proof"
    );
    // a real proof, but too old (held back by front)
    let old = a
        .sign(
            &alice,
            "POST",
            &path,
            &open_body(&alice, &doc.id, &attacker_key),
        )
        .unwrap();
    c.clock.advance(61_000);
    a.login(&alice, 0).await.unwrap();
    assert_eq!(
        err_code(
            a.core::<_, Value>("POST", &path, &json!({ "signed": old }))
                .await
        ),
        "step_up_stale"
    );
    // a real proof replayed into another HTP session
    let mut other = App::new(&c).unwrap();
    other.login(&alice, 0).await.unwrap();
    let mine = a
        .sign(
            &alice,
            "POST",
            &path,
            &open_body(&alice, &doc.id, &attacker_key),
        )
        .unwrap();
    assert_eq!(
        err_code(
            other
                .core::<_, Value>("POST", &path, &json!({ "signed": mine }))
                .await
        ),
        "session_changed"
    );

    assert_eq!(
        ledger_len(&c, &acct).await,
        n0,
        "nothing refused was logged as an open, and nothing was released"
    );
    assert_eq!(c.keys.count_rows("releases").await.unwrap(), 0);
    c.stop().await.unwrap();
}

/// A release request as core sends it, built from parts so each test can break one.
struct Release {
    statement: B64,
    cert: proofs::DeviceCert,
    signed: proofs::Signed,
}

fn release_parts(c: &Cluster, phone: &Phone, object: &Id, to: &KemSecret) -> Release {
    let th = vec![9u8; 64];
    let body = serde_json::to_vec(&open_body(phone, object, to)).unwrap();
    let signed = phone
        .step_up(
            "POST",
            &format!("/v1/objects/{object}/open"),
            &th,
            1,
            &nonce(),
            c.clock.now(),
            &body,
        )
        .unwrap();
    let ph = proofs::proof_hash(&signed.proof.device_sig).unwrap();
    let facts = k::ReleaseFacts {
        account: phone.account_id(),
        object: *object,
        proof_hash: B64(ph.to_vec()),
        ledger_seq: 1,
        ledger_hash: B64(vec![0; 64]),
    };
    Release {
        statement: core_statement(c, "release", &facts),
        cert: phone.cert(&th),
        signed,
    }
}

async fn send_release(c: &Cluster, object: &Id, r: &Release) -> humid_server::Result<k::Released> {
    let body = k::HolderAction {
        statement: r.statement.clone(),
        cert: r.cert.clone(),
        signed: r.signed.clone(),
    };
    c.core_to_keys
        .post(&format!("/v1/shares/{object}/release"), &[], &body)
        .await
}

#[tokio::test]
async fn keys_refuses_a_release_without_a_valid_holder_proof_even_from_core() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 100).await.unwrap();
    let (other_doc, _) = upload(&mut a, &alice, 100).await.unwrap();
    let to = KemSecret::generate().unwrap();

    // a statement signed by anyone but core's HSM key
    let mut r = release_parts(&c, &alice, &doc.id, &to);
    let rogue = SoftHsm::ephemeral().unwrap();
    let facts = k::ReleaseFacts {
        account: alice.account_id(),
        object: doc.id,
        proof_hash: B64(vec![0; 32]),
        ledger_seq: 1,
        ledger_hash: B64(vec![0; 64]),
    };
    r.statement = statement::sign(
        &rogue,
        KeyRef::CoreStatement,
        "release",
        c.clock.now(),
        &facts,
    )
    .unwrap();
    assert_eq!(err_code(send_release(&c, &doc.id, &r).await), "not_vouched");

    // a genuine core statement, but the device signature is garbage
    let mut r = release_parts(&c, &alice, &doc.id, &to);
    r.signed.proof.device_sig = B64(vec![0; 4640]);
    assert_eq!(err_code(send_release(&c, &doc.id, &r).await), "bad_proof");

    // a genuine statement and a valid proof, but no live signature from the secure chip
    let mut r = release_parts(&c, &alice, &doc.id, &to);
    r.signed.proof.live_p256 = B64(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    assert_eq!(
        err_code(send_release(&c, &doc.id, &r).await),
        "bad_live_proof"
    );

    // a valid proof, but the statement vouches for another one
    let r1 = release_parts(&c, &alice, &doc.id, &to);
    let mut r = release_parts(&c, &alice, &doc.id, &to);
    r.statement = r1.statement.clone();
    assert_eq!(err_code(send_release(&c, &doc.id, &r).await), "not_vouched");

    // a device certificate made by another account key, claiming alice's account (a lying core)
    let thief = Phone::new().unwrap();
    let mut r = release_parts(&c, &thief, &doc.id, &to);
    let facts = k::ReleaseFacts {
        account: alice.account_id(),
        object: doc.id,
        proof_hash: B64(proofs::proof_hash(&r.signed.proof.device_sig)
            .unwrap()
            .to_vec()),
        ledger_seq: 1,
        ledger_hash: B64(vec![0; 64]),
    };
    r.statement = core_statement(&c, "release", &facts);
    let mut forged_cert = thief.cert(&[9u8; 64]);
    forged_cert.account_vk = B64(alice.account.public().to_bytes());
    r.cert = forged_cert;
    assert_eq!(
        err_code(send_release(&c, &doc.id, &r).await),
        "bad_device_cert"
    );

    // a valid proof for one document, aimed at another
    let r = release_parts(&c, &alice, &other_doc.id, &to);
    assert_eq!(
        err_code(send_release(&c, &doc.id, &r).await),
        "step_up_mismatch"
    );

    // the control: every piece valid, it works — once
    let r = release_parts(&c, &alice, &doc.id, &to);
    let ok = send_release(&c, &doc.id, &r).await.unwrap();
    let req = share_request(&alice, &doc.id, &doc.manifest_hash, &to);
    let binding =
        humid_server::crypto::hash(humid_server::crypto::SHARE_REQUEST_LABEL, &[&req]).unwrap();
    let share = humid_server::crypto::phone::open_release(
        &to,
        alice.account_id().as_bytes(),
        doc.id.as_bytes(),
        &binding,
        &ok.sealed,
    )
    .unwrap();
    assert!(share.ct_eq(&doc.share));
    assert_eq!(
        err_code(send_release(&c, &doc.id, &r).await),
        "step_up_used",
        "each proof acts once at keys too"
    );
    c.stop().await.unwrap();
}

#[tokio::test]
async fn an_upload_share_swapped_by_front_is_refused() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    // The phone seals its share; front substitutes one it sealed itself (so it would know it).
    let id = Id::random().unwrap();
    let envelope = vec![5u8; 200];
    let env_hash = humid_server::crypto::sha3_512(&envelope);
    let manifest = manifest_of(&id);
    let kem = keys_kem(&a).await;
    let real = humid_server::crypto::Secret32::random().unwrap();
    let mine = humid_server::crypto::Secret32::random().unwrap();
    let sealed_real = humid_server::crypto::phone::seal_upload(
        &kem,
        alice.account_id().as_bytes(),
        id.as_bytes(),
        &manifest,
        &real,
    )
    .unwrap();
    let sealed_front = humid_server::crypto::phone::seal_upload(
        &kem,
        alice.account_id().as_bytes(),
        id.as_bytes(),
        &manifest,
        &mine,
    )
    .unwrap();
    let body = json!({ "object": id, "envelope_hash": B64(env_hash.to_vec()), "manifest_hash": B64(manifest.to_vec()), "sealed_share_hash": B64(humid_server::crypto::sha3_512(&sealed_real).to_vec()), "index": B64(vec![7; 64]) });
    let s = a.sign(&alice, "POST", "/v1/objects", &body).unwrap();
    let r = a.core::<_, Value>("POST", "/v1/objects", &json!({ "signed": s.clone(), "envelope": B64(envelope.clone()), "sealed_share": B64(sealed_front.clone()) })).await;
    assert_eq!(err_code(r), "step_up_mismatch");

    // even straight to keys with a genuine core statement, the swapped share doesn't match the proof
    let facts = k::UploadFacts {
        account: alice.account_id(),
        object: id,
        envelope_hash: B64(env_hash.to_vec()),
        manifest_hash: B64(manifest.to_vec()),
        proof_hash: B64(proofs::proof_hash(&s.proof.device_sig).unwrap().to_vec()),
    };
    let store = k::Store {
        statement: core_statement(&c, "upload", &facts),
        cert: alice.cert(&a.th),
        signed: s,
        sealed_share: B64(sealed_front),
    };
    assert_eq!(
        err_code(
            c.core_to_keys
                .post::<_, Value>("/v1/shares", &[], &store)
                .await
        ),
        "step_up_mismatch"
    );
    assert_eq!(c.keys.count_rows("shares").await.unwrap(), 0);
    let objects: i64 = c
        .core_db()
        .conn()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM objects", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        objects, 0,
        "core rolled back the envelope when keys refused"
    );
    c.stop().await.unwrap();
}

/* ---------------------------- M3: the ledger ---------------------------- */

#[tokio::test]
async fn front_cannot_write_or_forge_ledger_events() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let acct = alice.account_id();
    let n0 = ledger_len(&c, &acct).await;
    let forged = serde_json::to_vec(
        &json!({ "sub": acct, "type": "device.added", "detail": { "device": Id([1; 32]) } }),
    )
    .unwrap();
    for (m, p) in [
        ("POST", "/v1/ledger/events"),
        ("POST", "/internal/events"),
        ("PUT", "/v1/ledger/events"),
        ("POST", "/v1/ledger"),
        ("POST", "/events"),
    ] {
        let (status, _) = c.to_core.raw(m, p, &[], forged.clone()).await.unwrap();
        assert!(status == 404 || status == 405, "{m} {p} -> {status}");
    }
    // a cosignature from a cosigner that isn't in the signed policy
    let r = c
        .to_core
        .post::<_, Value>(
            "/tlog/cosign",
            &[],
            &json!({ "name": "front", "size": 1, "sig": B64(vec![0; 4640]) }),
        )
        .await;
    assert_eq!(err_code(r), "unknown_cosigner");
    assert_eq!(ledger_len(&c, &acct).await, n0);
    // every entry a live check vouches for names its proof; nothing claims a check it didn't have
    for e in entries(&a).await {
        assert!(e["proof"].is_string() || e["asserted"] == "server", "{e}");
    }
    c.stop().await.unwrap();
}

/* ------------------------- M2: duress and lockdown ------------------------- */

#[tokio::test]
async fn front_cannot_set_off_duress_or_a_lockdown() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let acct = alice.account_id();
    let (doc, _) = upload(&mut a, &alice, 64).await.unwrap();
    let s = a
        .sign(
            &alice,
            "POST",
            "/v1/checkin/arm",
            &json!({ "window_h": 8, "max_window_h": 8, "grace_min": 60 }),
        )
        .unwrap();
    let _: Value = a
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();

    // core has no route that sets a lockdown or a duress signal
    for p in ["/v1/duress", "/internal/duress", "/v1/lockdown"] {
        let (status, _) = c.to_core.raw("POST", p, &[], b"{}".to_vec()).await.unwrap();
        assert!(status == 404 || status == 405, "{p} -> {status}");
    }

    // front flips the duress bit in an ordinary sign-in: the device key signed d = 0
    let t = App::new(&c).unwrap();
    let ch: Value = t
        .core(
            "POST",
            "/v1/auth/challenge",
            &json!({ "account": acct, "device": alice.device_id() }),
        )
        .await
        .unwrap();
    let mut l = alice
        .login(
            &t.th,
            &B64::decode(ch["challenge"].as_str().unwrap()).unwrap(),
            0,
        )
        .unwrap();
    l.duress = 1;
    assert_eq!(
        err_code(t.core::<_, Value>("POST", "/v1/auth/login", &l).await),
        "bad_proof"
    );
    assert!(!locked_down(&c, &acct).await);

    // straight to keys with a genuine core `duress` statement, but an ordinary sign-in
    let th = vec![3u8; 64];
    let ordinary = alice.login(&th, &nonce(), 0).unwrap();
    let mut flipped = ordinary.clone();
    flipped.duress = 1;
    for login in [ordinary, flipped] {
        let req = k::Duress {
            statement: core_statement(&c, "duress", &k::DuressFacts { account: acct }),
            proof: DuressProof {
                cert: alice.cert(&th),
                login,
            },
        };
        assert_eq!(
            err_code(
                c.core_to_keys
                    .post::<_, Value>("/v1/duress", &[], &req)
                    .await
            ),
            "bad_proof"
        );
    }
    // a duress sign-in by another account's device, presented for alice
    let mallory = Phone::new().unwrap();
    let req = k::Duress {
        statement: core_statement(&c, "duress", &k::DuressFacts { account: acct }),
        proof: DuressProof {
            cert: mallory.cert(&th),
            login: mallory.login(&th, &nonce(), 1).unwrap(),
        },
    };
    assert_eq!(
        err_code(
            c.core_to_keys
                .post::<_, Value>("/v1/duress", &[], &req)
                .await
        ),
        "bad_device_cert"
    );
    assert_eq!(
        c.keys.status(&acct).await.unwrap().state,
        "armed",
        "nothing was erased"
    );

    // a real duress sign-in acts exactly once, even if front replays it
    let real = k::Duress {
        statement: core_statement(&c, "duress", &k::DuressFacts { account: acct }),
        proof: DuressProof {
            cert: alice.cert(&th),
            login: alice.login(&th, &nonce(), 1).unwrap(),
        },
    };
    let _: Value = c.core_to_keys.post("/v1/duress", &[], &real).await.unwrap();
    assert_eq!(
        err_code(
            c.core_to_keys
                .post::<_, Value>("/v1/duress", &[], &real)
                .await
        ),
        "already_used"
    );
    let _ = doc;
    c.stop().await.unwrap();
}

#[tokio::test]
async fn keys_refuses_checkin_changes_without_a_live_proof() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let acct = alice.account_id();
    let s = a
        .sign(
            &alice,
            "POST",
            "/v1/checkin/arm",
            &json!({ "window_h": 1, "max_window_h": 1, "grace_min": 0 }),
        )
        .unwrap();
    let _: Value = a
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    // a genuine core statement to disarm (or check in), with no proof: refused
    for action in ["disarm", "check", "arm"] {
        let facts = k::CheckinFacts {
            account: acct,
            action: action.into(),
            proof_hash: Some(B64(vec![0; 32])),
            objects: vec![],
        };
        let req = k::Checkin {
            statement: core_statement(&c, "checkin", &facts),
            cert: None,
            signed: None,
        };
        assert_eq!(
            err_code(
                c.core_to_keys
                    .post::<_, Value>("/v1/checkin", &[], &req)
                    .await
            ),
            "step_up_required",
            "{action}"
        );
    }
    // with a proof for another action (front re-targets a check-in as a disarm)
    let th = vec![4u8; 64];
    let signed = alice
        .step_up(
            "POST",
            "/v1/checkin/check",
            &th,
            1,
            &nonce(),
            c.clock.now(),
            b"{}",
        )
        .unwrap();
    let facts = k::CheckinFacts {
        account: acct,
        action: "disarm".into(),
        proof_hash: Some(B64(proofs::proof_hash(&signed.proof.device_sig)
            .unwrap()
            .to_vec())),
        objects: vec![],
    };
    let req = k::Checkin {
        statement: core_statement(&c, "checkin", &facts),
        cert: Some(alice.cert(&th)),
        signed: Some(signed),
    };
    assert_eq!(
        err_code(
            c.core_to_keys
                .post::<_, Value>("/v1/checkin", &[], &req)
                .await
        ),
        "step_up_mismatch"
    );
    assert_eq!(c.keys.status(&acct).await.unwrap().state, "armed");
    c.stop().await.unwrap();
}

/* ---------------------------- M1: post tokens ---------------------------- */

#[tokio::test]
async fn anon_mints_nothing_on_fronts_word() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let keys: Value = a
        .anon("GET", "/v1/post-tokens/keys", &json!({}))
        .await
        .unwrap();
    let kid = keys["keys"][0]["kid"].clone();
    let body =
        serde_json::to_vec(&json!({ "action": "post-tokens", "blinded": [B64(vec![1; 256])] }))
            .unwrap();
    // a live-check statement signed by front (or anyone) but not core
    let rogue = SoftHsm::ephemeral().unwrap();
    let facts = humid_server::api::anon::LiveCheckFacts {
        action: "post-tokens".into(),
        body_hash: B64(humid_server::crypto::sha3_512(&body).to_vec()),
        proof_hash: B64(vec![1; 32]),
    };
    let st = statement::sign(
        &rogue,
        KeyRef::CoreStatement,
        "live-check",
        c.clock.now(),
        &facts,
    )
    .unwrap();
    let r = a
        .anon::<_, Value>(
            "POST",
            "/v1/post-tokens",
            &json!({ "statement": st, "signed_body": B64(body.clone()), "kid": kid }),
        )
        .await;
    assert_eq!(err_code(r), "not_vouched");
    // a genuine statement, with other blinded values swapped in
    let st = core_statement(&c, "live-check", &facts);
    let other = serde_json::to_vec(
        &json!({ "action": "post-tokens", "blinded": [B64(vec![2; 256]), B64(vec![3; 256])] }),
    )
    .unwrap();
    let r = a
        .anon::<_, Value>(
            "POST",
            "/v1/post-tokens",
            &json!({ "statement": st, "signed_body": B64(other), "kid": kid }),
        )
        .await;
    assert_eq!(err_code(r), "not_vouched");
    // stamps aren't built: a typed refusal, never a panic
    assert_eq!(
        err_code(a.anon::<_, Value>("POST", "/v1/stamps", &json!({})).await),
        "not_implemented"
    );
    c.stop().await.unwrap();
}

/* ------------------------------- sessions ------------------------------- */

#[tokio::test]
async fn front_cannot_invent_a_session() {
    let (c, alice) = setup().await;
    let mut a = App::new(&c).unwrap();
    a.register(&alice).await.unwrap();
    let mut f = App::new(&c).unwrap();
    f.token = Some(vec![0; 32]);
    assert_eq!(
        err_code(f.core::<_, Value>("GET", "/v1/me", &json!({})).await),
        "session_expired"
    );
    f.token = None;
    assert_eq!(
        err_code(f.core::<_, Value>("POST", "/v1/sync", &json!({})).await),
        "no_session"
    );
    // a challenge for alice answered by a device key front made: refused, and alice is unaffected
    let impostor = alice.sibling().unwrap();
    let ch: Value = f
        .core(
            "POST",
            "/v1/auth/challenge",
            &json!({ "account": alice.account_id(), "device": impostor.device_id() }),
        )
        .await
        .unwrap();
    let l = impostor
        .login(
            &f.th,
            &B64::decode(ch["challenge"].as_str().unwrap()).unwrap(),
            0,
        )
        .unwrap();
    assert_eq!(
        err_code(f.core::<_, Value>("POST", "/v1/auth/login", &l).await),
        "bad_proof"
    );
    let me: Value = a.core("GET", "/v1/me", &json!({})).await.unwrap();
    assert_eq!(me["devices"].as_array().unwrap().len(), 1);
    c.stop().await.unwrap();
}
