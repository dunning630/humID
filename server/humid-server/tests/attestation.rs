//! Phone attestation end to end, over HTP/2 (crates/humid-attest, core/attest.rs).
//!
//! The simulated phones attest under the testkit's **test root**, which only a development
//! core trusts; `the_test_root_is_refused_by_a_production_core` proves production can't.

mod common;

use std::sync::Arc;

use common::*;
use humid_server::policy::{IosAttestation, KeyStorage, Policy};
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::testkit::{Phone, PhoneAttest};
use humid_server::wire::B64;
use serde_json::{Value, json};

/// Attestation required, the test team's App ID allowed, Google's list required.
fn attested(p: &mut Policy) {
    p.device_policy.attestation_required = true;
    p.device_policy.android.signing_cert_sha256 = vec![hex::encode(humid_attest::testkit::SIGNER)];
    p.device_policy.ios = IosAttestation {
        team_id: humid_attest::testkit::TEAM_ID.into(),
        app_ids: vec![humid_attest::testkit::APP_ID.into()],
        environment: humid_attest::Environment::Production,
        min_os_major: 26,
    };
}

const EMPTY_LIST: &str = r#"{"entries":{}}"#;

async fn cluster(tweak: impl FnOnce(&mut Policy)) -> Cluster {
    let c = Cluster::start(|p| {
        attested(p);
        tweak(p);
    })
    .await
    .unwrap();
    c.status_list(EMPTY_LIST).await.unwrap();
    c
}

fn android(c: &Cluster) -> Phone {
    Phone::new()
        .unwrap()
        .with_attest(PhoneAttest::android(&c.pki))
}

fn iphone(c: &Cluster) -> Phone {
    Phone::new()
        .unwrap()
        .with_attest(PhoneAttest::apple(&c.pki))
}

async fn proven(c: &Cluster, phone: &Phone) -> String {
    let conn = c.core_db().conn().await.unwrap();
    conn.query_one(
        "SELECT proven FROM devices WHERE id = $1",
        &[&phone.device_id().as_bytes()],
    )
    .await
    .unwrap()
    .get(0)
}

async fn register_code(c: &Cluster, phone: &Phone) -> String {
    let mut app = App::new(c).await.unwrap();
    match app.register(phone).await {
        Ok(()) => "ok".into(),
        Err(e) => e.code_str().to_string(),
    }
}

#[tokio::test]
async fn registration_needs_a_genuine_attested_phone() {
    let c = cluster(|_| {}).await;
    // Android 17 StrongBox and iOS 26: in
    let a = android(&c);
    assert_eq!(register_code(&c, &a).await, "ok");
    assert_eq!(proven(&c, &a).await, "android-strongbox");
    let i = iphone(&c);
    assert_eq!(register_code(&c, &i).await, "ok");
    assert_eq!(proven(&c, &i).await, "apple-app-attest");
    // no attestation: out
    assert_eq!(
        register_code(&c, &Phone::new().unwrap()).await,
        "attestation_required"
    );
    // a TEE phone is fine here (key_storage = tee_allowed) ...
    let tee = Phone::new().unwrap().with_attest(PhoneAttest::android_with(
        &c.pki,
        humid_attest::testkit::KeyDesc::tee(&[]),
    ));
    assert_eq!(register_code(&c, &tee).await, "ok");
    assert_eq!(proven(&c, &tee).await, "android-tee");
    // ... a PIN-unlockable key, an unlocked bootloader, Android 16, an Xcode build are not
    for (kd, code) in [
        (
            humid_attest::testkit::KeyDesc {
                user_auth_type: Some(3),
                ..humid_attest::testkit::KeyDesc::strongbox(&[])
            },
            "pin_allowed",
        ),
        (
            humid_attest::testkit::KeyDesc {
                device_locked: false,
                ..humid_attest::testkit::KeyDesc::strongbox(&[])
            },
            "unlocked_device",
        ),
        (
            humid_attest::testkit::KeyDesc {
                os_version: Some(160_000),
                ..humid_attest::testkit::KeyDesc::strongbox(&[])
            },
            "old_android",
        ),
    ] {
        let p = Phone::new()
            .unwrap()
            .with_attest(PhoneAttest::android_with(&c.pki, kd));
        assert_eq!(register_code(&c, &p).await, code);
    }
    let xcode = Phone::new().unwrap().with_attest(PhoneAttest::apple_with(
        &c.pki,
        humid_attest::Environment::Development,
    ));
    assert_eq!(register_code(&c, &xcode).await, "wrong_environment");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn strongbox_required_refuses_a_tee_downgrade() {
    let c = cluster(|p| p.device_policy.android.key_storage = KeyStorage::Strongbox).await;
    let tee = Phone::new().unwrap().with_attest(PhoneAttest::android_with(
        &c.pki,
        humid_attest::testkit::KeyDesc::tee(&[]),
    ));
    assert_eq!(register_code(&c, &tee).await, "not_strongbox");
    assert_eq!(register_code(&c, &android(&c)).await, "ok");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn an_attestation_is_bound_to_its_session_and_its_device_key() {
    let c = cluster(|_| {}).await;
    let a = android(&c);
    let mut app = App::new(&c).await.unwrap();
    // an enrolment made in another HTP session, its attestation carried into this one
    let other = App::new(&c).await.unwrap();
    let mut en = a.enrolment(&app.th).unwrap();
    en.attestation = a.enrolment(&other.th).unwrap().attestation;
    let body = json!({
        "account_vk": B64(a.account.public().to_bytes()),
        "kem_pk": B64(a.account_kem.public().to_bytes()),
        "pop": a.register_pop(&app.th).unwrap(),
        "enrolment": en,
    });
    assert_eq!(
        err_code(
            app.core::<_, Value>("POST", "/v1/auth/register", &body)
                .await
        ),
        "wrong_challenge"
    );
    // another device's attestation (its chip vouched for its own device key and live key)
    let b = android(&c);
    let mut en = a.enrolment(&app.th).unwrap();
    en.attestation = b.enrolment(&app.th).unwrap().attestation;
    let body = json!({
        "account_vk": B64(a.account.public().to_bytes()),
        "kem_pk": B64(a.account_kem.public().to_bytes()),
        "pop": a.register_pop(&app.th).unwrap(),
        "enrolment": en,
    });
    let code = err_code(
        app.core::<_, Value>("POST", "/v1/auth/register", &body)
            .await,
    );
    assert!(
        ["wrong_challenge", "wrong_key"].contains(&code.as_str()),
        "{code}"
    );
    // the genuine one
    app.register(&a).await.unwrap();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn a_joining_device_is_checked_against_the_join_requests_key() {
    let c = cluster(|_| {}).await;
    let phone = android(&c);
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();

    // the tablet asks to join with its own device key; the phone approves that request
    let tablet = phone
        .sibling()
        .unwrap()
        .with_attest(PhoneAttest::apple(&c.pki));
    let mut new = App::new(&c).await.unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let (jr, start) = join(&tablet, &phone.account_id(), &once);
    let l: Value = new.core("POST", "/v1/links", &start).await.unwrap();
    let code = l["code"].as_str().unwrap().to_string();
    let path = format!("/v1/links/{code}/approve");
    let signed = app
        .sign(&phone, "POST", &path, &approval(&jr, vec![1u8; 2000]))
        .unwrap();
    let _: Value = app
        .core("POST", &path, &json!({ "signed": signed }))
        .await
        .unwrap();

    // an attacker's phone with a genuine attestation of its own, presenting the tablet's
    // certificate: the chip vouched for another device key, so it's refused
    let thief = phone
        .sibling()
        .unwrap()
        .with_attest(PhoneAttest::apple(&c.pki));
    let mut en = tablet.enrolment(&new.th).unwrap();
    en.attestation = thief.enrolment(&new.th).unwrap().attestation;
    let r = new
        .core::<_, Value>(
            "POST",
            "/v1/devices",
            &json!({ "enrolment": en, "evidence": { "via": "link", "code": code } }),
        )
        .await;
    assert_eq!(err_code(r), "wrong_challenge");
    // an unattested enrolment for the approved key
    let mut en = tablet.enrolment(&new.th).unwrap();
    en.attestation = humid_server::proofs::Attestation::None;
    let r = new
        .core::<_, Value>(
            "POST",
            "/v1/devices",
            &json!({ "enrolment": en, "evidence": { "via": "link", "code": code } }),
        )
        .await;
    assert_eq!(err_code(r), "attestation_required");
    // the approved request's own device, attested for its own key: in (the link wasn't spent
    // by the refusals)
    let enrol = json!({ "enrolment": tablet.enrolment(&new.th).unwrap(), "evidence": { "via": "link", "code": code } });
    let d: Value = new.core("POST", "/v1/devices", &enrol).await.unwrap();
    assert_eq!(d["via"], "link");
    assert_eq!(proven(&c, &tablet).await, "apple-app-attest");
    new.login(&tablet, 0).await.unwrap();
    let e = entries(&app).await;
    let added = e
        .iter()
        .rev()
        .find(|x| x["type"] == "device.added")
        .unwrap();
    assert_eq!(added["detail"]["proven"], "apple-app-attest");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn every_iphone_check_carries_an_assertion_whose_counter_counts_up() {
    let c = cluster(|_| {}).await;
    let i = iphone(&c);
    let mut app = App::new(&c).await.unwrap();
    app.register(&i).await.unwrap(); // the sign-in used counter 1

    // a step-up with the next counter: fine
    let body = json!({ "action": "post-tokens", "blinded": [B64(vec![2; 256])] });
    let s = app.sign(&i, "POST", "/v1/live/attest", &body).unwrap();
    let _: Value = app
        .core("POST", "/v1/live/attest", &json!({ "signed": s }))
        .await
        .unwrap();

    // without its assertion: refused
    let mut s = app.sign(&i, "POST", "/v1/live/attest", &body).unwrap();
    s.proof.app_attest = None;
    assert_eq!(
        err_code(
            app.core::<_, Value>("POST", "/v1/live/attest", &json!({ "signed": s }))
                .await
        ),
        "app_attest_required"
    );
    // a counter rolled back (a cloned key replaying older counters): refused
    app.refill().await.unwrap();
    i.attest.as_ref().unwrap().set_counter(2);
    let s = app.sign(&i, "POST", "/v1/live/attest", &body).unwrap();
    assert_eq!(
        err_code(
            app.core::<_, Value>("POST", "/v1/live/attest", &json!({ "signed": s }))
                .await
        ),
        "assertion_replayed"
    );
    // an assertion made for another check: refused
    i.attest.as_ref().unwrap().set_counter(50);
    let mut s = app.sign(&i, "POST", "/v1/live/attest", &body).unwrap();
    let other = app
        .sign(
            &i,
            "POST",
            "/v1/live/attest",
            &json!({ "action": "post-tokens", "blinded": [B64(vec![3; 256])] }),
        )
        .unwrap();
    s.proof.app_attest = other.proof.app_attest;
    let code = err_code(
        app.core::<_, Value>("POST", "/v1/live/attest", &json!({ "signed": s }))
            .await,
    );
    assert_eq!(code, "bad_assertion");
    // sign-ins too: a fresh one works, one whose assertion is missing doesn't
    let mut again = App::new(&c).await.unwrap();
    again.login(&i, 0).await.unwrap();
    i.attest.as_ref().unwrap().set_counter(10);
    let mut bad = App::new(&c).await.unwrap();
    assert_eq!(
        bad.login(&i, 0).await.unwrap_err().code_str(),
        "assertion_replayed",
        "a sign-in's counter must count up too"
    );
    // an Android phone sends no assertion, and may not invent one
    let a = android(&c);
    let mut aa = App::new(&c).await.unwrap();
    aa.register(&a).await.unwrap();
    let mut s = aa.sign(&a, "POST", "/v1/live/attest", &body).unwrap();
    s.proof.app_attest = Some(B64(vec![0xa0]));
    assert_eq!(
        err_code(
            aa.core::<_, Value>("POST", "/v1/live/attest", &json!({ "signed": s }))
                .await
        ),
        "bad_assertion"
    );
    c.stop().await.unwrap();
}

#[tokio::test]
async fn a_revoked_android_chain_is_caught_at_sign_in_and_on_the_schedule() {
    let c = cluster(|p| p.device_policy.android.reverify_hours = 24).await;
    let a = android(&c);
    let b = android(&c);
    let mut app = App::new(&c).await.unwrap();
    app.register(&a).await.unwrap();
    let mut bpp = App::new(&c).await.unwrap();
    bpp.register(&b).await.unwrap();

    // Google revokes the intermediate in a's chain
    let serial = {
        let conn = c.core_db().conn().await.unwrap();
        let r = conn
            .query_one(
                "SELECT chain FROM device_attestations WHERE device = $1",
                &[&a.device_id().as_bytes()],
            )
            .await
            .unwrap();
        let chain: Vec<B64> = serde_json::from_value(r.get(0)).unwrap();
        humid_attest::x509::Cert::parse(&chain[1])
            .unwrap()
            .serial_key()
    };
    c.clock.advance(3_600_000);
    let listed =
        format!(r#"{{"entries":{{"{serial}":{{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}}}}"#);
    c.status_list(&listed).await.unwrap();

    // at a's next sign-in: refused, and the device is gone (its sessions too)
    let mut again = App::new(&c).await.unwrap();
    assert_eq!(
        again.login(&a, 0).await.unwrap_err().code_str(),
        "attestation_revoked"
    );
    assert_eq!(
        err_code(app.core::<_, Value>("GET", "/v1/me", &json!({})).await),
        "session_expired"
    );
    let mut third = App::new(&c).await.unwrap();
    assert_eq!(
        third.login(&a, 0).await.unwrap_err().code_str(),
        "bad_proof"
    );
    // b is unaffected
    let mut b2 = App::new(&c).await.unwrap();
    b2.login(&b, 0).await.unwrap();

    // the schedule: b's chain shares no certificate with a's, so it survives the round …
    c.clock.advance(25 * 3_600_000);
    c.status_list(&listed).await.unwrap();
    let (checked, removed) = humid_server::core::attest::reverify_due(&c.core)
        .await
        .unwrap();
    assert_eq!((checked, removed), (1, 0), "only b is due and active");
    // … until its own intermediate is listed
    let serial_b = {
        let conn = c.core_db().conn().await.unwrap();
        let r = conn
            .query_one(
                "SELECT chain FROM device_attestations WHERE device = $1",
                &[&b.device_id().as_bytes()],
            )
            .await
            .unwrap();
        let chain: Vec<B64> = serde_json::from_value(r.get(0)).unwrap();
        humid_attest::x509::Cert::parse(&chain[1])
            .unwrap()
            .serial_key()
    };
    c.clock.advance(25 * 3_600_000);
    c.status_list(&format!(
        r#"{{"entries":{{"{serial_b}":{{"status":"SUSPENDED"}}}}}}"#
    ))
    .await
    .unwrap();
    let (checked, removed) = humid_server::core::attest::reverify_due(&c.core)
        .await
        .unwrap();
    assert_eq!((checked, removed), (1, 1));
    assert_eq!(
        err_code(b2.core::<_, Value>("GET", "/v1/me", &json!({})).await),
        "session_expired",
        "a device removed on the schedule loses its sessions"
    );
    // the server asserted the removal in b's ledger (no holder proof: Google's list is why)
    let conn = c.core_db().conn().await.unwrap();
    let body: Vec<u8> = conn
        .query_one(
            "SELECT body FROM ledger_entries WHERE account = $1 ORDER BY seq DESC LIMIT 1",
            &[&b.account_id().as_bytes()],
        )
        .await
        .unwrap()
        .get(0);
    let last: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(last["type"], "device.removed");
    assert_eq!(last["detail"]["reason"], "attestation_revoked");
    assert_eq!(last["asserted"], "server");
    drop(bpp);
    c.stop().await.unwrap();
}

#[tokio::test]
async fn googles_list_fails_closed_when_missing_or_stale() {
    // no copy at all: an Android enrolment waits (503), it isn't let through
    let c = Cluster::start(attested).await.unwrap();
    assert_eq!(register_code(&c, &android(&c)).await, "status_unavailable");
    // iPhones don't depend on Google's list
    assert_eq!(register_code(&c, &iphone(&c)).await, "ok");
    c.status_list(EMPTY_LIST).await.unwrap();
    let a = android(&c);
    assert_eq!(register_code(&c, &a).await, "ok");
    // older than status_max_age_hours (48): sign-ins of Android phones wait too
    c.clock.advance(49 * 3_600_000);
    let mut app = App::new(&c).await.unwrap();
    assert_eq!(
        app.login(&a, 0).await.unwrap_err().code_str(),
        "status_stale"
    );
    // and a list can't be rolled back to an older copy
    let older = c.clock.now() - 60 * 3_600_000;
    assert_eq!(
        humid_server::core::attest::store_status(&c.core, EMPTY_LIST.as_bytes(), older)
            .await
            .unwrap_err()
            .code(),
        "status_rollback"
    );
    // nor replaced by something that isn't a status list
    assert_eq!(
        humid_server::core::attest::store_status(&c.core, b"{}", c.clock.now())
            .await
            .unwrap_err()
            .code(),
        "bad_status_list"
    );
    c.status_list(EMPTY_LIST).await.unwrap();
    app.login(&a, 0).await.unwrap();
    c.stop().await.unwrap();
}

#[tokio::test]
async fn a_tampered_stored_list_is_ignored() {
    let c = cluster(|_| {}).await;
    // someone with the database (not core's HSM) drops an entry and freshens the date
    let conn = c.core_db().conn().await.unwrap();
    conn.execute(
        "UPDATE attest_status SET fetched_at = fetched_at + 1, list = $1",
        &[&br#"{"entries":{"01":{"status":"REVOKED"}}}"#.as_slice()],
    )
    .await
    .unwrap();
    // a core that loads it (a restart, another instance) finds the signature broken
    let fresh = humid_server::core::Core::with_trust(
        c.core.db.clone(),
        c.core.hsm.clone(),
        c.core.policy.clone(),
        c.clock.clone(),
        c.core.keys.clone(),
        c.pki.trust(),
    )
    .unwrap();
    assert!(
        !humid_server::core::attest::load_status(&fresh)
            .await
            .unwrap()
    );
    assert_eq!(fresh.attest.status_fetched_at().unwrap(), None);
    c.stop().await.unwrap();
}

#[tokio::test]
async fn development_without_attestation_still_runs_unattested_phones() {
    // the development default: attestation not required (no list needed, nothing stored)
    let c = Cluster::start(|_| {}).await.unwrap();
    let p = Phone::new().unwrap();
    assert_eq!(register_code(&c, &p).await, "ok");
    assert_eq!(proven(&c, &p).await, "unattested");
    // an attested phone is still checked (and an iPhone without a configured team is refused)
    assert_eq!(register_code(&c, &iphone(&c)).await, "not_configured");
    c.stop().await.unwrap();
}

#[tokio::test]
async fn the_test_root_is_refused_by_a_production_core() {
    let c = cluster(|_| {}).await;
    // the same policy, in production mode (signed for this test only)
    let mut p = c.policy.policy.clone();
    p.mode = humid_server::unit::Mode::Production;
    p.registration = humid_server::policy::Registration::Pass;
    p.cosigners = vec![humid_server::policy::Cosigner {
        name: "witness.example".into(),
        key: p.unit_keys.core.clone(),
    }];
    p.validate().unwrap();
    let signed = Arc::new(humid_server::policy::SignedPolicy {
        bytes: serde_json::to_vec(&p).unwrap(),
        sig: vec![],
        policy: p,
    });
    // handed the testkit's root: it won't start
    let e = humid_server::core::Core::with_trust(
        c.core.db.clone(),
        c.core.hsm.clone(),
        signed.clone(),
        c.clock.clone(),
        c.core.keys.clone(),
        c.pki.trust(),
    )
    .err()
    .unwrap();
    assert_eq!(e.code(), "test_root_in_production");
    // with the vendors' roots it starts, and refuses what the test PKI made
    let prod = humid_server::core::Core::new(
        c.core.db.clone(),
        c.core.hsm.clone(),
        signed,
        c.clock.clone(),
        c.core.keys.clone(),
    )
    .unwrap();
    assert!(prod.attest.production());
    humid_server::core::attest::load_status(&prod)
        .await
        .unwrap();
    let th = [9u8; 64];
    for phone in [android(&c), iphone(&c)] {
        let en = phone.enrolment(&th).unwrap();
        let d = humid_server::proofs::check_enrolment(&en, None, &th).unwrap();
        assert_eq!(
            prod.attest
                .enrolment(&en, &d, &th, c.clock.now())
                .unwrap_err()
                .code(),
            "untrusted_root"
        );
    }
    c.stop().await.unwrap();
}
