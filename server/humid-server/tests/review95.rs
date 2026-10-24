//! Regressions for the PR #95 review: each was a reviewer probe that passed on the flawed
//! code (asserting the flaw). These assert the fixed behaviour.

mod common;

use common::*;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::wire::B64;
use serde_json::{Value, json};

/// F1 (H-3): junk sign-ins naming alice's account, from many networks, don't stop her
/// genuine sign-in: failures are counted only once a proof could be checked, and a valid
/// proof is never refused.
#[tokio::test]
async fn f1_junk_signins_never_lock_the_holder_out() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    for i in 0..30 {
        let mut m = App::new(&c).await.unwrap();
        // ten other networks, then alice's own network (a shared Wi-Fi or CGNAT address)
        m.net = if i < 10 {
            format!("v4:198.51.100.{i}")
        } else {
            a.net.clone()
        };
        let junk = json!({
            "th": B64(vec![1u8; 64]), "account": alice.account_id(), "device": alice.device_id(),
            "challenge": B64(vec![0u8; 32]), "duress": 0,
            "login_sig": B64(vec![0u8; 8]), "live_login": B64(vec![0u8; 8])
        });
        let _ = m.core::<_, Value>("POST", "/v1/auth/login", &junk).await;
    }
    a.login(&alice, 0)
        .await
        .expect("a valid sign-in always works");
    c.stop().await.unwrap();
}

/// F2 (H-3): anyone can ask for challenges for alice's device; it never stops her getting one.
#[tokio::test]
async fn f2_challenges_taken_by_others_never_block_the_holder() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let m = App::new(&c).await.unwrap();
    for _ in 0..12 {
        let _ = m
            .core::<_, Value>(
                "POST",
                "/v1/auth/challenge",
                &json!({ "account": alice.account_id(), "device": alice.device_id() }),
            )
            .await;
    }
    a.login(&alice, 0)
        .await
        .expect("a valid sign-in always works");
    c.stop().await.unwrap();
}

/// F3 (H-2): a duress session's Check-in "arm" is simulated: keys is never armed, nothing is
/// erased later, and the duress session still sees it as armed.
#[tokio::test]
async fn f3_a_duress_session_cannot_arm_checkin_for_real() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 64).await.unwrap();

    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap(); // duress gesture, Check-in off
    let s = forced
        .sign(
            &alice,
            "POST",
            "/v1/checkin/arm",
            &json!({ "window_h": 1, "max_window_h": 1, "grace_min": 0 }),
        )
        .unwrap();
    let st: Value = forced
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    assert_eq!(st["state"], "armed", "it looks armed to the duress session");
    let st: Value = forced.core("GET", "/v1/checkin", &json!({})).await.unwrap();
    assert_eq!(st["state"], "armed");
    assert_eq!(
        c.keys.status(&alice.account_id()).await.unwrap().state,
        "off",
        "but keys was never armed"
    );
    c.clock.advance(60 * 60_000 + 1);
    c.keys.tick().await.unwrap();
    a.login(&alice, 0).await.unwrap();
    open(&mut a, &alice, &doc.id)
        .await
        .expect("nothing was erased");
    c.stop().await.unwrap();
}

/// F4 (H-1): after a duress unlock of an armed vault, the duress session is shown Check-in
/// as it was (armed), though the vault really is erased.
#[tokio::test]
async fn f4_a_duress_session_sees_checkin_as_it_was() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let _ = upload(&mut a, &alice, 64).await.unwrap();
    let s = a
        .sign(
            &alice,
            "POST",
            "/v1/checkin/arm",
            &json!({ "window_h": 8, "max_window_h": 8, "grace_min": 60 }),
        )
        .unwrap();
    let armed: Value = a
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    humid_server::core::auth::deliver_duress(&c.core)
        .await
        .unwrap();
    assert_eq!(
        c.keys.status(&alice.account_id()).await.unwrap().state,
        "erased",
        "the erase is real"
    );
    let st: Value = forced.core("GET", "/v1/checkin", &json!({})).await.unwrap();
    assert_eq!(st["state"], "armed", "but the duress session can't tell");
    assert_eq!(st["deadline"], armed["deadline"]);
    // its own check-ins move the timer, as they would
    c.clock.advance(60_000);
    let s = forced
        .sign(&alice, "POST", "/v1/checkin/check", &json!({}))
        .unwrap();
    let st: Value = forced
        .core("POST", "/v1/checkin/check", &json!({ "signed": s }))
        .await
        .unwrap();
    assert_eq!(st["state"], "armed");
    assert_eq!(
        st["deadline"].as_i64().unwrap(),
        armed["deadline"].as_i64().unwrap() + 60_000
    );
    c.stop().await.unwrap();
}

/// F5 (H-2): a duress session can't replace an index entry.
#[tokio::test]
async fn f5_a_duress_session_cannot_patch_the_index() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 64).await.unwrap();
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    let path = format!("/v1/objects/{}", doc.id);
    let s = forced
        .sign(
            &alice,
            "PATCH",
            &path,
            &json!({ "object": doc.id, "index": B64(vec![0u8; 64]) }),
        )
        .unwrap();
    assert_eq!(
        err_code(
            forced
                .core::<_, Value>("PATCH", &path, &json!({ "signed": s }))
                .await
        ),
        "busy"
    );
    let r: Value = a.core("POST", "/v1/sync", &json!({})).await.unwrap();
    assert_eq!(
        r["changed"][0]["index"],
        json!(B64(vec![7u8; 64])),
        "the index entry is the holder's"
    );
    c.stop().await.unwrap();
}

/// F8 (H-1): nothing a duress session can read names duress.
#[tokio::test]
async fn f8_a_duress_session_reads_nothing_that_names_duress() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    humid_server::core::auth::deliver_duress(&c.core)
        .await
        .unwrap();
    let ev = events(&forced).await;
    assert!(
        !ev.iter().any(|e| e.contains("duress")),
        "ledger events: {ev:?}"
    );
    let r: Value = forced.core("POST", "/v1/sync", &json!({})).await.unwrap();
    assert!(!r.to_string().contains("duress"), "sync: {r}");
    c.stop().await.unwrap();
}
