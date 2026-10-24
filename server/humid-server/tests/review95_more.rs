//! More regressions for the PR #95 review: the every-route duress test (H-2), the duress queue
//! (M-3), deferred entries (H-1), sign-in limits (H-3), link and recovery caps (F6, M-5), the
//! relay (F7, M-6), network headers and call limits (M-4), and the policy high-water mark (M-7).

mod common;

use std::sync::atomic::Ordering;

use common::*;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::wire::B64;
use serde_json::{Value, json};

/// A digest of every row of every table of a unit's database (what "nothing changed" means).
async fn snapshot(db: &humid_server::db::Db, skip: &[&str]) -> Vec<(String, String)> {
    let mut out = vec![];
    for t in db.tables().await.unwrap() {
        if skip.contains(&t.as_str()) {
            continue;
        }
        let c = db.conn().await.unwrap();
        let q = format!(
            "SELECT md5(COALESCE(string_agg(md5(x::text), ',' ORDER BY md5(x::text)), '')) FROM {t} x"
        );
        let h: String = c.query_one(q.as_str(), &[]).await.unwrap().get(0);
        out.push((t, h));
    }
    out
}

/// The keys unit's key material: every share's object, account, wrapping and fuse state.
async fn material(c: &Cluster) -> String {
    c.keys
        .db()
        .conn()
        .await
        .unwrap()
        .query_one(
            "SELECT md5(COALESCE(string_agg(md5(object::text || account::text || wrapped::text || fused::text), ',' ORDER BY object), '')) FROM shares",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// What a duress session may change in core: its own session row (last use, its Check-in
/// copy), the step-up nonces it spends, and its day's live-check count.
const SESSION_TABLES: &[&str] = &["sessions", "nonces", "live_check_days"];

/// H-2: every step-up route in the allow-list, tried from a duress session with a valid proof,
/// changes nothing real in either database. (An open writes what an ordinary open writes: its
/// ledger entry and download ticket; what keys does with a duress open is the owner's call.)
#[tokio::test]
async fn every_step_up_route_from_a_duress_session_changes_nothing_real() {
    use humid_server::front::routes::{Auth, ROUTES};
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 64).await.unwrap();
    // hardened recovery with a request bound to alice, so cancel has something real to veto
    let body: Value =
        serde_json::from_slice(&alice.mode_body("hardened", 1, &[0u8; 64]).unwrap()).unwrap();
    let s = a.sign(&alice, "PUT", "/v1/recovery/mode", &body).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/mode", &json!({ "signed": s }))
        .await
        .unwrap();
    let card = json!({ "lookup": B64(vec![9u8; 32]), "blob": B64(vec![1u8; 100]) });
    let s = a.sign(&alice, "PUT", "/v1/recovery/card", &card).unwrap();
    let _: Value = a
        .core("PUT", "/v1/recovery/card", &json!({ "signed": s }))
        .await
        .unwrap();
    let n = App::new(&c).await.unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let thief = alice.sibling().unwrap();
    let r: Value = n
        .core("POST", "/v1/recovery/requests", &json!({ "device_vk": B64(thief.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) }))
        .await
        .unwrap();
    let rc = r["code"].as_str().unwrap().to_string();
    let _: Value = n
        .core(
            "POST",
            &format!(
                "/v1/recovery/requests/{}/card",
                r["request"].as_str().unwrap()
            ),
            &json!({ "lookup": B64(vec![9u8; 32]) }),
        )
        .await
        .unwrap();
    let alerts: Value = a
        .core("GET", "/v1/recovery/alerts", &json!({}))
        .await
        .unwrap();
    let reference = alerts["alerts"][0]["ref"].as_str().unwrap().to_string();
    // a device waiting to join alice
    let tablet = alice.sibling().unwrap();
    let (jr, start) = join(&tablet, &alice.account_id(), &once);
    let _: Value = n.core("POST", "/v1/links", &start).await.unwrap();

    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    humid_server::core::auth::deliver_duress(&c.core)
        .await
        .unwrap();
    let core_before = snapshot(c.core_db(), SESSION_TABLES).await;
    let keys_before = snapshot(c.keys.db(), &["used_proofs", "releases"]).await;
    let shares_before = humid_server::testkit::cluster::keys_count(&c, "shares").await;
    let material_before = material(&c).await;

    let id = doc.id.to_string();
    let k1 = humid_server::crypto::KemSecret::generate().unwrap();
    let mut tried = vec![];
    for r in ROUTES.iter().filter(|r| r.auth == Auth::Session) {
        let (path, body) = match (r.method, r.path) {
            ("DELETE", "/v1/me") | ("POST", "/v1/duress/clear") => (r.path.to_string(), json!({})),
            ("POST", "/v1/links/{code}/approve") => (
                format!("/v1/links/{}/approve", jr.code),
                approval(&jr, vec![1; 100]),
            ),
            ("DELETE", "/v1/devices/{id}") => (
                format!("/v1/devices/{}", Phone::new().unwrap().device_id()),
                json!({}),
            ),
            ("POST", "/v1/objects") => {
                // a whole upload: it signs its own body
                assert_eq!(err_code(upload(&mut forced, &alice, 64).await), "busy");
                tried.push(r.path);
                continue;
            }
            ("PATCH", "/v1/objects/{id}") => (
                format!("/v1/objects/{id}"),
                json!({ "object": doc.id, "index": B64(vec![0u8; 64]) }),
            ),
            ("DELETE", "/v1/objects/{id}") => {
                (format!("/v1/objects/{id}"), json!({ "object": doc.id }))
            }
            ("POST", "/v1/objects/{id}/open") => (
                format!("/v1/objects/{id}/open"),
                open_body(&alice, &doc.id, &k1),
            ),
            ("PUT", "/v1/recovery/mode") => (
                r.path.to_string(),
                serde_json::from_slice(&alice.mode_body("holder-only", 2, &[0u8; 64]).unwrap())
                    .unwrap(),
            ),
            ("PUT", "/v1/recovery/card") => (
                r.path.to_string(),
                json!({ "lookup": B64(vec![8u8; 32]), "blob": B64(vec![2u8; 100]) }),
            ),
            ("DELETE", "/v1/recovery/card") | ("DELETE", "/v1/recovery/witnesses") => {
                (r.path.to_string(), json!({}))
            }
            ("PUT", "/v1/recovery/witnesses") => (
                r.path.to_string(),
                json!({ "threshold": 2, "witnesses": [
                    { "account": Phone::new().unwrap().account_id(), "envelope": B64(vec![2u8; 100]) },
                    { "account": Phone::new().unwrap().account_id(), "envelope": B64(vec![3u8; 100]) }] }),
            ),
            ("POST", "/v1/recovery/help/{code}") => (
                format!("/v1/recovery/help/{rc}"),
                json!({ "account": alice.account_id(), "envelope": B64(vec![4u8; 100]) }),
            ),
            ("POST", "/v1/recovery/alerts/{ref}/cancel") => {
                (format!("/v1/recovery/alerts/{reference}/cancel"), json!({}))
            }
            ("POST", "/v1/checkin/arm") => (
                r.path.to_string(),
                json!({ "window_h": 1, "max_window_h": 1, "grace_min": 0 }),
            ),
            ("POST", "/v1/checkin/check") | ("POST", "/v1/checkin/disarm") => {
                (r.path.to_string(), json!({}))
            }
            ("POST", "/v1/live/attest") => (
                r.path.to_string(),
                json!({ "action": "post-tokens", "blinded": [B64(vec![1; 256])] }),
            ),
            // no step-up: reads, sign-out, the nonce pool
            _ => continue,
        };
        forced.refill().await.unwrap();
        let s = forced.sign(&alice, r.method, &path, &body).unwrap();
        let res = forced
            .core::<_, Value>(r.method, &path, &json!({ "signed": s }))
            .await;
        // Check-in "works" in a duress session (simulated on its own copy); the open is the
        // owner's decision; everything else is refused
        if !r.path.starts_with("/v1/checkin/") && r.path != "/v1/objects/{id}/open" {
            assert!(
                res.is_err(),
                "{} {} answered a duress session",
                r.method,
                r.path
            );
        }
        tried.push(r.path);
    }
    // every route in core that calls step_up (grep `step_up(` in src/core): 19
    assert_eq!(tried.len(), 19, "every step-up route was tried: {tried:?}");
    let core_after = snapshot(c.core_db(), SESSION_TABLES).await;
    let changed: Vec<_> = core_before
        .iter()
        .zip(&core_after)
        .filter(|(b, a)| b != a)
        .map(|(b, _)| b.0.clone())
        .collect();
    assert!(
        changed.iter().all(|t| [
            "ledger_entries",
            "tlog_nodes",
            "tlog_state",
            "download_tickets"
        ]
        .contains(&t.as_str())),
        "core tables a duress session changed: {changed:?}"
    );
    // and the only new ledger entry is the open
    let ev = entries(&a).await;
    let last = ev.last().unwrap();
    assert_eq!(last["type"], "object.opened");
    assert_eq!(ev[ev.len() - 2]["type"], "recovery.evidence");
    // keys: only an open's release bookkeeping (counters) may move; the key material may not
    let keys_after = snapshot(c.keys.db(), &["used_proofs", "releases", "shares"]).await;
    let keys_before: Vec<_> = keys_before
        .into_iter()
        .filter(|(t, _)| t != "shares")
        .collect();
    assert_eq!(keys_after, keys_before, "keys changed for a duress session");
    assert_eq!(
        humid_server::testkit::cluster::keys_count(&c, "shares").await,
        shares_before
    );
    assert_eq!(material(&c).await, material_before);
    c.stop().await.unwrap();
}

/// H-2 (keys' side): even from core, keys refuses a write whose proof carries the duress mode.
#[tokio::test]
async fn keys_refuses_a_duress_mode_write_even_from_core() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (doc, _) = upload(&mut a, &alice, 64).await.unwrap();
    let path = format!("/v1/objects/{}", doc.id);
    let body = serde_json::to_vec(&json!({ "object": doc.id })).unwrap();
    let signed = alice
        .step_up_mode(
            "DELETE",
            &path,
            &[9u8; 64],
            1,
            &humid_server::crypto::random::<32>().unwrap(),
            c.clock.now(),
            &body,
            1,
        )
        .unwrap();
    let ph = humid_server::proofs::proof_hash(&signed.proof.device_sig).unwrap();
    let st = humid_server::statement::sign(
        c.core_hsm.as_ref(),
        humid_server::hsm::KeyRef::CoreStatement,
        "delete",
        c.clock.now(),
        &humid_server::api::keys::ActionFacts {
            account: alice.account_id(),
            object: Some(doc.id),
            proof_hash: B64(ph.to_vec()),
        },
    )
    .unwrap();
    let r = c
        .core_to_keys
        .post::<_, Value>(
            &format!("/v1/shares/{}/delete", doc.id),
            &[],
            &humid_server::api::keys::HolderAction {
                statement: st,
                cert: alice.cert(&[9u8; 64]),
                signed,
            },
        )
        .await;
    assert_eq!(err_code(r), "busy");
    assert_eq!(
        humid_server::testkit::cluster::keys_count(&c, "shares").await,
        1
    );
    c.stop().await.unwrap();
}

/// M-3: the duress erase reaches keys even when keys is down at the sign-in: it is queued in
/// the sign-in's own transaction and retried until keys acts on it.
#[tokio::test]
async fn a_duress_erase_survives_keys_being_down() {
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
    let _: Value = a
        .core("POST", "/v1/checkin/arm", &json!({ "signed": s }))
        .await
        .unwrap();
    c.keys.refuse_duress.store(true, Ordering::SeqCst);
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await; // the after-reply attempt
    assert_eq!(
        humid_server::core::auth::deliver_duress(&c.core)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        c.keys.status(&alice.account_id()).await.unwrap().state,
        "armed"
    );
    c.keys.refuse_duress.store(false, Ordering::SeqCst);
    c.clock.advance(120_000);
    assert_eq!(
        humid_server::core::auth::deliver_duress(&c.core)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        c.keys.status(&alice.account_id()).await.unwrap().state,
        "erased"
    );
    c.clock.advance(120_000);
    assert_eq!(
        humid_server::core::auth::deliver_duress(&c.core)
            .await
            .unwrap(),
        0,
        "acted on once"
    );
    c.stop().await.unwrap();
}

/// H-1: the duress sign-in's ledger entry isn't lost, only held back: once the duress session
/// has ended, the holder's own devices see it.
#[tokio::test]
async fn the_duress_entry_reaches_the_holder_once_the_duress_session_ends() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    assert_eq!(
        humid_server::core::ledger::flush_deferred(&c.core)
            .await
            .unwrap(),
        0
    );
    assert!(
        !events(&a).await.iter().any(|e| e == "session.duress"),
        "not while the duress session is live"
    );
    let _: Value = forced
        .core("POST", "/v1/auth/logout", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        humid_server::core::ledger::flush_deferred(&c.core)
            .await
            .unwrap(),
        1
    );
    assert!(events(&a).await.iter().any(|e| e == "session.duress"));
    c.stop().await.unwrap();
}

/// H-1: in a duress session, a refused open (an erased vault) says only "not available".
#[tokio::test]
async fn a_duress_session_never_learns_the_vault_was_erased() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
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
    let mut forced = App::new(&c).await.unwrap();
    forced.login(&alice, 1).await.unwrap();
    humid_server::core::auth::deliver_duress(&c.core)
        .await
        .unwrap();
    assert_eq!(
        err_code(open(&mut forced, &alice, &doc.id).await),
        "not_available"
    );
    let ev = events(&forced).await;
    assert!(!ev.iter().any(|e| e == "access.denied"), "{ev:?}");
    c.stop().await.unwrap();
}

/// H-3: failed signatures on valid challenges for a real device are still limited (guessing is
/// slowed), but even then the holder's valid sign-in works.
#[tokio::test]
async fn bad_signatures_are_limited_but_never_block_a_valid_sign_in() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let thief = Phone::new().unwrap(); // not alice's keys
    let mut last = String::new();
    for i in 0..12 {
        let mut m = App::new(&c).await.unwrap();
        m.net = format!("v4:203.0.113.{i}");
        let ch: Value = m
            .core(
                "POST",
                "/v1/auth/challenge",
                &json!({ "account": alice.account_id(), "device": alice.device_id() }),
            )
            .await
            .unwrap();
        let ch = B64::decode(ch["challenge"].as_str().unwrap()).unwrap();
        let mut l = thief.login(&m.th, &ch, 0).unwrap();
        l.account = alice.account_id();
        l.device = alice.device_id();
        last = err_code(m.core::<_, Value>("POST", "/v1/auth/login", &l).await);
    }
    assert_eq!(last, "rate_limited", "guessing is slowed");
    a.login(&alice, 0)
        .await
        .expect("a valid sign-in still works");
    c.stop().await.unwrap();
}

/// H-3: a challenge signs in once, and only the device it was made for.
#[tokio::test]
async fn a_challenge_signs_in_once() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let ch: Value = a
        .core(
            "POST",
            "/v1/auth/challenge",
            &json!({ "account": alice.account_id(), "device": alice.device_id() }),
        )
        .await
        .unwrap();
    let ch = B64::decode(ch["challenge"].as_str().unwrap()).unwrap();
    let l = alice.login(&a.th, &ch, 0).unwrap();
    let _: Value = a.core("POST", "/v1/auth/login", &l).await.unwrap();
    assert_eq!(
        err_code(a.core::<_, Value>("POST", "/v1/auth/login", &l).await),
        "challenge_used"
    );
    let ch: Value = a
        .core(
            "POST",
            "/v1/auth/challenge",
            &json!({ "account": alice.account_id(), "device": Phone::new().unwrap().device_id() }),
        )
        .await
        .unwrap();
    let ch = B64::decode(ch["challenge"].as_str().unwrap()).unwrap();
    let l = alice.login(&a.th, &ch, 0).unwrap();
    assert_eq!(
        err_code(a.core::<_, Value>("POST", "/v1/auth/login", &l).await),
        "bad_proof"
    );
    // and it expires
    let ch: Value = a
        .core(
            "POST",
            "/v1/auth/challenge",
            &json!({ "account": alice.account_id(), "device": alice.device_id() }),
        )
        .await
        .unwrap();
    let ch = B64::decode(ch["challenge"].as_str().unwrap()).unwrap();
    c.clock.advance(2 * 60_000 + 1);
    let l = alice.login(&a.th, &ch, 0).unwrap();
    assert_eq!(
        err_code(a.core::<_, Value>("POST", "/v1/auth/login", &l).await),
        "bad_proof"
    );
    c.stop().await.unwrap();
}

/// F6 (M-5): a few networks can't fill the link cap for everyone: each /24 (or /48) holds
/// only a few open links, and other networks still link.
#[tokio::test]
async fn f6_a_few_networks_cannot_stop_device_linking() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let k = humid_server::crypto::KemSecret::generate().unwrap();
    let mut made = 0i64;
    for net in 0..84 {
        let mut m = App::new(&c).await.unwrap();
        m.net = format!("v4:203.0.113.{net}"); // all in one /24
        let (_, start) = join(
            &alice.sibling().unwrap(),
            &Phone::new().unwrap().account_id(),
            &k,
        );
        if m.core::<_, Value>("POST", "/v1/links", &start)
            .await
            .is_ok()
        {
            made += 1;
        }
    }
    assert_eq!(made, humid_server::core::devices::MAX_OPEN_LINKS_PER_BUCKET);
    let mut other = App::new(&c).await.unwrap();
    other.net = "v4:198.51.100.7".into();
    let (_, start) = join(&alice.sibling().unwrap(), &alice.account_id(), &k);
    let _: Value = other
        .core("POST", "/v1/links", &start)
        .await
        .expect("another network still links");
    c.stop().await.unwrap();
}

/// M-5: an unbound recovery request goes after an hour.
#[tokio::test]
async fn unbound_recoveries_go_after_an_hour() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let n = App::new(&c).await.unwrap();
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let d = Phone::new().unwrap();
    let r: Value = n
        .core("POST", "/v1/recovery/requests", &json!({ "device_vk": B64(d.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) }))
        .await
        .unwrap();
    assert_eq!(r["expires_at"].as_i64().unwrap(), c.clock.now() + 3_600_000);
    c.stop().await.unwrap();
}

async fn post_tokens(c: &Cluster, app: &mut App<'_>, phone: &Phone, n: usize) -> Vec<Value> {
    let keys: Value = app
        .anon("GET", "/v1/post-tokens/keys", &json!({}))
        .await
        .unwrap();
    let kid = keys["keys"][0]["kid"].as_str().unwrap().to_string();
    let pk = humid_server::crypto::blind::PublicKey::from_spki(
        &B64::decode(keys["keys"][0]["spki"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let msgs: Vec<[u8; 32]> = (0..n)
        .map(|_| humid_server::crypto::random::<32>().unwrap())
        .collect();
    let blinded: Vec<_> = msgs.iter().map(|m| pk.client_blind(m).unwrap()).collect();
    let body = json!({ "action": "post-tokens", "blinded": blinded.iter().map(|b| B64(b.0.clone())).collect::<Vec<_>>() });
    let s = app.sign(phone, "POST", "/v1/live/attest", &body).unwrap();
    let signed_body = s.body.clone();
    let st: Value = app
        .core("POST", "/v1/live/attest", &json!({ "signed": s }))
        .await
        .unwrap();
    let anon_app = App::new(c).await.unwrap();
    let t: Value = anon_app
        .anon(
            "POST",
            "/v1/post-tokens",
            &json!({ "statement": st["statement"], "signed_body": signed_body, "kid": kid }),
        )
        .await
        .unwrap();
    msgs.iter()
        .zip(&blinded)
        .zip(t["blind_sigs"].as_array().unwrap())
        .map(|((m, (_, state)), sig)| {
            let (r, s) = pk
                .client_finalize(state, &B64::decode(sig.as_str().unwrap()).unwrap(), m)
                .unwrap();
            json!({ "kid": kid, "msg": B64(m.to_vec()), "randomizer": B64(r.to_vec()), "sig": B64(s) })
        })
        .collect()
}

/// F7 (M-6): an object bigger than the tick reply doesn't block what comes after it: it comes
/// back as a stub (fetched alone), and the next message in the prefix is delivered.
#[tokio::test]
async fn f7_a_big_deposit_never_blocks_a_prefix() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();
    let tokens = post_tokens(&c, &mut app, &phone, 9).await;
    let anon_app = App::new(&c).await.unwrap();
    let mallory_box = {
        let mut b = vec![0xABu8; 16];
        b[15] = 0;
        b
    };
    let ah = humid_server::anon::relay::token_hash(b"ack", &[9u8; 32]).unwrap();
    let _: Value = anon_app
        .anon("POST", "/v1/relay/deposit", &json!({ "tokens": tokens[..8], "box": B64(mallory_box.clone()), "ack_hash": B64(ah.clone()), "wire": B64(vec![0u8; 131_072]) }))
        .await
        .unwrap();
    let victim_box = vec![0xABu8; 16];
    let _: Value = anon_app
        .anon("POST", "/v1/relay/deposit", &json!({ "tokens": [tokens[8]], "box": B64(victim_box.clone()), "ack_hash": B64(ah), "wire": B64(vec![0u8; 4096]) }))
        .await
        .unwrap();
    let prefix = humid_server::anon::relay::prefix_of(&victim_box, 16);
    let mut slots = vec![json!({ "prefix": prefix, "after": 0 })];
    slots.extend((1..16).map(|i| json!({ "prefix": i, "after": 0 })));
    let r: Value = anon_app
        .anon("POST", "/v1/relay/tick", &json!({ "slots": slots }))
        .await
        .unwrap();
    let got = r["got"].as_array().unwrap();
    assert_eq!(got.len(), 2, "{}", r["more"]);
    assert!(got[0]["wire"].is_null(), "the big one is a stub");
    assert_eq!(got[0]["size"], 131_072);
    assert_eq!(got[1]["box"], json!(B64(victim_box)));
    assert_eq!(
        B64::decode(got[1]["wire"].as_str().unwrap()).unwrap().len(),
        4096,
        "the victim's message is delivered"
    );
    let f: Value = anon_app
        .anon(
            "POST",
            "/v1/relay/fetch",
            &json!({ "id": got[0]["id"], "box": B64(mallory_box) }),
        )
        .await
        .unwrap();
    assert_eq!(
        B64::decode(f["wire"].as_str().unwrap()).unwrap().len(),
        131_072
    );
    c.stop().await.unwrap();
}

/// M-6: a deposit costs one post token per 16 KiB of its size, and the relay total is kept
/// in SQL.
#[tokio::test]
async fn deposits_cost_by_size_and_the_total_is_in_sql() {
    let c = Cluster::start(|p| p.messaging.max_total_bytes = 100_000)
        .await
        .unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();
    let tokens = post_tokens(&c, &mut app, &phone, 16).await;
    let anon_app = App::new(&c).await.unwrap();
    let ah = humid_server::anon::relay::token_hash(b"ack", &[9u8; 32]).unwrap();
    let d = |t: &[Value], size: usize, b: u8| json!({ "tokens": t, "box": B64(vec![b; 16]), "ack_hash": B64(ah.clone()), "wire": B64(vec![0u8; size]) });
    assert_eq!(
        err_code(
            anon_app
                .anon::<_, Value>("POST", "/v1/relay/deposit", &d(&tokens[..1], 65_536, 1))
                .await
        ),
        "bad_tokens"
    );
    let _: Value = anon_app
        .anon("POST", "/v1/relay/deposit", &d(&tokens[..4], 65_536, 1))
        .await
        .unwrap();
    assert_eq!(
        err_code(
            anon_app
                .anon::<_, Value>("POST", "/v1/relay/deposit", &d(&tokens[4..8], 65_536, 2))
                .await
        ),
        "relay_full"
    );
    let _: Value = anon_app
        .anon("POST", "/v1/relay/deposit", &d(&tokens[8..10], 32_768, 3))
        .await
        .unwrap();
    c.stop().await.unwrap();
}

/// M-6: live checks for post tokens are capped per account per day.
#[tokio::test]
async fn live_checks_for_post_tokens_are_capped_per_day() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();
    let mut codes = vec![];
    for _ in 0..=humid_server::core::auth::LIVE_CHECKS_PER_DAY {
        app.refill().await.unwrap();
        let body = json!({ "action": "post-tokens", "blinded": [B64(vec![1; 256])] });
        let s = app.sign(&phone, "POST", "/v1/live/attest", &body).unwrap();
        codes.push(
            match app
                .core::<_, Value>("POST", "/v1/live/attest", &json!({ "signed": s }))
                .await
            {
                Ok(_) => "ok".to_string(),
                Err(e) => e.code_str().to_string(),
            },
        );
    }
    assert!(codes[..codes.len() - 1].iter().all(|c| c == "ok"));
    assert_eq!(codes.last().unwrap(), "rate_limited");
    c.stop().await.unwrap();
}

/// M-4: a call without its client network gets no shared production bucket.
#[tokio::test]
async fn a_missing_client_network_is_never_a_shared_production_bucket() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let mut h = axum::http::HeaderMap::new();
    assert_eq!(
        c.core.network(&h).unwrap(),
        "dev:unknown",
        "development only: per-account limits do the work"
    );
    h.insert("x-humid-client-net", "v4:192.0.2.1".parse().unwrap());
    assert_eq!(c.core.network(&h).unwrap(), "v4:192.0.2.1");
    c.stop().await.unwrap();
}

/// M-4: `limits.calls_per_minute` is enforced per session.
#[tokio::test]
async fn calls_per_minute_is_enforced_per_session() {
    let c = Cluster::start(|p| p.limits.calls_per_minute = 5)
        .await
        .unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();
    let mut codes = vec![];
    for _ in 0..7 {
        codes.push(
            match app.core::<_, Value>("GET", "/v1/me", &json!({})).await {
                Ok(_) => "ok".to_string(),
                Err(e) => e.code_str().to_string(),
            },
        );
    }
    assert_eq!(codes.last().unwrap(), "rate_limited", "{codes:?}");
    c.clock.advance(60_000);
    let _: Value = app.core("GET", "/v1/me", &json!({})).await.unwrap();
    c.stop().await.unwrap();
}

/// M-7: a unit's database keeps the highest policy it accepted: an older one is refused even
/// with a fresh data directory.
#[tokio::test]
async fn the_policy_high_water_mark_is_in_the_database() {
    use humid_server::policy;
    let c = Cluster::start(|p| p.version = 7).await.unwrap();
    policy::accept_db(c.core_db(), &c.policy).await.unwrap();
    policy::accept_db(c.core_db(), &c.policy).await.unwrap(); // a restart
    let mut older = c.policy.as_ref().clone();
    older.policy.version = 6;
    older.bytes = serde_json::to_vec(&older.policy).unwrap();
    assert_eq!(
        policy::accept_db(c.core_db(), &older)
            .await
            .unwrap_err()
            .code(),
        "policy_rollback"
    );
    let mut same = c.policy.as_ref().clone();
    same.bytes.push(b' ');
    assert_eq!(
        policy::accept_db(c.core_db(), &same)
            .await
            .unwrap_err()
            .code(),
        "policy_rollback",
        "same version, other bytes"
    );
    c.stop().await.unwrap();
}

/// L-13: a chunk number that would overflow is refused, not wrapped.
#[tokio::test]
async fn a_huge_chunk_number_is_refused() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).await.unwrap();
    app.register(&phone).await.unwrap();
    let (doc, _) = upload(&mut app, &phone, 64).await.unwrap();
    let (_, _, ticket) = open(&mut app, &phone, &doc.id).await.unwrap();
    let t = B64::encode(&ticket);
    for n in ["999999", "2048"] {
        let (status, _) = app
            .core_raw(
                "GET",
                &format!("/v1/objects/{}/chunks/{n}", doc.id),
                &[("x-humid-ticket", &t)],
            )
            .await
            .unwrap();
        assert_eq!(status, 400, "chunk {n}");
    }
    c.stop().await.unwrap();
}
