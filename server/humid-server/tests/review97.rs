//! Regression tests for the PR #97 review, end to end (each was a probe that passed while its
//! finding was present).

mod common;

use common::*;
use humid_server::crypto;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::wire::{B64, Id};
use serde_json::{Value, json};

async fn upload_body(a: &App<'_>, alice: &Phone) -> (Value, Vec<u8>, Vec<u8>) {
    let id = Id::random().unwrap();
    let envelope: Vec<u8> = vec![5u8; 200];
    let manifest_hash = crypto::sha3_512(&[b"manifest".as_slice(), id.as_bytes()].concat());
    let share = crypto::Secret32::random().unwrap();
    let sealed = crypto::phone::seal_upload(
        &keys_kem(a).await,
        alice.account_id().as_bytes(),
        id.as_bytes(),
        &manifest_hash,
        &share,
    )
    .unwrap();
    let body = json!({
        "object": id,
        "envelope_hash": B64(crypto::sha3_512(&envelope).to_vec()),
        "manifest_hash": B64(manifest_hash.to_vec()),
        "sealed_share_hash": B64(crypto::sha3_512(&sealed).to_vec()),
        "index": B64(vec![7u8; 64]),
    });
    (body, envelope, sealed)
}

/// M-1: a live proof whose `seq` names a request of session generation 0 is refused on
/// another request in generation 1, in every body shape: the array form (refused by the
/// endpoint), and the typed proof part on a fresh request (refused by core's own seq check,
/// which now gets the request's seq from the endpoint).
#[tokio::test]
async fn m1_a_proof_is_bound_to_its_request_in_every_body_shape() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (body, envelope, sealed) = upload_body(&a, &alice).await;
    let signed = a.sign(&alice, "POST", "/v1/objects", &body).unwrap();
    assert_eq!(signed.proof.seq >> 32, 0);
    let (_, resumed) = a.relock().await.unwrap();
    assert_eq!(resumed, 1);
    // the array form the probe used
    let arr = json!([signed, B64(envelope.clone()), B64(sealed.clone())]);
    let e = a.core::<_, Value>("POST", "/v1/objects", &arr).await;
    assert_eq!(err_code(e), "bad_frame");
    // the same proof as a typed part on a fresh request id (the testkit sends a proof whose
    // seq it didn't reserve on a new request)
    let full = json!({ "signed": signed, "envelope": B64(envelope), "sealed_share": B64(sealed) });
    let e = a.core::<_, Value>("POST", "/v1/objects", &full).await;
    assert_eq!(err_code(e), "proof_mismatch");
    // nothing was stored
    let s: Value = a.core("POST", "/v1/sync", &json!({})).await.unwrap();
    assert!(s["changed"].as_array().unwrap().is_empty());
    c.stop().await.unwrap();
}

/// M-1: core refuses a proof that names another request even when it reaches core in a
/// session whose transcript differs from the proof's (no endpoint check applies then): the
/// endpoint's `x-humid-seq` is what core compares.
#[tokio::test]
async fn m1_core_checks_seq_itself() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let alice = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&alice).await.unwrap();
    let (body, envelope, sealed) = upload_body(&a, &alice).await;
    let mut signed = a.sign(&alice, "POST", "/v1/objects", &body).unwrap();
    // a proof for a request id far ahead (never reserved): the endpoint's own check passes
    // it only if its th differs, so re-sign with the right th and a wrong seq
    let nonce = signed.proof.nonce.0.clone();
    signed = alice
        .step_up(
            "POST",
            "/v1/objects",
            &a.th,
            signed.proof.seq + 7,
            &nonce,
            c.clock.now(),
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    let full = json!({ "signed": signed, "envelope": B64(envelope), "sealed_share": B64(sealed) });
    let e = a.core::<_, Value>("POST", "/v1/objects", &full).await;
    assert_eq!(err_code(e), "proof_mismatch");
    c.stop().await.unwrap();
}

/// L-2: anon never receives a client network; core gets front's, from the socket.
#[tokio::test]
async fn l2_anon_gets_no_client_address() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut a = App::new(&c).await.unwrap();
    a.register(&phone).await.unwrap();
    let seen = humid_server::testkit::cluster::anon_saw_client_net(&c);
    let _: Value = a
        .anon("GET", "/v1/post-tokens/keys", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        humid_server::testkit::cluster::anon_saw_client_net(&c),
        seen,
        "no anon request carried x-humid-client-net"
    );
    c.stop().await.unwrap();
}
