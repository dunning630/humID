//! Shared helpers for the integration tests.
#![allow(dead_code)]

use humid_server::crypto::{self, KemSecret, Secret32, phone};
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::App;
use humid_server::wire::{B64, Id};
use serde_json::{Value, json};

/// The keys unit's KEM key, as a phone fetches it.
pub async fn keys_kem(app: &App<'_>) -> crypto::KemPublic {
    let k: Value = app.core("GET", "/v1/keys-kem", &json!({})).await.unwrap();
    crypto::KemPublic::from_bytes(&B64::decode(k["kem_pk"].as_str().unwrap()).unwrap()).unwrap()
}

/// What a phone uploads, and what it keeps to check an open.
pub struct Doc {
    pub id: Id,
    pub envelope: Vec<u8>,
    pub manifest_hash: [u8; 64],
    pub share: Secret32,
}

/// Upload a document of `size` bytes.
pub async fn upload(
    app: &mut App<'_>,
    phone: &Phone,
    size: usize,
) -> humid_server::Result<(Doc, Value)> {
    let id = Id::random()?;
    let envelope: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let env_hash = crypto::sha3_512(&envelope);
    // in humid-core the manifest is the envelope's signed header; any 64 bytes stand in here
    let manifest_hash = crypto::sha3_512(&[b"manifest".as_slice(), id.as_bytes()].concat());
    let share = Secret32::random()?;
    let sealed = phone::seal_upload(
        &keys_kem(app).await,
        phone.account_id().as_bytes(),
        id.as_bytes(),
        &manifest_hash,
        &share,
    )?;
    let body = json!({
        "object": id,
        "envelope_hash": B64(env_hash.to_vec()),
        "manifest_hash": B64(manifest_hash.to_vec()),
        "sealed_share_hash": B64(crypto::sha3_512(&sealed).to_vec()),
        "index": B64(vec![7u8; 64]),
    });
    let signed = app.sign(phone, "POST", "/v1/objects", &body)?;
    let r: Value = app.core("POST", "/v1/objects", &json!({ "signed": signed, "envelope": B64(envelope.clone()), "sealed_share": B64(sealed) })).await?;
    Ok((
        Doc {
            id,
            envelope,
            manifest_hash,
            share,
        },
        r,
    ))
}

/// humid-core's share request for `id`, to `once` (CORE.md §6.3).
pub fn share_request(
    phone: &Phone,
    id: &Id,
    manifest_hash: &[u8; 64],
    once: &KemSecret,
) -> Vec<u8> {
    crypto::ShareRequest::encode(&phone.account_id().0, &id.0, manifest_hash, &once.public())
}

/// The body a phone signs to open `id`, sealing the share to `once`.
pub fn open_body(phone: &Phone, id: &Id, once: &KemSecret) -> Value {
    json!({ "object": id, "share_request": B64(share_request(phone, id, &manifest_of(id), once)) })
}

/// The manifest hash `upload` uses for `id`.
pub fn manifest_of(id: &Id) -> [u8; 64] {
    crypto::sha3_512(&[b"manifest".as_slice(), id.as_bytes()].concat())
}

/// Open a document: returns the share (opened with the one-time key) and the open reply.
pub async fn open(
    app: &mut App<'_>,
    phone: &Phone,
    id: &Id,
) -> humid_server::Result<(Secret32, Value, Vec<u8>)> {
    let once = KemSecret::generate()?;
    let req = share_request(phone, id, &manifest_of(id), &once);
    let binding = crypto::hash(crypto::SHARE_REQUEST_LABEL, &[&req])?;
    let body = json!({ "object": id, "share_request": B64(req) });
    let path = format!("/v1/objects/{id}/open");
    let signed = app.sign(phone, "POST", &path, &body)?;
    let r: Value = app
        .core("POST", &path, &json!({ "signed": signed }))
        .await?;
    let sealed = B64::decode(r["sealed_share"].as_str().unwrap()).unwrap();
    let share = phone::open_release(
        &once,
        phone.account_id().as_bytes(),
        id.as_bytes(),
        &binding,
        &sealed,
    )?;
    let ticket = B64::decode(r["ticket"].as_str().unwrap()).unwrap();
    Ok((share, r, ticket))
}

/// A new device's join request for `account` (humid-core's format, 0x0108), its parse, and
/// the body a link start sends.
pub fn join(device: &Phone, account: &Id, kem: &KemSecret) -> (crypto::JoinRequest, Value) {
    let req = phone::join_request(&account.0, &device.device, &kem.public()).unwrap();
    let parsed = crypto::JoinRequest::parse(&req).unwrap();
    (parsed, json!({ "request": B64(req), "platform": "tablet" }))
}

/// The body an approving device signs for a join request.
pub fn approval(req: &crypto::JoinRequest, envelope: Vec<u8>) -> Value {
    json!({ "binding": B64(req.binding.to_vec()), "envelope": B64(envelope) })
}

/// The error code of a result that must have failed (secrets have no `Debug`, so no `unwrap_err`).
pub fn err_code<T>(r: humid_server::Result<T>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal, got success"),
        Err(e) => e.code_str().to_string(),
    }
}

/// Ledger event types for an account, in order.
pub async fn events(app: &App<'_>) -> Vec<String> {
    let r: Value = app
        .core("GET", "/v1/ledger/events?since=0&limit=1000", &json!({}))
        .await
        .unwrap();
    r["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let body = B64::decode(e["body"].as_str().unwrap()).unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            v["type"].as_str().unwrap().to_string()
        })
        .collect()
}

/// The full ledger entries (parsed bodies).
pub async fn entries(app: &App<'_>) -> Vec<Value> {
    let r: Value = app
        .core("GET", "/v1/ledger/events?since=0&limit=1000", &json!({}))
        .await
        .unwrap();
    r["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            serde_json::from_slice(&B64::decode(e["body"].as_str().unwrap()).unwrap()).unwrap()
        })
        .collect()
}
