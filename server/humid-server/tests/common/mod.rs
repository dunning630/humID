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
    let share = Secret32::random()?;
    let sealed = phone::seal_upload(
        &keys_kem(app).await,
        phone.account_id().as_bytes(),
        id.as_bytes(),
        &env_hash,
        &share,
    )?;
    let body = json!({
        "object": id,
        "envelope_hash": B64(env_hash.to_vec()),
        "sealed_share_hash": B64(crypto::sha3_512(&sealed).to_vec()),
        "index": B64(vec![7u8; 64]),
    });
    let signed = app.sign(phone, "POST", "/v1/objects", &body)?;
    let r: Value = app.core("POST", "/v1/objects", &json!({ "signed": signed, "envelope": B64(envelope.clone()), "sealed_share": B64(sealed) })).await?;
    Ok((
        Doc {
            id,
            envelope,
            share,
        },
        r,
    ))
}

/// Open a document: returns the share (opened with the one-time key) and the open reply.
pub async fn open(
    app: &mut App<'_>,
    phone: &Phone,
    id: &Id,
) -> humid_server::Result<(Secret32, Value, Vec<u8>)> {
    let once = KemSecret::generate()?;
    let body = json!({ "object": id, "to": B64(once.public().to_bytes()) });
    let path = format!("/v1/objects/{id}/open");
    let signed = app.sign(phone, "POST", &path, &body)?;
    let binding = crypto::sha3_512(&signed.proof.device_sig);
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
