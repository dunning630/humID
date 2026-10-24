//! Hardened recovery (V5.md "Recovery"): two of the holder's proofs, then a wait that every
//! surviving device can veto. Holder-only accounts (the default until the holder chooses)
//! hold nothing here and release nothing.
//!
//! Proof kinds: `card` (a recovery card; looked up by a tag the HSM keys, so a database copy
//! can't be searched by card), `witness` (enough of the holder's witnesses, each with a live
//! check of their own), and — stubbed — `anchor` (passport) and `key` (FIDO).
//! A released recovery is consumed only by `devices::enrol`, for the device key the request
//! named, in that enrolment's own transaction (H1).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};

use super::auth::Approved;
use super::ledger::{self, Vouch};
use super::{Core, ENVELOPE, Reply, SMALL, ok, read};
use crate::crypto::{self, KemPublic, MlDsaPublic, label};
use crate::error::{Error, Result};
use crate::hsm::KeyRef;
use crate::unit::ms;
use crate::wire::{self, B64, Id};

/// Modes.
pub const HOLDER_ONLY: &str = "holder-only";
/// Modes.
pub const HARDENED: &str = "hardened";
/// Witnesses per account.
pub const MIN_WITNESSES: usize = 2;
/// Witnesses per account.
pub const MAX_WITNESSES: usize = 5;
/// Open recoveries per account.
pub const MAX_OPEN_PER_ACCOUNT: i64 = 3;
/// Unbound (anonymous) recoveries in all.
pub const MAX_UNBOUND: i64 = 10_000;
/// A request collects proofs for this long.
pub const COLLECT_MS: i64 = 7 * ms::DAY;
/// Request codes (80 bits).
pub const CODE_LEN: usize = 16;

/* ------------------------------- mode ------------------------------- */

/// The bytes the account key signs for a mode.
///
/// # Errors
/// Never in practice.
pub fn mode_message(account: &Id, mode: &str, version: u32, prev: &[u8]) -> Result<Vec<u8>> {
    crypto::lp(&[
        account.as_bytes(),
        mode.as_bytes(),
        &version.to_be_bytes(),
        prev,
    ])
}

async fn mode_of(c: &impl deadpool_postgres::GenericClient, account: &Id) -> Result<String> {
    Ok(c.query_opt(
        "SELECT mode FROM recovery_mode WHERE account = $1",
        &[&account.as_bytes()],
    )
    .await?
    .map_or_else(|| HOLDER_ONLY.to_string(), |r| r.get(0)))
}

async fn require_hardened(c: &impl deadpool_postgres::GenericClient, account: &Id) -> Result<()> {
    if mode_of(c, account).await? != HARDENED {
        return Err(Error::conflict(
            "holder_only",
            "This HumID opens only on its own devices, so it keeps no recovery pieces.",
        ));
    }
    Ok(())
}

/// `PUT /v1/recovery/mode`: the signed body is `ModeBody`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModeBody {
    /// `holder-only` or `hardened`.
    pub mode: String,
    /// Strictly increasing.
    pub version: u32,
    /// The account key's signature over `mode_message(…, prev = hash of the last statement)`.
    pub statement: B64,
}

/// Set the recovery mode (step-up + the account key's own chained statement).
pub async fn set_mode(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let r: Approved = read(body, SMALL).await?;
    let m: ModeBody = wire::parse(&r.signed.body)?;
    if m.mode != HOLDER_ONLY && m.mode != HARDENED {
        return Err(Error::bad("bad_recovery_mode", "Unknown recovery mode."));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(&tx, &s, &r.signed, "PUT", "/v1/recovery/mode")
        .await?;
    let a = s.account.as_bytes();
    let prev = tx
        .query_opt(
            "SELECT version, hash FROM recovery_mode WHERE account = $1 FOR UPDATE",
            &[&a],
        )
        .await?;
    let (last_version, prev_hash) = prev.map_or((0u32, vec![0u8; 64]), |r| {
        (u32::try_from(r.get::<_, i32>(0)).unwrap_or(0), r.get(1))
    });
    if m.version <= last_version {
        return Err(Error::conflict(
            "stale_recovery_mode",
            "A newer recovery choice is already on file.",
        ));
    }
    let avk: Vec<u8> = tx
        .query_one("SELECT account_vk FROM accounts WHERE id = $1", &[&a])
        .await?
        .get(0);
    let msg = mode_message(&s.account, &m.mode, m.version, &prev_hash)?;
    if !MlDsaPublic::from_bytes(&avk)?.verifies(label::RECOVERY_MODE, &msg, &m.statement) {
        return Err(Error::bad_proof());
    }
    let hash = crypto::hash(label::RECOVERY_MODE, &[&msg])?;
    let v = i32::try_from(m.version)
        .map_err(|_| Error::bad("bad_recovery_mode", "Version too large."))?;
    tx.execute(
        "INSERT INTO recovery_mode (account, mode, version, statement, hash) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account) DO UPDATE SET mode = $2, version = $3, statement = $4, hash = $5",
        &[&a, &m.mode, &v, &m.statement.0, &hash.as_slice()],
    )
    .await?;
    if m.mode == HOLDER_ONLY {
        // holder-only keeps nothing and releases nothing, whatever was collected before
        tx.execute("DELETE FROM recovery_cards WHERE account = $1", &[&a])
            .await?;
        tx.execute("DELETE FROM recovery_witnesses WHERE account = $1", &[&a])
            .await?;
        tx.execute("UPDATE recovery_requests SET status = 'cancelled', closed_at = $2 WHERE account = $1 AND status IN ('collecting', 'waiting')", &[&a, &core.now()])
            .await?;
    }
    tx.execute(
        "UPDATE accounts SET recovery_rev = recovery_rev + 1 WHERE id = $1",
        &[&a],
    )
    .await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "recovery.mode_set",
        &serde_json::json!({ "mode": m.mode, "version": m.version, "hash": hex::encode(hash) }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "mode": m.mode, "version": m.version }))
}

/* ------------------------------- card ------------------------------- */

/// The card's lookup tag: keyed by the HSM, so the table can't be searched without it.
///
/// # Errors
/// HSM failure.
pub fn card_tag(core: &Core, lookup: &[u8]) -> Result<[u8; 32]> {
    core.hsm.mac(KeyRef::CardTag, label::CARD_TAG, &[lookup])
}

/// `PUT /v1/recovery/card`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardBody {
    /// 32 bytes the phone derives from the card's ≥160-bit secret, for lookup only.
    pub lookup: B64,
    /// The card part, sealed on the phone under the card secret.
    pub blob: B64,
}

/// Set (or replace) the recovery card.
pub async fn set_card(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let r: Approved = read(body, SMALL).await?;
    let b: CardBody = wire::parse(&r.signed.body)?;
    if b.lookup.len() != 32 || b.blob.is_empty() || b.blob.len() > 1024 {
        return Err(Error::bad(
            "bad_card",
            "A card lookup is 32 bytes and its part at most 1 KiB.",
        ));
    }
    let tag = card_tag(&core, &b.lookup)?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(&tx, &s, &r.signed, "PUT", "/v1/recovery/card")
        .await?;
    require_hardened(&tx, &s.account).await?;
    let a = s.account.as_bytes();
    tx.execute(
        "INSERT INTO recovery_cards (account, tag, blob, set_at) VALUES ($1, $2, $3, $4) ON CONFLICT (account) DO UPDATE SET tag = $2, blob = $3, set_at = $4",
        &[&a, &tag.as_slice(), &b.blob.0, &core.now()],
    )
    .await?;
    tx.execute(
        "UPDATE accounts SET recovery_rev = recovery_rev + 1 WHERE id = $1",
        &[&a],
    )
    .await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "recovery.card_set",
        &serde_json::json!({}),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "card": true }))
}

/// Remove the card.
pub async fn remove_card(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    remove_piece(
        core,
        headers,
        body,
        "/v1/recovery/card",
        "recovery_cards",
        "recovery.card_removed",
    )
    .await
}

/// Remove the witnesses.
pub async fn remove_witnesses(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    body: Body,
) -> Reply {
    remove_piece(
        core,
        headers,
        body,
        "/v1/recovery/witnesses",
        "recovery_witnesses",
        "recovery.witnesses_removed",
    )
    .await
}

async fn remove_piece(
    core: Arc<Core>,
    headers: HeaderMap,
    body: Body,
    path: &str,
    table: &str,
    event: &str,
) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let r: Approved = read(body, SMALL).await?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core.step_up(&tx, &s, &r.signed, "DELETE", path).await?;
    let a = s.account.as_bytes();
    tx.execute(
        format!("DELETE FROM {table} WHERE account = $1").as_str(),
        &[&a],
    )
    .await?;
    tx.execute(
        "UPDATE accounts SET recovery_rev = recovery_rev + 1 WHERE id = $1",
        &[&a],
    )
    .await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        event,
        &serde_json::json!({}),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "removed": true }))
}

/* ----------------------------- witnesses ----------------------------- */

/// `PUT /v1/recovery/witnesses`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessesBody {
    /// How many must help.
    pub threshold: u32,
    /// Each witness's account and their piece, sealed to that witness.
    pub witnesses: Vec<WitnessPiece>,
}

/// One witness.
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WitnessPiece {
    /// Their account.
    pub account: Id,
    /// Their piece, sealed on the holder's phone to the witness's KEM key.
    pub envelope: B64,
}

/// Set (or replace) the witnesses.
pub async fn set_witnesses(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let r: Approved = read(body, 6 * ENVELOPE).await?;
    let b: WitnessesBody = wire::parse(&r.signed.body)?;
    let n = b.witnesses.len();
    let mut uniq: Vec<Id> = b.witnesses.iter().map(|w| w.account).collect();
    uniq.sort();
    uniq.dedup();
    if !(MIN_WITNESSES..=MAX_WITNESSES).contains(&n)
        || uniq.len() != n
        || b.threshold as usize != n / 2 + 1
        || uniq.contains(&s.account)
    {
        return Err(Error::bad(
            "bad_witnesses",
            "Choose 2 to 5 other people; more than half must help.",
        ));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(&tx, &s, &r.signed, "PUT", "/v1/recovery/witnesses")
        .await?;
    require_hardened(&tx, &s.account).await?;
    let a = s.account.as_bytes();
    tx.execute("DELETE FROM recovery_witnesses WHERE account = $1", &[&a])
        .await?;
    for w in &b.witnesses {
        if w.envelope.is_empty() || w.envelope.len() > 64 << 10 {
            return Err(Error::bad(
                "bad_envelope",
                "A witness piece is missing or too large.",
            ));
        }
        let ok = tx
            .query_opt(
                "SELECT 1 FROM accounts WHERE id = $1 AND status = 'active'",
                &[&w.account.as_bytes()],
            )
            .await?;
        if ok.is_none() {
            return Err(Error::not_found(
                "unknown_witness",
                "One of these witnesses has no HumID here.",
            ));
        }
        tx.execute(
            "INSERT INTO recovery_witnesses (account, witness, threshold, envelope, set_at) VALUES ($1, $2, $3, $4, $5)",
            &[&a, &w.account.as_bytes(), &i32::try_from(b.threshold).unwrap_or(i32::MAX), &w.envelope.0, &core.now()],
        )
        .await?;
    }
    tx.execute(
        "UPDATE accounts SET recovery_rev = recovery_rev + 1 WHERE id = $1",
        &[&a],
    )
    .await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "recovery.witnesses_set",
        &serde_json::json!({ "n": n, "threshold": b.threshold }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "witnesses": n, "threshold": b.threshold }))
}

/* ------------------------------ requests ------------------------------ */

/// The wait for a set of proof kinds (the stronger, the shorter), doubled after a recent
/// duress signal. `None` until two different kinds are in.
#[must_use]
pub fn delay(kinds: &[&str], base: i64, duress: bool) -> Option<i64> {
    let mut k: Vec<&str> = kinds.to_vec();
    k.sort_unstable();
    k.dedup();
    if k.len() < 2 {
        return None;
    }
    let ms = if k.contains(&"witness") {
        base
    } else {
        base * 7 / 3
    };
    Some(if duress { ms * 2 } else { ms })
}

fn request_code(device_vk: &[u8], kem_pk: &[u8]) -> Result<String> {
    let h = crypto::hash(label::CODE, &[b"recover", device_vk, kem_pk])?;
    Ok(wire::base32(&h, CODE_LEN))
}

/// `POST /v1/recovery/requests` (anonymous).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartReq {
    /// The device key that will join when this is released.
    pub device_vk: B64,
    /// The new device's KEM key (pieces are sealed to it).
    pub kem_pk: B64,
    /// What it calls itself.
    #[serde(default)]
    pub platform: String,
}

/// A new phone starts a recovery. Limited per network and in all (no single bucket an
/// anonymous visitor can drain for everyone: M4); once a proof names the account, per account.
pub async fn start(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let r: StartReq = read(body, SMALL).await?;
    MlDsaPublic::from_bytes(&r.device_vk)?;
    KemPublic::from_bytes(&r.kem_pk)?;
    let net = Core::network(&headers);
    let now = core.now();
    if !core.recovery_per_network.take(&net, now) {
        return Err(Error::too_many(
            "rate_limited",
            "Too many recoveries started from this network. Try again later.",
        ));
    }
    let c = core.db.conn().await?;
    let unbound: i64 = c.query_one("SELECT count(*) FROM recovery_requests WHERE account IS NULL AND status = 'collecting'", &[]).await?.get(0);
    if unbound >= MAX_UNBOUND {
        return Err(Error::busy());
    }
    let id = crypto::random::<16>()?;
    let reference = hex::encode(crypto::random::<8>()?);
    let code = request_code(&r.device_vk, &r.kem_pk)?;
    let platform: String = r
        .platform
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let n = c
        .execute(
            "INSERT INTO recovery_requests (id, ref, code, device_vk, kem_pk, platform, status, created_at, expires_at, network)
             VALUES ($1, $2, $3, $4, $5, $6, 'collecting', $7, $8, $9) ON CONFLICT DO NOTHING",
            &[&id.as_slice(), &reference, &code, &r.device_vk.0, &r.kem_pk.0, &platform, &now, &(now + COLLECT_MS), &net],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict("code_in_use", "Start again."));
    }
    super::created(
        &serde_json::json!({ "request": B64(id.to_vec()), "code": code, "expires_at": now + COLLECT_MS }),
    )
}

fn request_id(s: &str) -> Result<Vec<u8>> {
    let id = B64::decode(s)?;
    if id.len() != 16 {
        return Err(Error::not_found("unknown_request", "No such recovery."));
    }
    Ok(id)
}

async fn kinds_of(
    c: &impl deadpool_postgres::GenericClient,
    request: &[u8],
    account: Option<&Id>,
) -> Result<Vec<&'static str>> {
    let rows = c
        .query(
            "SELECT kind, count(*) FROM recovery_evidence WHERE request = $1 GROUP BY kind",
            &[&request],
        )
        .await?;
    let threshold: Option<i32> = match account {
        Some(a) => c
            .query_opt(
                "SELECT threshold FROM recovery_witnesses WHERE account = $1 LIMIT 1",
                &[&a.as_bytes()],
            )
            .await?
            .map(|r| r.get(0)),
        None => None,
    };
    let mut out = vec![];
    for r in rows {
        let (k, n): (String, i64) = (r.get(0), r.get(1));
        match k.as_str() {
            "card" => out.push("card"),
            "witness" if threshold.is_some_and(|t| n >= i64::from(t)) => out.push("witness"),
            _ => {}
        }
    }
    Ok(out)
}

/// Bind a request to an account (the first proof names it), then (re)compute its wait.
async fn bind_and_evaluate(
    tx: &Transaction<'_>,
    core: &Core,
    request: &[u8],
    account: &Id,
) -> Result<()> {
    let row = tx
        .query_one(
            "SELECT account, status FROM recovery_requests WHERE id = $1 FOR UPDATE",
            &[&request],
        )
        .await?;
    let bound: Option<Vec<u8>> = row.get(0);
    let status: String = row.get(1);
    if status != "collecting" && status != "waiting" {
        return Err(Error::conflict(
            "closed",
            "This recovery is no longer open. Start again.",
        ));
    }
    let now = core.now();
    match bound {
        Some(b) if b != account.as_bytes() => {
            return Err(Error::conflict(
                "different_person",
                "These proofs belong to different people. Nothing was released.",
            ));
        }
        Some(_) => {}
        None => {
            require_hardened(tx, account).await?;
            let open: i64 = tx
                .query_one("SELECT count(*) FROM recovery_requests WHERE account = $1 AND status IN ('collecting', 'waiting')", &[&account.as_bytes()])
                .await?
                .get(0);
            if open >= MAX_OPEN_PER_ACCOUNT {
                return Err(Error::too_many(
                    "too_many_requests",
                    "There are already recoveries waiting for this HumID.",
                ));
            }
            tx.execute(
                "UPDATE recovery_requests SET account = $2 WHERE id = $1",
                &[&request, &account.as_bytes()],
            )
            .await?;
            let reference: String = tx
                .query_one(
                    "SELECT ref FROM recovery_requests WHERE id = $1",
                    &[&request],
                )
                .await?
                .get(0);
            ledger::append(
                tx,
                now,
                account,
                "recovery.requested",
                &serde_json::json!({ "ref": reference }),
                Vouch::Server,
            )
            .await?;
        }
    }
    let kinds = kinds_of(tx, request, Some(account)).await?;
    let p = &core.policy.policy.recovery;
    let duress: Option<i64> = tx
        .query_one(
            "SELECT max(at) FROM duress WHERE account = $1",
            &[&account.as_bytes()],
        )
        .await?
        .get(0);
    let recent_duress = duress.is_some_and(|d| now - d < p.duress_window_ms);
    match delay(&kinds, p.base_delay_ms, recent_duress) {
        Some(d) if status == "collecting" => {
            tx.execute("UPDATE recovery_requests SET status = 'waiting', release_at = $2, expires_at = $3 WHERE id = $1", &[&request, &(now + d), &(now + d + COLLECT_MS)])
                .await?;
        }
        _ => {}
    }
    Ok(())
}

/// `POST /v1/recovery/requests/:id/card` (anonymous).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardEvidence {
    /// The 32-byte lookup the phone derives from the card.
    pub lookup: B64,
}

/// Add the recovery card to a request.
pub async fn add_card(State(core): State<Arc<Core>>, Path(id): Path<String>, body: Body) -> Reply {
    let request = request_id(&id)?;
    let r: CardEvidence = read(body, SMALL).await?;
    if r.lookup.len() != 32 {
        return Err(Error::bad("bad_card", "A card lookup is 32 bytes."));
    }
    let tag = card_tag(&core, &r.lookup)?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let card = tx
        .query_opt(
            "SELECT account, blob FROM recovery_cards WHERE tag = $1",
            &[&tag.as_slice()],
        )
        .await?
        .ok_or_else(|| {
            Error::not_found(
                "unknown_card",
                "That recovery card isn't on file. Check the code, or it may have been replaced.",
            )
        })?;
    let account = Id::from_slice(&card.get::<_, Vec<u8>>(0))?;
    let blob: Vec<u8> = card.get(1);
    tx.execute(
        "INSERT INTO recovery_evidence (request, kind, blob, at) VALUES ($1, 'card', $2, $3) ON CONFLICT (request, kind, witness) DO UPDATE SET blob = $2",
        &[&request, &blob, &core.now()],
    )
    .await
    .map_err(|_| Error::not_found("unknown_request", "No such recovery."))?;
    bind_and_evaluate(&tx, &core, &request, &account).await?;
    ledger::append(
        &tx,
        core.now(),
        &account,
        "recovery.evidence",
        &serde_json::json!({ "kind": "card" }),
        Vouch::Server,
    )
    .await?;
    tx.commit().await?;
    status_of(&core, &request).await
}

/// Passport evidence: stubbed.
pub async fn add_anchor(Path(_id): Path<String>) -> Reply {
    Err(Error::NotImplemented {
        what: "passport (ID chip) recovery evidence",
        waiting_on: "a second share operator, and ICAO passive authentication in Rust",
    })
}

/// Security-key evidence: stubbed.
pub async fn add_key(Path(_id): Path<String>) -> Reply {
    Err(Error::NotImplemented {
        what: "security-key (FIDO) recovery evidence",
        waiting_on: "CTAP / hmac-secret verification in Rust",
    })
}

/// `GET /v1/recovery/help/:code`: a witness looks up a code someone gave them.
pub async fn help_get(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Reply {
    core.session(&headers).await?;
    if !wire::is_code(&code, CODE_LEN) {
        return Err(Error::bad("bad_code", "That isn't a recovery code."));
    }
    let c = core.db.conn().await?;
    let r = c
        .query_opt("SELECT device_vk, kem_pk, platform FROM recovery_requests WHERE code = $1 AND status IN ('collecting', 'waiting') AND expires_at > $2", &[&code, &core.now()])
        .await?
        .ok_or_else(|| Error::not_found("unknown_request", "No recovery is waiting with that code."))?;
    ok(
        &serde_json::json!({ "device_vk": B64(r.get(0)), "kem_pk": B64(r.get(1)), "platform": r.get::<_, String>(2) }),
    )
}

/// `POST /v1/recovery/help/:code`: the witness's signed body.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelpBody {
    /// Whom they're helping.
    pub account: Id,
    /// Their piece, re-sealed (on their phone) to the new device's KEM key.
    pub envelope: B64,
}

/// A witness helps, with their own live check.
pub async fn help(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(code): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    if !wire::is_code(&code, CODE_LEN) {
        return Err(Error::bad("bad_code", "That isn't a recovery code."));
    }
    let r: Approved = read(body, ENVELOPE).await?;
    let h: HelpBody = wire::parse(&r.signed.body)?;
    if h.envelope.is_empty() || h.envelope.len() > 64 << 10 {
        return Err(Error::bad(
            "bad_envelope",
            "The piece is missing or too large.",
        ));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(
            &tx,
            &s,
            &r.signed,
            "POST",
            &format!("/v1/recovery/help/{code}"),
        )
        .await?;
    let witness = tx
        .query_opt(
            "SELECT 1 FROM recovery_witnesses WHERE account = $1 AND witness = $2",
            &[&h.account.as_bytes(), &s.account.as_bytes()],
        )
        .await?;
    if witness.is_none() {
        return Err(Error::forbidden(
            "not_a_witness",
            "You aren't one of this person's witnesses.",
        ));
    }
    let request: Vec<u8> = tx
        .query_opt(
            "SELECT id FROM recovery_requests WHERE code = $1 AND expires_at > $2",
            &[&code, &core.now()],
        )
        .await?
        .ok_or_else(|| {
            Error::not_found("unknown_request", "No recovery is waiting with that code.")
        })?
        .get(0);
    tx.execute(
        "INSERT INTO recovery_evidence (request, kind, witness, blob, at) VALUES ($1, 'witness', $2, $3, $4)
         ON CONFLICT (request, kind, witness) DO UPDATE SET blob = $3",
        &[&request, &s.account.as_bytes(), &h.envelope.0, &core.now()],
    )
    .await?;
    bind_and_evaluate(&tx, &core, &request, &h.account).await?;
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "recovery.helped",
        &serde_json::json!({ "for": h.account }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    ledger::append(
        &tx,
        core.now(),
        &h.account,
        "recovery.evidence",
        &serde_json::json!({ "kind": "witness", "witness": s.account }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "helped": true }))
}

/// Where a request stands, as the new device sees it.
#[derive(Serialize, Deserialize, Debug)]
pub struct RequestView {
    /// `collecting`, `waiting`, `released`, `cancelled`, `completed`, `expired`.
    pub status: String,
    /// The account, once a proof named it.
    pub account: Option<Id>,
    /// Proof kinds that count so far.
    pub kinds: Vec<String>,
    /// When it releases (ms).
    pub release_at: Option<i64>,
    /// Released pieces (card part, witness pieces), sealed to the new device.
    #[serde(default)]
    pub pieces: Vec<B64>,
}

async fn status_of(core: &Core, request: &[u8]) -> Reply {
    let c = core.db.conn().await?;
    let r = c
        .query_opt(
            "SELECT status, account, release_at, expires_at FROM recovery_requests WHERE id = $1",
            &[&request],
        )
        .await?
        .ok_or_else(|| Error::not_found("unknown_request", "No such recovery."))?;
    let mut status: String = r.get(0);
    let account = r
        .get::<_, Option<Vec<u8>>>(1)
        .map(|a| Id::from_slice(&a))
        .transpose()?;
    let release_at: Option<i64> = r.get(2);
    let now = core.now();
    if r.get::<_, i64>(3) < now && (status == "collecting" || status == "waiting") {
        status = "expired".into();
    }
    let kinds = kinds_of(&c, request, account.as_ref()).await?;
    let mut pieces = vec![];
    if status == "waiting"
        && release_at.is_some_and(|t| now >= t)
        && let Some(a) = &account
    {
        {
            if mode_of(&c, a).await? == HARDENED {
                status = "released".into();
                pieces = c
                    .query("SELECT blob FROM recovery_evidence WHERE request = $1 AND blob IS NOT NULL ORDER BY kind, witness", &[&request])
                    .await?
                    .iter()
                    .map(|r| B64(r.get(0)))
                    .collect();
            } else {
                status = "cancelled".into();
            }
        }
    }
    ok(&RequestView {
        status,
        account,
        kinds: kinds.iter().map(|k| (*k).to_string()).collect(),
        release_at,
        pieces,
    })
}

/// `GET /v1/recovery/requests/:id` (the 128-bit id is the capability).
pub async fn status(State(core): State<Arc<Core>>, Path(id): Path<String>) -> Reply {
    status_of(&core, &request_id(&id)?).await
}

/// Consume a released recovery for an enrolment (called inside `devices::enrol`'s transaction).
///
/// # Errors
/// `not_approved` if it isn't released, for this account, for this device key.
pub async fn consume_release(
    tx: &Transaction<'_>,
    _core: &Core,
    request: &[u8],
    account: &Id,
    device_vk: &[u8],
    now: i64,
) -> Result<()> {
    let refuse = || {
        Error::forbidden(
            "not_approved",
            "That recovery isn't released yet, so this device can't join.",
        )
    };
    if request.len() != 16 {
        return Err(refuse());
    }
    require_hardened(tx, account).await.map_err(|_| refuse())?;
    let n = tx
        .execute(
            "UPDATE recovery_requests SET status = 'completed', closed_at = $4
              WHERE id = $1 AND account = $2 AND device_vk = $3 AND status = 'waiting' AND release_at <= $4 AND expires_at > $4",
            &[&request, &account.as_bytes(), &device_vk, &now],
        )
        .await?;
    if n != 1 {
        return Err(refuse());
    }
    tx.execute(
        "DELETE FROM recovery_evidence WHERE request = $1",
        &[&request],
    )
    .await?;
    Ok(())
}

/// `GET /v1/recovery/alerts`: open recoveries of this account (every device sees them).
pub async fn alerts(State(core): State<Arc<Core>>, headers: HeaderMap) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    let rows = c
        .query(
            "SELECT ref, status, platform, created_at, release_at FROM recovery_requests WHERE account = $1 AND status IN ('collecting', 'waiting') ORDER BY created_at",
            &[&s.account.as_bytes()],
        )
        .await?;
    let v: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| serde_json::json!({ "ref": r.get::<_, String>(0), "status": r.get::<_, String>(1), "platform": r.get::<_, String>(2), "created_at": r.get::<_, i64>(3), "release_at": r.get::<_, Option<i64>>(4) }))
        .collect();
    ok(&serde_json::json!({ "alerts": v }))
}

/// `POST /v1/recovery/alerts/:ref/cancel`: the veto, from any signed-in device.
pub async fn cancel(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(reference): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    if reference.len() != 16 || !reference.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad("bad_ref", "Unknown recovery."));
    }
    let r: Approved = read(body, SMALL).await?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(
            &tx,
            &s,
            &r.signed,
            "POST",
            &format!("/v1/recovery/alerts/{reference}/cancel"),
        )
        .await?;
    let n = tx
        .execute(
            "UPDATE recovery_requests SET status = 'cancelled', closed_at = $3 WHERE ref = $1 AND account = $2 AND status IN ('collecting', 'waiting')",
            &[&reference, &s.account.as_bytes(), &core.now()],
        )
        .await?;
    if n != 1 {
        return Err(Error::not_found(
            "unknown_ref",
            "No open recovery with that reference.",
        ));
    }
    ledger::append(
        &tx,
        core.now(),
        &s.account,
        "recovery.cancelled",
        &serde_json::json!({ "ref": reference }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "cancelled": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits() {
        let base = 72 * ms::HOUR;
        assert_eq!(
            delay(&["card"], base, false),
            None,
            "one proof is never enough"
        );
        assert_eq!(
            delay(&["card", "card"], base, false),
            None,
            "two of the same kind don't count twice"
        );
        assert_eq!(delay(&["card", "witness"], base, false), Some(base));
        assert_eq!(
            delay(&["card", "key"], base, false),
            Some(base * 7 / 3),
            "no people involved: longer"
        );
        assert_eq!(
            delay(&["card", "witness"], base, true),
            Some(2 * base),
            "a recent duress signal doubles it"
        );
    }
}
