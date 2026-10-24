//! Adding and removing devices (H1).
//!
//! A device joins an existing account only with **evidence core checks itself, consumed in
//! the same transaction that inserts the device**: a link that one of the account's devices
//! approved with a live check for exactly this device key, or a recovery that was released
//! (proofs in, wait over, no veto) for exactly this device key. A copied account seed plus
//! a compromised front gets nowhere: there is no route by which front marks a link approved
//! or a recovery released.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use super::auth::{Approved, added, insert_device};
use super::ledger::{self, Vouch};
use super::{Core, ENVELOPE, Reply, SMALL, ok, path_id, read};
use crate::api::app;
use crate::crypto::{self, KemPublic, MlDsaPublic, label};
use crate::error::{Error, Result};
use crate::proofs::{self, Enrolment};
use crate::unit::ms;
use crate::wire::{self, B64, Id};

/// A link lives this long.
pub const LINK_TTL_MS: i64 = 10 * ms::MINUTE;
/// Open links in all (anonymous route).
pub const MAX_OPEN_LINKS: i64 = 10_000;
/// Code length (60 bits).
pub const CODE_LEN: usize = 12;

/// The 12-character code that commits to a new device's keys (both screens recompute it).
///
/// # Errors
/// Never in practice.
pub fn link_code(device_vk: &[u8], kem_pk: &[u8]) -> Result<String> {
    let h = crypto::hash(label::CODE, &[b"link", device_vk, kem_pk])?;
    Ok(wire::base32(&h, CODE_LEN))
}

/// `POST /v1/links`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkStart {
    /// The new device's ML-DSA-87 key (the only key that can join with this link).
    pub device_vk: B64,
    /// A hybrid KEM key the account seed will be sealed to.
    pub kem_pk: B64,
    /// What it calls itself.
    #[serde(default)]
    pub platform: String,
}

/// A new device asks to join (anonymous: it has nothing to sign in with yet).
pub async fn link_start(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let r: LinkStart = read(body, SMALL).await?;
    MlDsaPublic::from_bytes(&r.device_vk)?;
    KemPublic::from_bytes(&r.kem_pk)?;
    let now = core.now();
    if !core.anon_per_network.take(&Core::network(&headers), now) {
        return Err(Error::too_many(
            "rate_limited",
            "Too many requests from this network.",
        ));
    }
    let code = link_code(&r.device_vk, &r.kem_pk)?;
    let c = core.db.conn().await?;
    let open: i64 = c
        .query_one("SELECT count(*) FROM links WHERE expires_at > $1", &[&now])
        .await?
        .get(0);
    if open >= MAX_OPEN_LINKS {
        return Err(Error::busy());
    }
    let platform: String = r
        .platform
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let n = c
        .execute(
            "INSERT INTO links (code, device_vk, kem_pk, platform, status, created_at, expires_at) VALUES ($1, $2, $3, $4, 'waiting', $5, $6) ON CONFLICT DO NOTHING",
            &[&code, &r.device_vk.0, &r.kem_pk.0, &platform, &now, &(now + LINK_TTL_MS)],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict(
            "code_in_use",
            "Start again on the new device.",
        ));
    }
    super::created(&serde_json::json!({ "code": code, "expires_at": now + LINK_TTL_MS }))
}

fn code_param(code: &str) -> Result<String> {
    if !wire::is_code(code, CODE_LEN) {
        return Err(Error::bad("bad_code", "That isn't a device code."));
    }
    Ok(code.to_string())
}

/// A signed-in device looks up a code (to recompute it from the keys and show the check).
pub async fn link_get(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Reply {
    core.session(&headers).await?;
    let code = code_param(&code)?;
    let c = core.db.conn().await?;
    let r = c
        .query_opt("SELECT device_vk, kem_pk, platform, status, expires_at FROM links WHERE code = $1 AND expires_at > $2", &[&code, &core.now()])
        .await?
        .ok_or_else(|| Error::not_found("unknown_code", "No device is waiting with that code. Codes last 10 minutes."))?;
    let status: String = r.get(3);
    if status != "waiting" {
        return Err(Error::conflict(
            "already_used",
            "That code was already used.",
        ));
    }
    ok(
        &serde_json::json!({ "code": code, "device_vk": B64(r.get(0)), "kem_pk": B64(r.get(1)), "platform": r.get::<_, String>(2), "expires_at": r.get::<_, i64>(4) }),
    )
}

/// `POST /v1/links/:code/approve`: the signed body names the device key it approves.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkApproval {
    /// The device key being approved.
    pub device_vk: B64,
    /// The account seed sealed (on the approving phone) to the new device's KEM key.
    pub envelope: B64,
}

/// An existing device approves a waiting one, with a live check.
pub async fn link_approve(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(code): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let code = code_param(&code)?;
    let r: Approved = read(body, ENVELOPE).await?;
    let a: LinkApproval = wire::parse(&r.signed.body)?;
    if a.envelope.is_empty() || a.envelope.len() > 64 << 10 {
        return Err(Error::bad(
            "bad_envelope",
            "The sealed seed is missing or too large.",
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
            &format!("/v1/links/{code}/approve"),
        )
        .await?;
    let l = tx
        .query_opt(
            "SELECT device_vk, status FROM links WHERE code = $1 AND expires_at > $2 FOR UPDATE",
            &[&code, &core.now()],
        )
        .await?
        .ok_or_else(|| {
            Error::not_found(
                "unknown_code",
                "That code expired. Start again on the new device.",
            )
        })?;
    if l.get::<_, String>(1) != "waiting" {
        return Err(Error::conflict(
            "already_used",
            "That code was already used.",
        ));
    }
    let vk: Vec<u8> = l.get(0);
    if !crypto::ct_eq(&vk, &a.device_vk) {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different device.",
        ));
    }
    let now = core.now();
    tx.execute(
        "UPDATE links SET status = 'approved', account = $2, envelope = $3, expires_at = $4 WHERE code = $1",
        &[&code, &s.account.as_bytes(), &a.envelope.0, &(now + LINK_TTL_MS)],
    )
    .await?;
    let device = Id(MlDsaPublic::from_bytes(&vk)?.id());
    ledger::append(
        &tx,
        now,
        &s.account,
        "device.link_approved",
        &serde_json::json!({ "device": device }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "approved": true }))
}

/// The new device polls (the code is the capability; the envelope is sealed to its own key).
pub async fn link_result(State(core): State<Arc<Core>>, Path(code): Path<String>) -> Reply {
    let code = code_param(&code)?;
    let c = core.db.conn().await?;
    let Some(r) = c
        .query_opt(
            "SELECT status, account, envelope, expires_at FROM links WHERE code = $1",
            &[&code],
        )
        .await?
    else {
        return ok(&serde_json::json!({ "status": "expired" }));
    };
    let (status, exp): (String, i64) = (r.get(0), r.get(3));
    if exp < core.now() {
        return ok(&serde_json::json!({ "status": "expired" }));
    }
    match status.as_str() {
        "approved" | "used" => ok(&serde_json::json!({
            "status": status,
            "account": Id::from_slice(&r.get::<_, Vec<u8>>(1))?,
            "envelope": B64(r.get(2)),
        })),
        _ => ok(&serde_json::json!({ "status": "waiting", "expires_at": exp })),
    }
}

/// How a device proves it may join.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(tag = "via", rename_all = "lowercase", deny_unknown_fields)]
pub enum Evidence {
    /// An approved link.
    Link {
        /// Its code.
        code: String,
    },
    /// A released recovery.
    Recovery {
        /// The request id (a 128-bit capability, base64url).
        request: B64,
    },
}

/// `POST /v1/devices`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enrol {
    /// The device and its certificate.
    pub enrolment: Enrolment,
    /// What lets it join.
    pub evidence: Evidence,
}

/// A device joins an account: certificate under the account key, possession, the chip,
/// attestation — and the evidence, consumed here (H1).
pub async fn enrol(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let r: Enrol = read(body, SMALL).await?;
    let th = Core::th(&headers)?;
    if !core
        .anon_per_network
        .take(&Core::network(&headers), core.now())
    {
        return Err(Error::too_many(
            "rate_limited",
            "Too many requests from this network.",
        ));
    }
    let (d, proven) = proofs::check_enrolment(
        &r.enrolment,
        None,
        &th,
        core.policy.policy.device_policy.attestation_required,
    )?;
    let now = core.now();
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let active = tx
        .query_opt("SELECT lockdown_at IS NOT NULL FROM accounts WHERE id = $1 AND status = 'active' FOR UPDATE", &[&d.account.as_bytes()])
        .await?
        .ok_or_else(not_approved)?;
    if active.get::<_, bool>(0) {
        return Err(Error::busy());
    }
    let via = match &r.evidence {
        Evidence::Link { code } => {
            let code = code_param(code)?;
            let n = tx
                .execute(
                    "UPDATE links SET status = 'used', used_at = $4 WHERE code = $1 AND status = 'approved' AND account = $2 AND device_vk = $3 AND expires_at > $4",
                    &[&code, &d.account.as_bytes(), &r.enrolment.cert.device_vk.0, &now],
                )
                .await?;
            if n != 1 {
                return Err(not_approved());
            }
            "link"
        }
        Evidence::Recovery { request } => {
            super::recovery::consume_release(
                &tx,
                &core,
                request,
                &d.account,
                &r.enrolment.cert.device_vk,
                now,
            )
            .await?;
            "recovery"
        }
    };
    insert_device(&tx, &core, &r.enrolment, &d, proven.as_str(), via).await?;
    added(
        &tx,
        now,
        &d.account,
        &d.id,
        via,
        proven.as_str(),
        &proofs::proof_hash(&r.enrolment.device_pop)?,
    )
    .await?;
    if via == "recovery" {
        ledger::append(
            &tx,
            now,
            &d.account,
            "recovery.completed",
            &serde_json::json!({ "device": d.id }),
            Vouch::Holder(&proofs::proof_hash(&r.enrolment.device_pop)?),
        )
        .await?;
    }
    tx.commit().await?;
    super::created(&serde_json::json!({ "account": d.account, "device": d.id, "via": via }))
}

fn not_approved() -> Error {
    Error::forbidden(
        "not_approved",
        "None of your devices approved this one, and no recovery released it. Approve it from a device you already use.",
    )
}

/// `DELETE /v1/devices/:id`: remove another device, with a live check on this one.
pub async fn remove(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let target = path_id(&id)?;
    let r: Approved = read(body, SMALL).await?;
    let _: app::Empty = wire::parse(&r.signed.body)?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(
            &tx,
            &s,
            &r.signed,
            "DELETE",
            &format!("/v1/devices/{target}"),
        )
        .await?;
    if target == s.device {
        return Err(Error::bad(
            "current_device",
            "You can't remove the device you're using. Remove it from another device.",
        ));
    }
    let now = core.now();
    let n = tx
        .execute(
            "UPDATE devices SET revoked_at = $3 WHERE id = $1 AND account = $2 AND revoked_at IS NULL",
            &[&target.as_bytes(), &s.account.as_bytes(), &now],
        )
        .await?;
    if n != 1 {
        return Err(Error::not_found(
            "unknown_device",
            "No such device on your HumID.",
        ));
    }
    tx.execute(
        "UPDATE sessions SET revoked_at = $2 WHERE device = $1 AND revoked_at IS NULL",
        &[&target.as_bytes(), &now],
    )
    .await?;
    tx.execute(
        "UPDATE accounts SET devices_rev = devices_rev + 1 WHERE id = $1",
        &[&s.account.as_bytes()],
    )
    .await?;
    ledger::append(
        &tx,
        now,
        &s.account,
        "device.removed",
        &serde_json::json!({ "device": target }),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "removed": target }))
}
