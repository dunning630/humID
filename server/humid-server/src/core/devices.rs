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
use crate::crypto::{self, JOIN_CODE_LEN, JoinRequest, MlDsaPublic};
use crate::error::{Error, Result};
use crate::proofs::{self, Enrolment};
use crate::unit::ms;
use crate::wire::{self, B64, Id};

/// A link lives this long.
pub const LINK_TTL_MS: i64 = 10 * ms::MINUTE;
/// Open links in all (anonymous route): a backstop only.
pub const MAX_OPEN_LINKS: i64 = 10_000;
/// Open links per network bucket (an IPv4 /24 or an IPv6 /48), so a handful of networks can't
/// fill the global cap and stop device linking for everyone (M-5).
pub const MAX_OPEN_LINKS_PER_BUCKET: i64 = 64;

/// The coarse bucket a network key falls in: IPv4 /24, IPv6 /48 (anything else as is).
#[must_use]
pub fn bucket_of(net: &str) -> String {
    if let Some(v4) = net.strip_prefix("v4:")
        && let Ok(a) = v4.parse::<std::net::Ipv4Addr>()
    {
        let o = a.octets();
        return format!("v4:{}.{}.{}.0/24", o[0], o[1], o[2]);
    }
    if let Some(v6) = net.strip_prefix("v6:") {
        let groups: Vec<&str> = v6.split(':').take(3).collect();
        return format!("v6:{}::/48", groups.join(":"));
    }
    net.to_string()
}

/// `POST /v1/links`: a new device sends the join request humid-core made (`begin_join`).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkStart {
    /// humid-core's self-signed join request (type `0x0108`).
    pub request: B64,
    /// What it calls itself.
    #[serde(default)]
    pub platform: String,
}

/// A new device asks to join (anonymous: it has nothing to sign in with yet). The request is
/// signed by the new device's key and names the account; its 100-bit code is what both
/// screens show (CORE.md §5.3).
pub async fn link_start(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let r: LinkStart = read(body, SMALL).await?;
    let req = JoinRequest::parse(&r.request)?;
    let now = core.now();
    let net = core.network(&headers)?;
    if !core.anon_per_network.take(&net, now) {
        return Err(Error::too_many(
            "rate_limited",
            "Too many requests from this network.",
        ));
    }
    let bucket = bucket_of(&net);
    let c = core.db.conn().await?;
    let row = c
        .query_one(
            "SELECT count(*) FILTER (WHERE bucket = $2), count(*) FROM links WHERE expires_at > $1",
            &[&now, &bucket],
        )
        .await?;
    let (in_bucket, open): (i64, i64) = (row.get(0), row.get(1));
    if in_bucket >= MAX_OPEN_LINKS_PER_BUCKET {
        return Err(Error::too_many(
            "rate_limited",
            "Too many devices are waiting to join from this network. Try again in a few minutes.",
        ));
    }
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
            "INSERT INTO links (code, device_vk, kem_pk, platform, status, created_at, expires_at, request, binding, wants, bucket)
             VALUES ($1, $2, $3, $4, 'waiting', $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
            &[&req.code, &req.device_vk, &req.join_kem.to_bytes(), &platform, &now, &(now + LINK_TTL_MS),
              &r.request.0, &req.binding.as_slice(), &req.account.as_slice(), &bucket],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict(
            "code_in_use",
            "Start again on the new device.",
        ));
    }
    super::created(&serde_json::json!({ "code": req.code, "expires_at": now + LINK_TTL_MS }))
}

fn code_param(code: &str) -> Result<String> {
    // the person may type it grouped and in any case; humid-core's alphabet, 20 characters
    let c: String = code
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !wire::is_code(&c, JOIN_CODE_LEN) {
        return Err(Error::bad("bad_code", "That isn't a device code."));
    }
    Ok(c)
}

/// A signed-in device looks up a code: it gets the join request itself, so its own core
/// checks the signature, the account and the code before the person approves.
pub async fn link_get(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Reply {
    let s = core.session(&headers).await?;
    let code = code_param(&code)?;
    let c = core.db.conn().await?;
    let r = c
        .query_opt("SELECT request, platform, status, expires_at, wants FROM links WHERE code = $1 AND expires_at > $2", &[&code, &core.now()])
        .await?
        .ok_or_else(|| Error::not_found("unknown_code", "No device is waiting with that code. Codes last 10 minutes."))?;
    // L-18: a request names the account it joins; another account sees nothing
    if r.get::<_, Option<Vec<u8>>>(4).as_deref() != Some(s.account.as_bytes()) {
        return Err(Error::not_found(
            "unknown_code",
            "No device is waiting with that code. Codes last 10 minutes.",
        ));
    }
    let status: String = r.get(2);
    if status != "waiting" {
        return Err(Error::conflict(
            "already_used",
            "That code was already used.",
        ));
    }
    ok(
        &serde_json::json!({ "code": code, "request": B64(r.get(0)), "platform": r.get::<_, String>(1), "expires_at": r.get::<_, i64>(3) }),
    )
}

/// `POST /v1/links/:code/approve`: the signed body names the request it approves.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkApproval {
    /// The join request's binding, `H("HUMID-PQ2 join-binding", [body])`: what the approving
    /// live check signs (humid-core `live-grant`).
    pub binding: B64,
    /// humid-core's grant: the account seed sealed to the request's join key.
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
            "SELECT device_vk, status, binding, wants FROM links WHERE code = $1 AND expires_at > $2 FOR UPDATE",
            &[&code, &core.now()],
        )
        .await?
        .ok_or_else(|| {
            Error::not_found(
                "unknown_code",
                "That code expired. Start again on the new device.",
            )
        })?;
    if l.get::<_, Option<Vec<u8>>>(3).as_deref() != Some(s.account.as_bytes()) {
        // L-18: the new device asked to join another account
        return Err(Error::not_found(
            "unknown_code",
            "That code expired. Start again on the new device.",
        ));
    }
    if l.get::<_, String>(1) != "waiting" {
        return Err(Error::conflict(
            "already_used",
            "That code was already used.",
        ));
    }
    let binding: Vec<u8> = l.get::<_, Option<Vec<u8>>>(2).unwrap_or_default();
    if !crypto::ct_eq(&binding, &a.binding) {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different device.",
        ));
    }
    let vk: Vec<u8> = l.get(0);
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
        .take(&core.network(&headers)?, core.now())
    {
        return Err(Error::too_many(
            "rate_limited",
            "Too many requests from this network.",
        ));
    }
    let d = proofs::check_enrolment(&r.enrolment, None, &th)?;
    let now = core.now();
    // the new device's platform proof, bound to this session and to the device key the
    // certificate (and so the approved join request) names: CORE.md §5.3, "attested model"
    let attested = core.attest.enrolment(&r.enrolment, &d, &th, now)?;
    let proven = attested.proven();
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
    insert_device(&tx, &core, &r.enrolment, &d, &proven, via).await?;
    core.attest.store(&tx, &d.id, &attested, now).await?;
    added(
        &tx,
        now,
        &d.account,
        &d.id,
        via,
        &proven,
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
