//! The core unit: identity + vault + ledger + recovery, one database (SERVER.md §1).
//!
//! Core verifies every holder proof itself: sign-ins (it issues the session), step-ups (it
//! consumes the nonce in the same transaction as the action), enrolment evidence (H1),
//! duress (M2). It writes the ledger in the same transaction as the action (M3), and
//! "logged before release" is one commit. Front only carries requests; nothing here takes
//! front's word for anything the holder could have signed.

pub mod auth;
pub mod checkin;
pub mod devices;
pub mod ledger;
pub mod objects;
pub mod recovery;

use std::sync::Arc;

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post, put};
use deadpool_postgres::Transaction;
use serde::Serialize;

use crate::api::headers;
use crate::crypto::{self, label};
use crate::db::{Db, Migration};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::limits::Sketch;
use crate::net::{CLIENT_NET, UnitClient};
use crate::policy::SignedPolicy;
use crate::proofs::{self, Checked, Device, DeviceCert, Signed};
use crate::retention::{Rule, TableRule};
use crate::unit::{Clock, ms};
use crate::wire::{B64, Id};

/// Core's migrations, from empty.
pub const MIGRATIONS: &[Migration] = &[(
    1,
    "init",
    include_str!("../../migrations/core/0001_init.sql"),
)];

/// HSM keys core needs before it starts.
pub const HSM_KEYS: &[KeyRef] = &[
    KeyRef::CoreStatement,
    KeyRef::Ledger,
    KeyRef::CardTag,
    KeyRef::Seal,
];

/// Session lifetimes.
pub const SESSION_IDLE_MS: i64 = 15 * ms::MINUTE;
/// Absolute.
pub const SESSION_MAX_MS: i64 = 8 * ms::HOUR;
/// Step-up nonces in a session's pool.
pub const NONCE_POOL: i64 = 8;
/// A pool nonce lives this long.
pub const NONCE_MS: i64 = 15 * ms::MINUTE;

/// Retention for every core table (SERVER.md §5). `$1` is now (ms).
pub const RETENTION: &[TableRule] = &[
    TableRule {
        table: "accounts",
        rule: Rule::Kept("public keys stay for old proofs; closed accounts keep their row"),
    },
    TableRule {
        table: "devices",
        rule: Rule::Kept("revoked devices stay with the account, for old proofs"),
    },
    TableRule {
        table: "sessions",
        rule: Rule::Delete("expires_at < $1 - 86400000 OR revoked_at < $1 - 86400000"),
    },
    TableRule {
        table: "nonces",
        rule: Rule::Delete("expires_at < $1"),
    },
    TableRule {
        table: "objects",
        rule: Rule::Kept("until the holder or Check-in deletes it"),
    },
    TableRule {
        table: "object_tombstones",
        rule: Rule::Delete("deleted_at < $1 - 2592000000"),
    },
    TableRule {
        table: "download_tickets",
        rule: Rule::Delete("expires_at < $1"),
    },
    TableRule {
        table: "ledger_entries",
        rule: Rule::Kept(
            "append-only; bodies of accounts closed 7 years are redacted by redact_closed()",
        ),
    },
    TableRule {
        table: "tlog_nodes",
        rule: Rule::Kept("the public log itself"),
    },
    TableRule {
        table: "tlog_state",
        rule: Rule::Kept("one row"),
    },
    TableRule {
        table: "tlog_checkpoints",
        rule: Rule::Delete(
            "at < $1 - 3600000 AND size < (SELECT max(size) FROM tlog_checkpoints) AND size NOT IN (SELECT size FROM tlog_cosigs) \
             AND size NOT IN (SELECT max(size) FROM tlog_checkpoints GROUP BY at / 86400000)",
        ),
    },
    TableRule {
        table: "tlog_cosigs",
        rule: Rule::Kept("with their checkpoint (cascade)"),
    },
    TableRule {
        table: "links",
        rule: Rule::Delete("expires_at < $1 - 86400000"),
    },
    TableRule {
        table: "recovery_mode",
        rule: Rule::Kept("until replaced, or the account closes"),
    },
    TableRule {
        table: "recovery_cards",
        rule: Rule::Kept("until replaced, or the account closes"),
    },
    TableRule {
        table: "recovery_witnesses",
        rule: Rule::Kept("until replaced, or the account closes"),
    },
    TableRule {
        table: "recovery_requests",
        rule: Rule::Delete(
            "(closed_at IS NOT NULL AND closed_at < $1 - 2592000000) OR (account IS NULL AND created_at < $1 - 86400000) OR expires_at < $1 - 2592000000",
        ),
    },
    TableRule {
        table: "recovery_evidence",
        rule: Rule::Kept("with its request (cascade)"),
    },
    TableRule {
        table: "used_statements",
        rule: Rule::Delete("expires_at < $1"),
    },
    TableRule {
        table: "duress",
        rule: Rule::Delete("at < $1 - 1209600000"),
    },
];

/// The core unit.
pub struct Core {
    /// Its database.
    pub db: Db,
    /// Its HSM.
    pub hsm: Arc<dyn Hsm>,
    /// The verified policy.
    pub policy: Arc<SignedPolicy>,
    /// The clock.
    pub clock: Clock,
    /// The keys unit.
    pub keys: UnitClient,
    /// Failed sign-ins per account.
    pub signin_per_identity: Sketch,
    /// Failed sign-ins per network.
    pub signin_per_network: Sketch,
    /// Recovery starts per network.
    pub recovery_per_network: Sketch,
    /// Anonymous link and enrolment requests per network.
    pub anon_per_network: Sketch,
}

/// A signed-in session, as core verified it.
#[derive(Clone, Debug)]
pub struct Session {
    /// Hash of its token.
    pub token_hash: Vec<u8>,
    /// Account.
    pub account: Id,
    /// Device.
    pub device: Id,
    /// HTP transcript.
    pub th: Vec<u8>,
    /// Signed in with the duress gesture.
    pub duress: bool,
    /// The account is locked down.
    pub lockdown: bool,
}

impl Core {
    /// A core unit.
    #[must_use]
    pub fn new(
        db: Db,
        hsm: Arc<dyn Hsm>,
        policy: Arc<SignedPolicy>,
        clock: Clock,
        keys: UnitClient,
    ) -> Arc<Self> {
        let l = &policy.policy.limits;
        Arc::new(Self {
            signin_per_identity: Sketch::new(l.signin_failures_per_identity, 5 * ms::MINUTE),
            signin_per_network: Sketch::new(l.signin_failures_per_network, 5 * ms::MINUTE),
            recovery_per_network: Sketch::new(l.recovery_starts_per_network_hour, ms::HOUR),
            anon_per_network: Sketch::new(120, ms::MINUTE),
            db,
            hsm,
            policy,
            clock,
            keys,
        })
    }

    /// Now.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// The client network front reported (availability limits only).
    #[must_use]
    pub fn network(headers: &HeaderMap) -> String {
        headers
            .get(CLIENT_NET)
            .and_then(|v| v.to_str().ok())
            .filter(|s| s.len() <= 64)
            .unwrap_or("unknown")
            .to_string()
    }

    /// The HTP transcript this call came in (front binds sessions to it).
    ///
    /// # Errors
    /// `no_session`.
    pub fn th(headers: &HeaderMap) -> Result<Vec<u8>> {
        let v = headers
            .get(headers::TH)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::bad("no_transcript", "This call needs its HTP session."))?;
        let th = B64::decode(v)?;
        if th.is_empty() || th.len() > 64 {
            return Err(Error::bad("no_transcript", "Bad HTP transcript."));
        }
        Ok(th)
    }

    /// The session behind `Authorization: Session <token>`, bound to this call's transcript.
    ///
    /// # Errors
    /// `no_session` / `session_expired`.
    pub async fn session(&self, headers: &HeaderMap) -> Result<Session> {
        let unauth = || Error::unauth("no_session", "Sign in first.");
        let token = headers
            .get(headers::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Session "))
            .ok_or_else(unauth)?;
        let token = B64::decode(token).map_err(|_| unauth())?;
        let th = Self::th(headers)?;
        let h = token_hash(&token)?;
        let now = self.now();
        let c = self.db.conn().await?;
        let row = c
            .query_opt(
                "SELECT s.account, s.device, s.th, s.duress, a.lockdown_at IS NOT NULL
                   FROM sessions s JOIN accounts a ON a.id = s.account JOIN devices d ON d.id = s.device
                  WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND s.last_used_at > $3
                    AND a.status = 'active' AND d.revoked_at IS NULL",
                &[&h.as_slice(), &now, &(now - SESSION_IDLE_MS)],
            )
            .await?
            .ok_or_else(|| Error::unauth("session_expired", "Your session ended. Sign in again."))?;
        let s_th: Vec<u8> = row.get(2);
        if !crypto::ct_eq(&s_th, &th) {
            // a token replayed in another HTP session (or by a front that stole it) is refused
            return Err(unauth());
        }
        c.execute(
            "UPDATE sessions SET last_used_at = $2 WHERE token_hash = $1",
            &[&h.as_slice(), &now],
        )
        .await?;
        Ok(Session {
            token_hash: h.to_vec(),
            account: Id::from_slice(&row.get::<_, Vec<u8>>(0))?,
            device: Id::from_slice(&row.get::<_, Vec<u8>>(1))?,
            th: s_th,
            duress: row.get(3),
            lockdown: row.get(4),
        })
    }

    /// Load an active device's certificate and keys.
    ///
    /// # Errors
    /// `bad_proof` (an unknown, removed or foreign device all look the same).
    pub async fn device(
        &self,
        c: &impl deadpool_postgres::GenericClient,
        account: &Id,
        device: &Id,
    ) -> Result<(DeviceCert, Device)> {
        let row = c
            .query_opt(
                "SELECT d.cert FROM devices d JOIN accounts a ON a.id = d.account
                  WHERE d.id = $1 AND d.account = $2 AND d.revoked_at IS NULL AND a.status = 'active'",
                &[&device.as_bytes(), &account.as_bytes()],
            )
            .await?
            .ok_or_else(Error::bad_proof)?;
        let cert: DeviceCert = serde_json::from_value(row.get(0))
            .map_err(|e| Error::internal(format!("stored cert: {e}")))?;
        let d = cert.verify(Some(account))?;
        if d.id != *device {
            return Err(Error::internal("stored cert doesn't match its device id"));
        }
        Ok((cert, d))
    }

    /// Check a step-up for `method path` from this session's device, and consume its nonce in
    /// `tx` (so a proof is good for exactly one committed action).
    ///
    /// # Errors
    /// Any proof refusal; `step_up_used` for a spent or unknown nonce.
    pub async fn step_up(
        &self,
        tx: &Transaction<'_>,
        s: &Session,
        signed: &Signed,
        method: &str,
        path: &str,
    ) -> Result<(Checked, DeviceCert)> {
        if signed.proof.device != s.device {
            return Err(Error::bad_proof());
        }
        let (cert, d) = self.device(tx, &s.account, &s.device).await?;
        let e = proofs::Expect {
            method,
            path,
            th: Some(&s.th),
            now: self.now(),
            p256_only_until: self.policy.policy.device_policy.p256_only_until,
        };
        let checked = proofs::check_step_up(&signed.proof, &signed.body, &d, &e)?;
        let n = tx
            .execute(
                "DELETE FROM nonces WHERE nonce = $1 AND kind = 'step-up' AND session = $2 AND expires_at >= $3",
                &[&checked.nonce, &s.token_hash, &self.now()],
            )
            .await?;
        if n != 1 {
            return Err(Error::forbidden(
                "step_up_used",
                "That approval was already used, or has expired. Try again.",
            ));
        }
        Ok((checked, cert))
    }

    /// Top a session's nonce pool up to [`NONCE_POOL`]; returns the unused nonces.
    ///
    /// # Errors
    /// Database failure.
    pub async fn nonces(
        &self,
        c: &impl deadpool_postgres::GenericClient,
        token_hash: &[u8],
        device: &Id,
    ) -> Result<Vec<B64>> {
        let now = self.now();
        let have = c
            .query("SELECT nonce FROM nonces WHERE session = $1 AND kind = 'step-up' AND expires_at >= $2", &[&token_hash, &now])
            .await?;
        let mut out: Vec<B64> = have.iter().map(|r| B64(r.get(0))).collect();
        for _ in out.len()..usize::try_from(NONCE_POOL).unwrap_or(8) {
            let n = crypto::random::<32>()?;
            c.execute(
                "INSERT INTO nonces (nonce, kind, device, session, expires_at) VALUES ($1, 'step-up', $2, $3, $4)",
                &[&n.as_slice(), &device.as_bytes(), &token_hash, &(now + NONCE_MS)],
            )
            .await?;
            out.push(B64(n.to_vec()));
        }
        Ok(out)
    }

    /// A statement from core (signed by core's HSM statement key).
    ///
    /// # Errors
    /// HSM failure.
    pub fn statement<T: Serialize>(&self, kind: &str, facts: &T) -> Result<B64> {
        crate::statement::sign(
            self.hsm.as_ref(),
            KeyRef::CoreStatement,
            kind,
            self.now(),
            facts,
        )
    }

    /// Refuse a sensitive change while the account is locked down (it looks temporary).
    ///
    /// # Errors
    /// `busy`.
    pub fn not_locked(s: &Session) -> Result<()> {
        if s.lockdown || s.duress {
            return Err(Error::busy());
        }
        Ok(())
    }

    /// Mark a single-use statement from another unit as used.
    ///
    /// # Errors
    /// `already_used`.
    pub async fn use_statement(&self, tx: &Transaction<'_>, statement: &[u8]) -> Result<()> {
        let h = crypto::sha3_512(statement);
        let n = tx
            .execute(
                "INSERT INTO used_statements (hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&h.as_slice(), &(self.now() + 2 * crate::statement::MAX_AGE_MS)],
            )
            .await?;
        if n != 1 {
            return Err(Error::conflict("already_used", "That was already used."));
        }
        Ok(())
    }

    /// Redact ledger bodies of accounts closed more than 7 years ago (the hashes stay).
    ///
    /// # Errors
    /// Database failure.
    pub async fn redact_closed(&self) -> Result<u64> {
        let c = self.db.conn().await?;
        Ok(c.execute(
            "UPDATE ledger_entries e SET body = NULL FROM accounts a
              WHERE e.account = a.id AND a.status = 'closed' AND a.closed_at < $1 AND e.body IS NOT NULL",
            &[&(self.now() - 7 * 365 * ms::DAY)],
        )
        .await?)
    }

    /// Core's router.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            // auth
            .route("/v1/auth/register", post(auth::register))
            .route("/v1/auth/challenge", post(auth::challenge))
            .route("/v1/auth/login", post(auth::login))
            .route("/v1/auth/logout", post(auth::logout))
            .route("/v1/auth/nonces", post(auth::nonces))
            .route("/v1/me", get(auth::me).delete(auth::close))
            .route("/v1/sync", post(objects::sync))
            .route("/v1/duress/clear", post(auth::clear_duress))
            .route("/v1/keys-kem", get(objects::keys_kem))
            // devices
            .route("/v1/links", post(devices::link_start))
            .route("/v1/links/{code}", get(devices::link_get))
            .route("/v1/links/{code}/approve", post(devices::link_approve))
            .route("/v1/links/{code}/result", get(devices::link_result))
            .route("/v1/devices", post(devices::enrol))
            .route("/v1/devices/{id}", delete(devices::remove))
            // documents
            .route("/v1/objects", post(objects::upload))
            .route(
                "/v1/objects/{id}",
                patch(objects::update).delete(objects::remove),
            )
            .route("/v1/objects/{id}/open", post(objects::open))
            .route("/v1/objects/{id}/chunks/{n}", get(objects::chunk))
            // ledger and public log
            .route("/v1/ledger/events", get(objects::ledger_events))
            .route("/v1/ledger/inclusion", get(objects::ledger_inclusion))
            .route("/tlog/checkpoint", get(objects::tlog_checkpoint))
            .route("/tlog/consistency", get(objects::tlog_consistency))
            .route("/tlog/cosign", post(objects::tlog_cosign))
            // recovery
            .route("/v1/recovery/mode", put(recovery::set_mode))
            .route(
                "/v1/recovery/card",
                put(recovery::set_card).delete(recovery::remove_card),
            )
            .route(
                "/v1/recovery/witnesses",
                put(recovery::set_witnesses).delete(recovery::remove_witnesses),
            )
            .route("/v1/recovery/requests", post(recovery::start))
            .route("/v1/recovery/requests/{id}", get(recovery::status))
            .route("/v1/recovery/requests/{id}/card", post(recovery::add_card))
            .route(
                "/v1/recovery/requests/{id}/anchor",
                post(recovery::add_anchor),
            )
            .route("/v1/recovery/requests/{id}/key", post(recovery::add_key))
            .route(
                "/v1/recovery/help/{code}",
                get(recovery::help_get).post(recovery::help),
            )
            .route("/v1/recovery/alerts", get(recovery::alerts))
            .route(
                "/v1/recovery/alerts/{reference}/cancel",
                post(recovery::cancel),
            )
            // Check-in
            .route("/v1/checkin", get(checkin::status))
            .route("/v1/checkin/arm", post(checkin::arm))
            .route("/v1/checkin/check", post(checkin::check))
            .route("/v1/checkin/disarm", post(checkin::disarm))
            // live checks for anon (no account goes there)
            .route("/v1/live/attest", post(auth::live_attest))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self.clone())
    }
}

/// `H(session-token, token)`.
///
/// # Errors
/// Never in practice.
pub fn token_hash(token: &[u8]) -> Result<[u8; 64]> {
    crypto::hash(label::SESSION_TOKEN, &[token])
}

/// Parse a path id.
///
/// # Errors
/// `bad_id`.
pub fn path_id(s: &str) -> Result<Id> {
    Id::parse(s)
}

/// A handler's answer.
pub type Reply = Result<axum::response::Response>;

/// JSON 200.
pub fn ok<T: Serialize>(v: &T) -> Reply {
    Ok(crate::net::json(axum::http::StatusCode::OK, v))
}

/// JSON 201.
pub fn created<T: Serialize>(v: &T) -> Reply {
    Ok(crate::net::json(axum::http::StatusCode::CREATED, v))
}

/// Read and parse a body.
///
/// # Errors
/// Too large; malformed.
pub async fn read<T: serde::de::DeserializeOwned>(body: axum::body::Body, max: usize) -> Result<T> {
    let b = crate::net::body_bytes(body, max).await?;
    crate::wire::parse(&b)
}

/// Small JSON bodies.
pub const SMALL: usize = 64 << 10;
/// Bodies that carry a sealed envelope (links, witnesses).
pub const ENVELOPE: usize = 256 << 10;
