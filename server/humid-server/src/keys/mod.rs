//! The keys unit: one sealed key share per document (SERVER.md §3), and Check-in.
//!
//! Every action is checked **here**, whatever core says:
//! * core's HSM-signed statement for the action (core checked the session, logged the event);
//! * the device's certificate, under the account key whose hash is the account id (so not
//!   even a compromised core can invent a device for an account);
//! * the holder's own live step-up for exactly the app route, whose signed body names this
//!   object (and, for an upload, this envelope's and this sealed share's hashes);
//! * that the proof is the one core's statement names, and that it hasn't acted here before.
//!
//! Shares: the phone seals each to this unit's KEM key (H2, upload direction); this unit
//! opens it, wraps it under the HSM share KEK (and an armed account's Check-in fuse key),
//! and forgets it. On release it unwraps inside one call and seals it to the phone's one-time
//! key. The share is never in the clear outside this unit's memory for one call.
//!
//! Check-in fuse keys exist only in this process's memory. A restart erases every armed
//! vault (fail-deadly, as 4.x), and the timer runs on the monotonic clock.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::Deserialize;
use tokio::sync::{Mutex, Notify};

use crate::api::{app, keys as k};
use crate::crypto::{self, KemSecret, Secret32, object_type};
use crate::db::{Db, Migration};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::policy::SignedPolicy;
use crate::proofs::{self, DeviceCert, Signed};
use crate::retention::{Rule, TableRule};
use crate::unit::{Clock, ms};
use crate::wire::{self, B64, Id};

/// The keys unit's migrations.
pub const MIGRATIONS: &[Migration] = &[
    (
        1,
        "init",
        include_str!("../../migrations/keys/0001_init.sql"),
    ),
    (
        2,
        "review95",
        include_str!("../../migrations/keys/0002_review95.sql"),
    ),
];

/// HSM keys it needs.
pub const HSM_KEYS: &[KeyRef] = &[KeyRef::KeysStatement, KeyRef::ShareKek, KeyRef::Seal];

/// Retention (SERVER.md §5).
pub const RETENTION: &[TableRule] = &[
    TableRule {
        table: "shares",
        rule: Rule::Kept("until deleted, account close, or a Check-in erase"),
    },
    TableRule {
        table: "releases",
        rule: Rule::Delete("at < $1 - 3600000"),
    },
    TableRule {
        table: "used_proofs",
        rule: Rule::Delete("expires_at < $1"),
    },
    TableRule {
        table: "checkin",
        rule: Rule::Delete("state = 'erased' AND cleaned AND erased_at < $1 - 604800000"),
    },
    TableRule {
        table: "duress_used",
        rule: Rule::Delete("at < $1 - 28800000"),
    },
    TableRule {
        table: "policy_seen",
        rule: Rule::Kept("one row: the highest policy accepted"),
    },
];

struct Fuse {
    key: Secret32,
    deadline: i64,
    erases_at: i64,
}

/// The keys unit.
pub struct Keys {
    db: Db,
    hsm: Arc<dyn Hsm>,
    policy: Arc<SignedPolicy>,
    clock: Clock,
    kem: KemSecret,
    fuses: Mutex<HashMap<Id, Fuse>>,
    /// Wakes the erase timer when a deadline changes.
    pub wake: Notify,
    /// Tests: refuse duress requests as if keys were down (the queue must retry).
    #[cfg(any(test, feature = "testkit"))]
    pub refuse_duress: std::sync::atomic::AtomicBool,
}

const LOCKED: fn() -> Error = || {
    Error::Locked(
        "checkin_missed",
        "You missed a check-in. Check in to use your vault again.".into(),
    )
};
const ERASED: fn() -> Error =
    || Error::Gone("vault_erased", "Your vault was erased by Check-in.".into());

impl Keys {
    /// A keys unit. Erases any vault that was armed when the last process stopped.
    ///
    /// # Errors
    /// Database failure.
    pub async fn new(
        db: Db,
        hsm: Arc<dyn Hsm>,
        policy: Arc<SignedPolicy>,
        clock: Clock,
        kem: KemSecret,
    ) -> Result<Arc<Self>> {
        let me = Arc::new(Self {
            db,
            hsm,
            policy,
            clock,
            kem,
            fuses: Mutex::new(HashMap::new()),
            wake: Notify::new(),
            #[cfg(any(test, feature = "testkit"))]
            refuse_duress: std::sync::atomic::AtomicBool::new(false),
        });
        let c = me.db.conn().await?;
        let orphans = c
            .query("SELECT account FROM checkin WHERE state = 'armed'", &[])
            .await?;
        drop(c);
        for r in &orphans {
            me.erase(&Id::from_slice(&r.get::<_, Vec<u8>>(0))?).await?;
        }
        if !orphans.is_empty() {
            tracing::warn!(
                count = orphans.len(),
                "keys restarted while Check-in was armed: those vaults were erased"
            );
        }
        Ok(me)
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Rows in one of this unit's tables (tests).
    ///
    /// # Errors
    /// Unknown table; database failure.
    #[cfg(any(test, feature = "testkit"))]
    pub async fn count_rows(&self, table: &str) -> Result<i64> {
        if !RETENTION.iter().any(|r| r.table == table) {
            return Err(Error::bad("bad_table", "unknown table"));
        }
        Ok(self
            .db
            .conn()
            .await?
            .query_one(format!("SELECT count(*) FROM {table}").as_str(), &[])
            .await?
            .get(0))
    }

    /// Its database (tests).
    #[cfg(any(test, feature = "testkit"))]
    #[must_use]
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// The router.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/kem-key", get(kem_key))
            .route("/v1/shares", post(store))
            .route("/v1/shares/{id}/release", post(release))
            .route("/v1/shares/{id}/delete", post(delete_share))
            .route("/v1/accounts/{id}/close", post(close))
            .route("/v1/checkin", post(checkin))
            .route("/v1/checkin/erased", post(erased))
            .route("/v1/checkin/cleaned", post(cleaned))
            .route("/v1/duress", post(duress))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self.clone())
    }

    /// Check core's statement, the device certificate and the holder's step-up for `method
    /// path`, and that core's statement names this very proof. Marks the proof used.
    #[allow(clippy::too_many_arguments)] // one call checks every piece of a holder action together
    async fn holder<F: serde::de::DeserializeOwned>(
        &self,
        statement: &[u8],
        kind: &str,
        cert: &DeviceCert,
        signed: &Signed,
        method: &str,
        path: &str,
        proof_of: impl Fn(&F) -> (&Id, Option<&B64>),
    ) -> Result<(F, proofs::Device, proofs::Checked)> {
        let p = &self.policy.policy;
        let facts: F = crate::statement::verify(&p.core_key()?, statement, kind, self.now())?;
        let (account, proof_hash) = proof_of(&facts);
        let d = cert.verify(Some(account))?;
        let e = proofs::Expect {
            method,
            path,
            th: None,
            now: self.now(),
            p256_only_until: p.device_policy.p256_only_until,
            mode: None,
        };
        let checked = proofs::check_step_up(&signed.proof, &signed.body, &d, &e)?;
        // The proof's own signed mode (CORE.md §8–9): a duress session changes nothing real
        // here, whatever core says (a compromised core can't relay a coerced arm, delete or
        // close). Releases follow the owner's duress decision (SERVER.md §13): for now as
        // ordinary, with an armed vault already erased by the duress sign-in.
        if checked.mode == 1 && kind != "release" {
            return Err(Error::busy());
        }
        if !proof_hash.is_some_and(|h| crypto::ct_eq(h, &checked.proof_hash)) {
            return Err(Error::forbidden(
                "not_vouched",
                "Core's statement names a different approval.",
            ));
        }
        let c = self.db.conn().await?;
        let n = c
            .execute(
                "INSERT INTO used_proofs (proof_hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&checked.proof_hash.as_slice(), &(self.now() + 10 * ms::MINUTE)],
            )
            .await?;
        if n != 1 {
            return Err(Error::forbidden(
                "step_up_used",
                "That approval was already used.",
            ));
        }
        Ok((facts, d, checked))
    }

    fn wrap(&self, account: &Id, object: &Id, share: &Secret32) -> Result<Vec<u8>> {
        self.hsm.wrap(
            KeyRef::ShareKek,
            object_type::SHARE_AT_REST,
            &[account.as_bytes(), object.as_bytes()],
            share.expose(),
        )
    }

    fn fuse_seal(fuse: &Secret32, account: &Id, object: &Id, wrapped: &[u8]) -> Result<Vec<u8>> {
        crypto::seal_at_rest(
            fuse,
            object_type::SHARE_FUSED,
            &[account.as_bytes(), object.as_bytes()],
            wrapped,
        )
    }

    fn fuse_open(fuse: &Secret32, account: &Id, object: &Id, boxed: &[u8]) -> Result<Vec<u8>> {
        Ok(crypto::open_at_rest(
            fuse,
            object_type::SHARE_FUSED,
            &[account.as_bytes(), object.as_bytes()],
            boxed,
        )?
        .to_vec())
    }

    fn unwrap(
        &self,
        account: &Id,
        object: &Id,
        wrapped: &[u8],
        fused: bool,
        fuses: &HashMap<Id, Fuse>,
    ) -> Result<Secret32> {
        let inner = if fused {
            let f = fuses.get(account).ok_or_else(ERASED)?;
            Self::fuse_open(&f.key, account, object, wrapped)?
        } else {
            wrapped.to_vec()
        };
        let pt = self.hsm.unwrap(
            KeyRef::ShareKek,
            object_type::SHARE_AT_REST,
            &[account.as_bytes(), object.as_bytes()],
            &inner,
        )?;
        Secret32::from_slice(&pt).map_err(|_| Error::internal("a stored share isn't 32 bytes"))
    }

    /// Where an account's Check-in stands. Settles a deadline that has passed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn status(&self, account: &Id) -> Result<k::CheckinStatus> {
        let c = self.db.conn().await?;
        let Some(r) = c
            .query_opt(
                "SELECT state, erased_at, window_ms, max_window_ms FROM checkin WHERE account = $1",
                &[&account.as_bytes()],
            )
            .await?
        else {
            return Ok(k::CheckinStatus::off());
        };
        drop(c);
        if r.get::<_, String>(0) == "erased" {
            return Ok(k::CheckinStatus {
                state: "erased".into(),
                erased_at: r.get(1),
                ..k::CheckinStatus::off()
            });
        }
        let now = self.now();
        let due = {
            let f = self.fuses.lock().await;
            match f.get(account) {
                Some(f) if now < f.erases_at => Some((f.deadline, f.erases_at)),
                _ => None,
            }
        };
        match due {
            Some((deadline, erases_at)) => Ok(k::CheckinStatus {
                state: if now < deadline { "armed" } else { "locked" }.into(),
                deadline: Some(deadline),
                erases_at: Some(erases_at),
                erased_at: None,
                window_ms: r.get(2),
                max_window_ms: r.get(3),
            }),
            None => {
                self.erase(account).await?;
                Box::pin(self.status(account)).await
            }
        }
    }

    /// Destroy an account's fuse key (that *is* the erase), then drop its fused shares.
    ///
    /// # Errors
    /// Database failure.
    pub async fn erase(&self, account: &Id) -> Result<()> {
        self.fuses.lock().await.remove(account); // Secret32 wipes on drop
        let mut c = self.db.conn().await?;
        let tx = c.transaction().await?;
        let gone = i64::try_from(
            tx.execute(
                "DELETE FROM shares WHERE account = $1 AND fused",
                &[&account.as_bytes()],
            )
            .await?,
        )
        .unwrap_or(i64::MAX);
        tx.execute(
            "UPDATE checkin SET state = 'erased', erased_at = $2, erased_count = $3, cleaned = false WHERE account = $1 AND state = 'armed'",
            &[&account.as_bytes(), &self.now(), &gone],
        )
        .await?;
        tx.commit().await?;
        tracing::warn!("check-in: an armed vault's keys were destroyed"); // never the account id
        Ok(())
    }

    /// Erase every vault whose grace has run out. Returns the next time to look (ms).
    ///
    /// # Errors
    /// Database failure.
    pub async fn tick(&self) -> Result<Option<i64>> {
        let now = self.now();
        let (due, next): (Vec<Id>, Option<i64>) = {
            let f = self.fuses.lock().await;
            (
                f.iter()
                    .filter(|(_, f)| now >= f.erases_at)
                    .map(|(a, _)| *a)
                    .collect(),
                f.values().map(|f| f.erases_at).filter(|t| *t > now).min(),
            )
        };
        for a in due {
            self.erase(&a).await?;
        }
        Ok(next)
    }

    /// One timer, to the next deadline (not a 1 s tick for life, as 4.x had).
    pub fn spawn_timer(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                let next = me.tick().await.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "check-in tick failed");
                    None
                });
                let wait = next.map_or(60_000, |t| (t - me.now()).clamp(10, 60_000));
                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_millis(u64::try_from(wait).unwrap_or(1000))) => {}
                    () = me.wake.notified() => {}
                }
            }
        })
    }

    /// Re-seal an account's shares: under the fuse when `fused(object)`, plain otherwise.
    async fn reseal(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        account: &Id,
        new_fuse: Option<&Secret32>,
        fused: impl Fn(&Id) -> bool,
        fuses: &HashMap<Id, Fuse>,
    ) -> Result<()> {
        let rows = tx
            .query(
                "SELECT object, wrapped, fused FROM shares WHERE account = $1 FOR UPDATE",
                &[&account.as_bytes()],
            )
            .await?;
        for r in rows {
            let object = Id::from_slice(&r.get::<_, Vec<u8>>(0))?;
            let (wrapped, was): (Vec<u8>, bool) = (r.get(1), r.get(2));
            let inner = if was {
                Self::fuse_open(
                    &fuses.get(account).ok_or_else(ERASED)?.key,
                    account,
                    &object,
                    &wrapped,
                )?
            } else {
                wrapped
            };
            let want = new_fuse.is_some() && fused(&object);
            let out = match (want, new_fuse) {
                (true, Some(fk)) => Self::fuse_seal(fk, account, &object, &inner)?,
                _ => inner,
            };
            tx.execute(
                "UPDATE shares SET wrapped = $2, fused = $3 WHERE object = $1",
                &[&object.as_bytes(), &out, &want],
            )
            .await?;
        }
        Ok(())
    }
}

type St = State<Arc<Keys>>;
type Reply = Result<axum::response::Response>;

fn ok<T: serde::Serialize>(v: &T) -> Reply {
    Ok(crate::net::json(axum::http::StatusCode::OK, v))
}

async fn read<T: serde::de::DeserializeOwned>(body: Body) -> Result<T> {
    let b = crate::net::body_bytes(body, 256 << 10).await?;
    wire::parse(&b)
}

async fn kem_key(State(keys): St) -> Reply {
    let pk = keys.kem.public().to_bytes();
    let st = crate::statement::sign(
        keys.hsm.as_ref(),
        KeyRef::KeysStatement,
        "kem-key",
        keys.now(),
        &serde_json::json!({ "kem_pk": B64(pk.clone()) }),
    )?;
    ok(&k::KemKey {
        kem_pk: B64(pk),
        statement: st,
    })
}

/// Store a share the phone sealed to this unit (H2).
async fn store(State(keys): St, body: Body) -> Reply {
    let r: k::Store = read(body).await?;
    let (f, _d, _checked): (k::UploadFacts, _, _) = keys
        .holder(
            &r.statement,
            "upload",
            &r.cert,
            &r.signed,
            "POST",
            "/v1/objects",
            |f: &k::UploadFacts| (&f.account, Some(&f.proof_hash)),
        )
        .await?;
    let u: app::Upload = wire::parse(&r.signed.body)?;
    if u.object != f.object
        || !crypto::ct_eq(&u.envelope_hash, &f.envelope_hash)
        || !crypto::ct_eq(&u.manifest_hash, &f.manifest_hash)
        || !crypto::ct_eq(&u.sealed_share_hash, &crypto::sha3_512(&r.sealed_share))
    {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "The live check approved a different document or key.",
        ));
    }
    // bound to the manifest the holder signed (CORE.md §6.3): a share moved onto another
    // document or version doesn't open
    let share = crypto::open_upload_share(
        &keys.kem,
        f.account.as_bytes(),
        f.object.as_bytes(),
        &u.manifest_hash,
        &r.sealed_share,
    )?;
    let st = keys.status(&f.account).await?;
    if st.state == "locked" {
        return Err(LOCKED());
    }
    let wrapped = keys.wrap(&f.account, &f.object, &share)?;
    // L-7: the fuse lock is held from the state check to the insert, so an upload racing an
    // arm is either resealed by the arm or fused here, never left out of the erase
    let fuses = keys.fuses.lock().await;
    let (stored, fused) = match fuses.get(&f.account) {
        Some(fz) => (
            Keys::fuse_seal(&fz.key, &f.account, &f.object, &wrapped)?,
            true,
        ), // sealed while armed: in the fuse from the start
        None => (wrapped, false),
    };
    let c = keys.db.conn().await?;
    let n = c
        .execute(
            "INSERT INTO shares (object, account, wrapped, fused, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            &[&f.object.as_bytes(), &f.account.as_bytes(), &stored, &fused, &keys.now()],
        )
        .await?;
    drop(fuses);
    if n != 1 {
        return Err(Error::conflict(
            "share_exists",
            "This document already has a key.",
        ));
    }
    ok(&serde_json::json!({ "stored": true }))
}

/// Release a share: sealed to the phone's one-time key from the body its device key signed.
async fn release(State(keys): St, Path(id): Path<String>, body: Body) -> Reply {
    let object = Id::parse(&id)?;
    let r: k::HolderAction = read(body).await?;
    let path = format!("/v1/objects/{object}/open");
    let (f, _d, _): (k::ReleaseFacts, _, _) = keys
        .holder(
            &r.statement,
            "release",
            &r.cert,
            &r.signed,
            "POST",
            &path,
            |f: &k::ReleaseFacts| (&f.account, Some(&f.proof_hash)),
        )
        .await?;
    let o: app::Open = wire::parse(&r.signed.body)?;
    if o.object != object || f.object != object {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different document.",
        ));
    }
    // the share request the holder's device key signed: its one-time key and its binding
    let req = crypto::ShareRequest::parse(&o.share_request)?;
    if req.account != f.account.0 || req.doc != object.0 {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That share request is for a different document.",
        ));
    }
    match keys.status(&f.account).await?.state.as_str() {
        "locked" => return Err(LOCKED()),
        "erased" => {
            let c = keys.db.conn().await?;
            if c.query_opt(
                "SELECT 1 FROM shares WHERE object = $1",
                &[&object.as_bytes()],
            )
            .await?
            .is_none()
            {
                return Err(ERASED());
            }
        }
        _ => {}
    }
    let now = keys.now();
    let mut c = keys.db.conn().await?;
    let tx = c.transaction().await?;
    // L-6: releases of one account one at a time, so the hourly cap holds under concurrency
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 7))",
        &[&f.account.as_bytes()],
    )
    .await?;
    let n: i64 = tx
        .query_one(
            "SELECT count(*) FROM releases WHERE account = $1 AND at > $2",
            &[&f.account.as_bytes(), &(now - ms::HOUR)],
        )
        .await?
        .get(0);
    if n >= i64::from(keys.policy.policy.limits.share_releases_per_hour) {
        return Err(Error::too_many(
            "share_rate_limited",
            "You've opened a lot of documents in the last hour. Wait a while and try again.",
        ));
    }
    let row = tx
        .query_opt(
            "SELECT wrapped, fused FROM shares WHERE object = $1 AND account = $2 FOR UPDATE",
            &[&object.as_bytes(), &f.account.as_bytes()],
        )
        .await?
        .ok_or_else(|| Error::not_found("no_share", "This document has no key here."))?;
    let share = {
        let fuses = keys.fuses.lock().await;
        keys.unwrap(
            &f.account,
            &object,
            &row.get::<_, Vec<u8>>(0),
            row.get(1),
            &fuses,
        )?
    };
    tx.execute(
        "INSERT INTO releases (account, at) VALUES ($1, $2)",
        &[&f.account.as_bytes(), &now],
    )
    .await?;
    tx.execute(
        "UPDATE shares SET released = released + 1, last_released_at = $2 WHERE object = $1",
        &[&object.as_bytes(), &now],
    )
    .await?;
    let sealed = crypto::seal_release_share(
        &req.one_time,
        f.account.as_bytes(),
        object.as_bytes(),
        &req.binding,
        &share,
    )?;
    tx.commit().await?;
    ok(&k::Released {
        sealed: B64(sealed),
    })
}

async fn delete_share(State(keys): St, Path(id): Path<String>, body: Body) -> Reply {
    let object = Id::parse(&id)?;
    let r: k::HolderAction = read(body).await?;
    let path = format!("/v1/objects/{object}");
    let (f, _, _): (k::ActionFacts, _, _) = keys
        .holder(
            &r.statement,
            "delete",
            &r.cert,
            &r.signed,
            "DELETE",
            &path,
            |f: &k::ActionFacts| (&f.account, Some(&f.proof_hash)),
        )
        .await?;
    let u: app::ObjectChange = wire::parse(&r.signed.body)?;
    if u.object != object || f.object != Some(object) {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different document.",
        ));
    }
    let c = keys.db.conn().await?;
    let n = c
        .execute(
            "DELETE FROM shares WHERE object = $1 AND account = $2",
            &[&object.as_bytes(), &f.account.as_bytes()],
        )
        .await?;
    ok(&serde_json::json!({ "deleted": n == 1 }))
}

async fn close(State(keys): St, Path(id): Path<String>, body: Body) -> Reply {
    let account = Id::parse(&id)?;
    let r: k::HolderAction = read(body).await?;
    let (f, _, _): (k::ActionFacts, _, _) = keys
        .holder(
            &r.statement,
            "close",
            &r.cert,
            &r.signed,
            "DELETE",
            "/v1/me",
            |f: &k::ActionFacts| (&f.account, Some(&f.proof_hash)),
        )
        .await?;
    if f.account != account {
        return Err(Error::forbidden(
            "not_vouched",
            "That statement is for another account.",
        ));
    }
    keys.fuses.lock().await.remove(&account);
    let mut c = keys.db.conn().await?;
    let tx = c.transaction().await?;
    let n = tx
        .execute(
            "DELETE FROM shares WHERE account = $1",
            &[&account.as_bytes()],
        )
        .await?;
    tx.execute(
        "DELETE FROM releases WHERE account = $1",
        &[&account.as_bytes()],
    )
    .await?;
    tx.execute(
        "DELETE FROM checkin WHERE account = $1",
        &[&account.as_bytes()],
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "deleted": n }))
}

fn pick(v: u32, allowed: &[u32], what: &str) -> Result<i64> {
    if allowed.contains(&v) {
        Ok(i64::from(v))
    } else {
        Err(Error::bad(
            "bad_checkin",
            format!("Check-in can't use that {what}."),
        ))
    }
}

async fn checkin(State(keys): St, body: Body) -> Reply {
    let r: k::Checkin = read(body).await?;
    let p = &keys.policy.policy;
    let peek: k::CheckinFacts =
        crate::statement::verify(&p.core_key()?, &r.statement, "checkin", keys.now())?;
    if peek.action == "status" {
        return ok(&keys.status(&peek.account).await?);
    }
    let (cert, signed) = match (&r.cert, &r.signed) {
        (Some(c), Some(s)) => (c, s),
        _ => {
            return Err(Error::forbidden(
                "step_up_required",
                "This needs a live check.",
            ));
        }
    };
    let action = peek.action.clone();
    let path = format!("/v1/checkin/{action}");
    let (f, _, _): (k::CheckinFacts, _, _) = keys
        .holder(
            &r.statement,
            "checkin",
            cert,
            signed,
            "POST",
            &path,
            |f: &k::CheckinFacts| (&f.account, f.proof_hash.as_ref()),
        )
        .await?;
    let a = f.account;
    let st = keys.status(&a).await?;
    let now = keys.now();
    match action.as_str() {
        "arm" => {
            let s: app::CheckinArm = wire::parse(&signed.body)?;
            let window = pick(s.window_h, &p.checkin.windows_h, "window")? * ms::HOUR;
            let max = pick(s.max_window_h, &p.checkin.windows_h, "longest window")? * ms::HOUR;
            let grace = pick(s.grace_min, &p.checkin.grace_min, "grace period")? * ms::MINUTE;
            if max < window {
                return Err(Error::bad(
                    "bad_checkin",
                    "The longest window can't be shorter than the usual one.",
                ));
            }
            if st.state == "erased" {
                return Err(ERASED());
            }
            let mut c = keys.db.conn().await?;
            let tx = c.transaction().await?;
            let have: std::collections::HashSet<Vec<u8>> = tx
                .query(
                    "SELECT object FROM shares WHERE account = $1",
                    &[&a.as_bytes()],
                )
                .await?
                .iter()
                .map(|r| r.get(0))
                .collect();
            if f.objects.iter().any(|o| !have.contains(o.as_bytes())) {
                return Err(Error::conflict(
                    "unsplit_items",
                    "Some documents have no key here, so Check-in couldn't erase them for good.",
                ));
            }
            let keep: std::collections::HashSet<Id> = s.keep.iter().copied().collect();
            let mut fuses = keys.fuses.lock().await;
            let new_key = match fuses.get(&a) {
                Some(f) => Secret32::from_slice(f.key.expose()).map_err(Error::from)?,
                None => Secret32::random().map_err(Error::from)?,
            };
            keys.reseal(&tx, &a, Some(&new_key), |o| !keep.contains(o), &fuses)
                .await?;
            tx.execute(
                "INSERT INTO checkin (account, state, window_ms, max_window_ms, grace_ms, armed_at, deadline) VALUES ($1, 'armed', $2, $3, $4, $5, $6)
                 ON CONFLICT (account) DO UPDATE SET state = 'armed', window_ms = $2, max_window_ms = $3, grace_ms = $4, deadline = $6",
                &[&a.as_bytes(), &window, &max, &grace, &now, &(now + window)],
            )
            .await?;
            tx.commit().await?;
            fuses.insert(
                a,
                Fuse {
                    key: new_key,
                    deadline: now + window,
                    erases_at: now + window + grace,
                },
            );
        }
        "check" => {
            let s: app::CheckinCheck = wire::parse(&signed.body)?;
            match st.state.as_str() {
                "erased" => return Err(ERASED()),
                "off" => return Err(Error::conflict("checkin_off", "Check-in isn't on.")),
                _ => {}
            }
            let c = keys.db.conn().await?;
            let row = c
                .query_one(
                    "SELECT window_ms, max_window_ms, grace_ms FROM checkin WHERE account = $1",
                    &[&a.as_bytes()],
                )
                .await?;
            let (window, max, grace): (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
            let next = match s.next_window_h {
                Some(h) => pick(h, &p.checkin.windows_h, "window")? * ms::HOUR,
                None => window,
            };
            if next > max {
                return Err(Error::bad(
                    "bad_checkin",
                    "That's longer than the longest window you allowed.",
                ));
            }
            let mut fuses = keys.fuses.lock().await;
            let fz = fuses.get_mut(&a).ok_or_else(ERASED)?;
            fz.deadline = now + next;
            fz.erases_at = now + next + grace;
            c.execute(
                "UPDATE checkin SET deadline = $2 WHERE account = $1",
                &[&a.as_bytes(), &(now + next)],
            )
            .await?;
        }
        "disarm" => {
            if st.state == "erased" {
                return Err(ERASED());
            }
            if st.state != "off" {
                let mut c = keys.db.conn().await?;
                let tx = c.transaction().await?;
                let mut fuses = keys.fuses.lock().await;
                keys.reseal(&tx, &a, None, |_| false, &fuses).await?;
                tx.execute("DELETE FROM checkin WHERE account = $1", &[&a.as_bytes()])
                    .await?;
                tx.commit().await?;
                fuses.remove(&a);
            }
        }
        _ => return Err(Error::bad("bad_checkin", "Unknown Check-in action.")),
    }
    keys.wake.notify_one();
    ok(&keys.status(&a).await?)
}

/// Erase now: a duress sign-in from this account, checked here, each acted on once.
async fn duress(State(keys): St, body: Body) -> Reply {
    #[cfg(any(test, feature = "testkit"))]
    if keys.refuse_duress.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::unavailable("down", "keys is down (test)"));
    }
    let r: k::Duress = read(body).await?;
    let p = &keys.policy.policy;
    let f: k::DuressFacts =
        crate::statement::verify(&p.core_key()?, &r.statement, "duress", keys.now())?;
    let ph = r
        .proof
        .check(&f.account, keys.now(), p.device_policy.p256_only_until)?;
    let c = keys.db.conn().await?;
    let n = c
        .execute(
            "INSERT INTO duress_used (proof_hash, at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&ph.as_slice(), &keys.now()],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict(
            "already_used",
            "That duress sign-in was already acted on.",
        ));
    }
    drop(c);
    let st = keys.status(&f.account).await?;
    if st.state == "armed" || st.state == "locked" {
        keys.erase(&f.account).await?;
        return ok(&serde_json::json!({ "erased": true }));
    }
    ok(&serde_json::json!({ "erased": false }))
}

#[derive(Deserialize)]
struct StatementOnly {
    statement: B64,
}

/// Erased vaults core hasn't cleaned up: one `erased` statement each, signed here.
async fn erased(State(keys): St, body: Body) -> Reply {
    let r: StatementOnly = read(body).await?;
    let _: k::AccountFacts = crate::statement::verify(
        &keys.policy.policy.core_key()?,
        &r.statement,
        "account",
        keys.now(),
    )?;
    let c = keys.db.conn().await?;
    let rows = c.query("SELECT account, erased_at, erased_count FROM checkin WHERE state = 'erased' AND NOT cleaned LIMIT 50", &[]).await?;
    let mut out = vec![];
    for row in rows {
        let account = Id::from_slice(&row.get::<_, Vec<u8>>(0))?;
        let keep = c
            .query(
                "SELECT object FROM shares WHERE account = $1",
                &[&account.as_bytes()],
            )
            .await?
            .iter()
            .map(|r| Id::from_slice(&r.get::<_, Vec<u8>>(0)))
            .collect::<Result<Vec<_>>>()?;
        let facts = k::ErasedFacts {
            account,
            erased_at: row.get(1),
            keep,
            count: row.get::<_, Option<i64>>(2).unwrap_or(0),
        };
        out.push(crate::statement::sign(
            keys.hsm.as_ref(),
            KeyRef::KeysStatement,
            "erased",
            keys.now(),
            &facts,
        )?);
    }
    ok(&k::ErasedList { erased: out })
}

async fn cleaned(State(keys): St, body: Body) -> Reply {
    let r: k::Cleaned = read(body).await?;
    let f: k::AccountFacts = crate::statement::verify(
        &keys.policy.policy.core_key()?,
        &r.statement,
        "account",
        keys.now(),
    )?;
    let a = f
        .account
        .ok_or_else(|| Error::bad("bad_request", "Name the account."))?;
    let c = keys.db.conn().await?;
    c.execute("UPDATE checkin SET cleaned = true WHERE account = $1 AND state = 'erased' AND erased_at = $2", &[&a.as_bytes(), &r.erased_at]).await?;
    ok(&serde_json::json!({ "cleaned": true }))
}

/// Load (or create) the keys unit's KEM key, its seed sealed under the HSM `seal` key.
///
/// # Errors
/// File or HSM failure.
pub fn load_kem(hsm: &dyn Hsm, dir: &std::path::Path) -> Result<KemSecret> {
    let path = dir.join("keys-kem.sealed");
    let aad: &[&[u8]] = &[b"keys-kem"];
    if path.exists() {
        let boxed = std::fs::read(&path)
            .map_err(|e| Error::internal(format!("{}: {e}", path.display())))?;
        let seed = hsm.unwrap(KeyRef::Seal, object_type::UNIT_SEALED, aad, &boxed)?;
        let s = crypto::Secret::<96>::from_slice(&seed)
            .map_err(|_| Error::internal("keys-kem seed isn't 96 bytes"))?;
        return Ok(KemSecret::from_seed(&s));
    }
    let k = KemSecret::generate()?;
    let boxed = hsm.wrap(
        KeyRef::Seal,
        object_type::UNIT_SEALED,
        aad,
        k.seed().expose(),
    )?;
    std::fs::create_dir_all(dir).map_err(|e| Error::internal(format!("{}: {e}", dir.display())))?;
    crate::hsm::write_private(&path, &boxed)?;
    Ok(k)
}
