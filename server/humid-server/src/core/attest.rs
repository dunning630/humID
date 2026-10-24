//! Phone attestation in core (crates/humid-attest; SERVER.md §2.3, V5.md "The live check").
//!
//! | When | Android | iOS |
//! | --- | --- | --- |
//! | enrolment (register, `POST /v1/devices`) | key attestation chain for the certificate's P-256 live key, bound to [`proofs::attest_challenge`] (the session and the **new device key**, so it is checked against the join request's key); Google's status list | App Attest attestation over `SHA-256(challenge ‖ live key)` |
//! | every sign-in | the stored chain against today's status list (revoked: the device is removed) | an App Attest assertion over the sign-in's live digest, counter strictly increasing |
//! | every step-up | — | an App Attest assertion over the step-up's live digest, counter strictly increasing |
//! | on a schedule (`device_policy.android.reverify_hours`) | the stored chain against today's status list | — |
//!
//! Google's status list is kept in `attest_status`, signed by core's statement key with its
//! fetch time (so the database alone can't drop an entry or freshen a copy), loaded at start,
//! refreshed by [`spawn_status_fetch`] and reloaded by every core instance from the database.
//! When the policy requires attestation, a missing or stale copy fails closed.
//!
//! The trust store is the vendors' pinned roots; [`Attest::new`] in production refuses any
//! other (the testkit's test root can't be accepted there).

use std::sync::RwLock;

use deadpool_postgres::GenericClient;
use humid_attest::{AndroidAttested, AppleAttested, StatusList, Trust, Verifier, android, apple};
use serde::{Deserialize, Serialize};

use super::Core;
use super::ledger::{self, Vouch};
use crate::crypto::{self, label};
use crate::error::{Error, Result};
use crate::hsm::KeyRef;
use crate::policy::Policy;
use crate::proofs::{self, Attestation, Device, Enrolment};
use crate::unit::{Mode, ms};
use crate::wire::{B64, Id};

/// How often the fetcher refreshes Google's list (and how soon it retries after a failure).
pub const STATUS_REFRESH_MS: i64 = 6 * ms::HOUR;
/// Retry after a failed fetch.
pub const STATUS_RETRY_MS: i64 = 10 * ms::MINUTE;
/// Android re-checks per job round.
pub const REVERIFY_BATCH: i64 = 500;

/// Core's attestation checks.
pub struct Attest {
    verifier: Verifier,
    android: humid_attest::AndroidPolicy,
    ios: humid_attest::ApplePolicy,
    required: bool,
    reverify_ms: i64,
    status_max_age_ms: i64,
    status: RwLock<StatusList>,
}

/// What an enrolment's attestation proved.
#[derive(Clone, Debug)]
pub enum Attested {
    /// Nothing (development, attestation not required).
    None,
    /// Android key attestation.
    Android {
        /// The summary.
        detail: AndroidAttested,
        /// The chain, leaf first.
        chain: Vec<Vec<u8>>,
    },
    /// Apple App Attest.
    Apple(AppleAttested),
}

impl Attested {
    /// What the device row and the ledger record (`unattested`, `android-strongbox`,
    /// `android-tee`, `apple-app-attest`).
    #[must_use]
    pub fn proven(&self) -> String {
        match self {
            Attested::None => "unattested".into(),
            Attested::Android { detail, .. } => detail.proven(),
            Attested::Apple(_) => "apple-app-attest".into(),
        }
    }
}

fn refusal(r: humid_attest::Refusal) -> Error {
    match r.code {
        "status_unavailable" | "status_stale" => Error::unavailable(r.code, r.message),
        _ => Error::forbidden(r.code, r.message),
    }
}

fn reattest() -> Error {
    Error::forbidden(
        "reattest_required",
        "This device joined without proving its secure chip, which this server now requires. Add it again from one of your devices.",
    )
}

impl Attest {
    /// Core's checks under `policy`, trusting `trust` (production: only the vendors' roots).
    ///
    /// # Errors
    /// `test_root_in_production`; `bad_policy`.
    pub fn new(policy: &Policy, trust: Trust) -> Result<Self> {
        let mode = match policy.mode {
            Mode::Production => humid_attest::Mode::Production,
            Mode::Development => humid_attest::Mode::Development,
        };
        let verifier = Verifier::new(trust, mode).map_err(refusal)?;
        let dp = &policy.device_policy;
        let required = dp.attestation_required;
        let status_max_age_ms = i64::from(dp.android.status_max_age_hours) * ms::HOUR;
        Ok(Self {
            verifier,
            android: dp.android.rules()?,
            ios: dp.ios.rules(),
            required,
            reverify_ms: i64::from(dp.android.reverify_hours) * ms::HOUR,
            status_max_age_ms,
            status: RwLock::new(StatusList::empty(required, status_max_age_ms)),
        })
    }

    /// Whether the verifier runs in production mode.
    #[must_use]
    pub fn production(&self) -> bool {
        self.verifier.mode() == humid_attest::Mode::Production
    }

    fn with_status<T>(&self, f: impl FnOnce(&StatusList) -> T) -> Result<T> {
        let g = self
            .status
            .read()
            .map_err(|_| Error::internal("status list lock"))?;
        Ok(f(&g))
    }

    /// When the copy of Google's list in memory was fetched.
    ///
    /// # Errors
    /// A poisoned lock.
    pub fn status_fetched_at(&self) -> Result<Option<i64>> {
        self.with_status(StatusList::fetched_at)
    }

    /// Check an enrolment's attestation for device `d`, made in session `th`.
    ///
    /// # Errors
    /// `attestation_required`, or humid-attest's refusal.
    pub fn enrolment(&self, en: &Enrolment, d: &Device, th: &[u8], now: i64) -> Result<Attested> {
        let challenge = proofs::attest_challenge(th, &en.cert.device_vk)?;
        match &en.attestation {
            Attestation::None if self.required => Err(Error::forbidden(
                "attestation_required",
                "This server accepts only phones whose secure chip proves itself.",
            )),
            Attestation::None => Ok(Attested::None),
            Attestation::AndroidKey { chain } => {
                let chain: Vec<Vec<u8>> = chain.iter().map(|c| c.0.clone()).collect();
                let detail = self
                    .with_status(|s| {
                        android::verify(
                            &self.verifier,
                            &chain,
                            &challenge,
                            &d.live_p256,
                            &self.android,
                            s,
                            now,
                        )
                    })?
                    .map_err(refusal)?;
                Ok(Attested::Android { detail, chain })
            }
            Attestation::AppleAppAttest { object } => {
                let cdh = apple::enrolment_client_data_hash(&challenge, &d.live_p256);
                let a = apple::verify_attestation(&self.verifier, object, &cdh, &self.ios, now)
                    .map_err(refusal)?;
                Ok(Attested::Apple(a))
            }
        }
    }

    /// Store what an enrolment proved, beside the device row (same transaction).
    ///
    /// # Errors
    /// Database failure.
    pub async fn store(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        device: &Id,
        a: &Attested,
        now: i64,
    ) -> Result<()> {
        match a {
            Attested::None => Ok(()),
            Attested::Android { detail, chain } => {
                let chain: Vec<B64> = chain.iter().cloned().map(B64).collect();
                tx.execute(
                    "INSERT INTO device_attestations (device, kind, detail, chain, verified_at, next_check_at) VALUES ($1, 'android', $2, $3, $4, $5)",
                    &[&device.as_bytes(), &to_json(detail)?, &to_json(&chain)?, &now, &(now + self.reverify_ms)],
                )
                .await?;
                Ok(())
            }
            Attested::Apple(x) => {
                tx.execute(
                    "INSERT INTO device_attestations (device, kind, detail, app_attest_key, verified_at) VALUES ($1, 'apple', $2, $3, $4)",
                    &[&device.as_bytes(), &to_json(x)?, &x.public_key, &now],
                )
                .await?;
                Ok(())
            }
        }
    }

    /// The per-check App Attest assertion (iOS) for a step-up or a sign-in whose live digest
    /// is `live_digest`; its counter is raised in `c`'s transaction, so a proof is good once.
    /// An Android device sends none. A device without a stored attestation passes only where
    /// attestation isn't required.
    ///
    /// # Errors
    /// `app_attest_required`, `bad_assertion`, `assertion_replayed`, `reattest_required`.
    pub async fn per_check(
        &self,
        c: &impl GenericClient,
        device: &Id,
        assertion: Option<&[u8]>,
        live_digest: &[u8; 64],
    ) -> Result<Stored> {
        let bad = || {
            Error::forbidden(
                "bad_assertion",
                "This iPhone's App Attest proof for this check doesn't verify.",
            )
        };
        let Some(st) = Stored::load(c, device).await? else {
            if self.required {
                return Err(reattest());
            }
            return if assertion.is_some() {
                Err(bad())
            } else {
                Ok(Stored::Unattested)
            };
        };
        let Stored::Apple { attested, counter } = &st else {
            return if assertion.is_some() {
                Err(bad())
            } else {
                Ok(st)
            };
        };
        let a = assertion.ok_or_else(|| {
            Error::forbidden(
                "app_attest_required",
                "This check needs this iPhone's App Attest proof. Update HumID.",
            )
        })?;
        let cdh = proofs::app_attest_client_data_hash(live_digest);
        let last = u32::try_from(*counter).unwrap_or(u32::MAX);
        let ok = apple::verify_assertion(a, attested, &cdh, last).map_err(refusal)?;
        let n = c
            .execute(
                "UPDATE device_attestations SET app_attest_counter = $2 WHERE device = $1 AND app_attest_counter < $2",
                &[&device.as_bytes(), &i64::from(ok.counter)],
            )
            .await?;
        if n != 1 {
            // a concurrent check got there first with this counter or a higher one
            return Err(Error::forbidden(
                "assertion_replayed",
                "That App Attest proof was already used. Try the check again.",
            ));
        }
        Ok(st)
    }

    /// Every sign-in: the per-check assertion (iOS) and, for Android, the stored chain against
    /// today's status list. A revoked chain removes the device, in its own committed
    /// transaction, before the sign-in is refused.
    ///
    /// # Errors
    /// As [`Attest::per_check`]; `attestation_revoked`; `status_unavailable` / `status_stale`.
    pub async fn sign_in(
        &self,
        core: &Core,
        c: &impl GenericClient,
        device: &Id,
        assertion: Option<&[u8]>,
        live_digest: &[u8; 64],
    ) -> Result<()> {
        let st = self.per_check(c, device, assertion, live_digest).await?;
        if let Stored::Android { chain } = st {
            match self.recheck(&chain, core.now())? {
                Ok(()) => {}
                Err(r) if r.code == "revoked" => {
                    revoke(core, device).await?;
                    return Err(revoked_error());
                }
                Err(r) => return Err(refusal(r)),
            }
        }
        Ok(())
    }

    fn recheck(&self, chain: &[Vec<u8>], now: i64) -> Result<humid_attest::Result<()>> {
        self.with_status(|s| android::recheck(&self.verifier, chain, s, now))
    }

    /// Replace the in-memory list (after a verified load).
    ///
    /// # Errors
    /// A poisoned lock.
    fn set_status(&self, s: StatusList) -> Result<()> {
        let mut g = self
            .status
            .write()
            .map_err(|_| Error::internal("status list lock"))?;
        if g.fetched_at()
            .is_none_or(|old| s.fetched_at().is_some_and(|new| new > old))
        {
            *g = s;
        }
        Ok(())
    }
}

fn revoked_error() -> Error {
    Error::forbidden(
        "attestation_revoked",
        "Google has revoked this phone's secure-chip certificate (a leaked or compromised key), so it was removed from your HumID. Use another device or your recovery proofs.",
    )
}

/// What core stored about a device's attestation.
pub enum Stored {
    /// No attestation (development).
    Unattested,
    /// Android: the chain.
    Android {
        /// DER, leaf first.
        chain: Vec<Vec<u8>>,
    },
    /// iOS: the App Attest key and the last counter.
    Apple {
        /// What the attestation proved.
        attested: AppleAttested,
        /// The highest counter accepted.
        counter: i64,
    },
}

impl Stored {
    async fn load(c: &impl GenericClient, device: &Id) -> Result<Option<Self>> {
        let Some(r) = c
            .query_opt(
                "SELECT kind, detail, chain, app_attest_counter FROM device_attestations WHERE device = $1",
                &[&device.as_bytes()],
            )
            .await?
        else {
            return Ok(None);
        };
        let kind: String = r.get(0);
        let bad = |e: serde_json::Error| Error::internal(format!("stored attestation: {e}"));
        Ok(Some(match kind.as_str() {
            "android" => {
                let chain: Vec<B64> =
                    serde_json::from_value(r.get::<_, serde_json::Value>(2)).map_err(bad)?;
                Stored::Android {
                    chain: chain.into_iter().map(|b| b.0).collect(),
                }
            }
            _ => Stored::Apple {
                attested: serde_json::from_value(r.get(1)).map_err(bad)?,
                counter: r.get(3),
            },
        }))
    }
}

/// Remove a device whose attestation was revoked: the device, its sessions, and a
/// `device.removed` entry the server asserts (no holder proof: Google's list is the reason).
///
/// # Errors
/// Database failure.
pub async fn revoke(core: &Core, device: &Id) -> Result<bool> {
    let now = core.now();
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let Some(r) = tx
        .query_opt(
            "UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL RETURNING account",
            &[&device.as_bytes(), &now],
        )
        .await?
    else {
        return Ok(false);
    };
    let account = Id::from_slice(&r.get::<_, Vec<u8>>(0))?;
    tx.execute(
        "UPDATE sessions SET revoked_at = $2 WHERE device = $1 AND revoked_at IS NULL",
        &[&device.as_bytes(), &now],
    )
    .await?;
    tx.execute(
        "UPDATE accounts SET devices_rev = devices_rev + 1 WHERE id = $1",
        &[&account.as_bytes()],
    )
    .await?;
    tx.execute(
        "UPDATE device_attestations SET next_check_at = NULL WHERE device = $1",
        &[&device.as_bytes()],
    )
    .await?;
    ledger::append(
        &tx,
        now,
        &account,
        "device.removed",
        &serde_json::json!({ "device": device, "reason": "attestation_revoked" }),
        Vouch::Server,
    )
    .await?;
    tx.commit().await?;
    tracing::warn!(device = %device, "device removed: its attestation chain is on Google's status list");
    Ok(true)
}

/// Scheduled re-verification (V5.md: "Android attestation re-verified on a schedule"): every
/// active Android device whose check is due is re-checked against today's status list; a
/// revoked one is removed. With no usable list, nothing is removed and the checks wait.
/// Returns (checked, removed).
///
/// # Errors
/// Database failure.
pub async fn reverify_due(core: &Core) -> Result<(usize, usize)> {
    let now = core.now();
    let a = &core.attest;
    if a.with_status(|s| s.usable(now))?.is_err() || a.status_fetched_at()?.is_none() {
        return Ok((0, 0));
    }
    let c = core.db.conn().await?;
    let rows = c
        .query(
            "SELECT t.device, t.chain FROM device_attestations t JOIN devices d ON d.id = t.device
              WHERE t.kind = 'android' AND d.revoked_at IS NULL AND t.next_check_at <= $1
              ORDER BY t.next_check_at LIMIT $2",
            &[&now, &REVERIFY_BATCH],
        )
        .await?;
    let (mut checked, mut removed) = (0, 0);
    for r in rows {
        let device = Id::from_slice(&r.get::<_, Vec<u8>>(0))?;
        let chain: Vec<B64> = serde_json::from_value(r.get(1))
            .map_err(|e| Error::internal(format!("stored chain: {e}")))?;
        let chain: Vec<Vec<u8>> = chain.into_iter().map(|b| b.0).collect();
        checked += 1;
        match a.recheck(&chain, now)? {
            Err(x) if x.code == "revoked" => {
                if revoke(core, &device).await? {
                    removed += 1;
                }
            }
            Err(x) => {
                tracing::warn!(device = %device, code = x.code, "scheduled attestation re-check refused");
                c.execute(
                    "UPDATE device_attestations SET next_check_at = $2 WHERE device = $1",
                    &[&device.as_bytes(), &(now + a.reverify_ms)],
                )
                .await?;
            }
            Ok(()) => {
                c.execute(
                    "UPDATE device_attestations SET next_check_at = $2, verified_at = $3 WHERE device = $1",
                    &[&device.as_bytes(), &(now + a.reverify_ms), &now],
                )
                .await?;
            }
        }
    }
    Ok((checked, removed))
}

/* ------------------------------- the status list ------------------------------- */

fn status_message(fetched_at: i64, list: &[u8]) -> Result<Vec<u8>> {
    crypto::lp(&[&fetched_at.to_be_bytes(), list])
}

/// Keep a copy of Google's list fetched at `fetched_at`: parsed first (anything that isn't a
/// status list is refused and the old copy stays), signed by core's statement key, stored
/// forward-only, and put in memory.
///
/// # Errors
/// `bad_status_list`; `status_rollback` for a copy no newer than the stored one; database or
/// HSM failure.
pub async fn store_status(core: &Core, list: &[u8], fetched_at: i64) -> Result<()> {
    let a = &core.attest;
    if fetched_at > core.now() + 5 * ms::MINUTE {
        return Err(Error::bad(
            "bad_status_list",
            "A status list dated in the future.",
        ));
    }
    let parsed =
        StatusList::parse(list, fetched_at, a.required, a.status_max_age_ms).map_err(refusal)?;
    let sig = core.hsm.mldsa_sign(
        KeyRef::CoreStatement,
        label::ATTEST_STATUS,
        &status_message(fetched_at, list)?,
    )?;
    let c = core.db.conn().await?;
    let n = c
        .execute(
            "INSERT INTO attest_status (one, fetched_at, list, sig) VALUES (true, $1, $2, $3)
             ON CONFLICT (one) DO UPDATE SET fetched_at = $1, list = $2, sig = $3 WHERE attest_status.fetched_at < $1",
            &[&fetched_at, &list, &sig],
        )
        .await?;
    if n != 1 {
        return Err(Error::conflict(
            "status_rollback",
            "A newer copy of Google's status list is already kept.",
        ));
    }
    a.set_status(parsed)
}

/// Load the stored copy if it is newer than the one in memory (start-up, and every core
/// instance's job round: the fetcher may run on another instance). A copy whose signature
/// doesn't verify under core's statement key is ignored (and logged): the list then ages
/// out and checks fail closed.
///
/// # Errors
/// Database failure.
pub async fn load_status(core: &Core) -> Result<bool> {
    let a = &core.attest;
    let c = core.db.conn().await?;
    let Some(at) = c
        .query_opt("SELECT fetched_at FROM attest_status WHERE one", &[])
        .await?
        .map(|r| r.get::<_, i64>(0))
    else {
        return Ok(false);
    };
    if a.status_fetched_at()?.is_some_and(|have| have >= at) {
        return Ok(false);
    }
    let r = c
        .query_one(
            "SELECT fetched_at, list, sig FROM attest_status WHERE one",
            &[],
        )
        .await?;
    let (at, list, sig): (i64, Vec<u8>, Vec<u8>) = (r.get(0), r.get(1), r.get(2));
    let key = core.policy.policy.core_key()?;
    if !key.verifies(label::ATTEST_STATUS, &status_message(at, &list)?, &sig) {
        tracing::error!("the stored attestation status list isn't signed by core: ignored");
        return Ok(false);
    }
    let parsed = StatusList::parse(&list, at, a.required, a.status_max_age_ms).map_err(refusal)?;
    a.set_status(parsed)?;
    Ok(true)
}

/// Fetch Google's list over HTTPS (system roots, TLS 1.2+). The URL is fixed: nothing in
/// `server.toml` can point core at another list.
///
/// # Errors
/// `status_fetch_failed`.
pub async fn fetch_google() -> Result<Vec<u8>> {
    use http_body_util::BodyExt;
    let fail = |e: &dyn std::fmt::Display| {
        Error::unavailable(
            "status_fetch_failed",
            format!("Google's attestation status list: {e}"),
        )
    };
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|e| fail(&e))?
        .https_only()
        .enable_http1()
        .build();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, http_body_util::Empty<bytes::Bytes>>(https);
    let req = axum::http::Request::get(humid_attest::status::STATUS_URL)
        .header("accept", "application/json")
        .body(http_body_util::Empty::new())
        .map_err(|e| fail(&e))?;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(20), client.request(req))
        .await
        .map_err(|e| fail(&e))?
        .map_err(|e| fail(&e))?;
    if !resp.status().is_success() {
        return Err(fail(&resp.status()));
    }
    let body = http_body_util::Limited::new(resp.into_body(), humid_attest::status::MAX_LIST);
    let b = tokio::time::timeout(std::time::Duration::from_secs(60), body.collect())
        .await
        .map_err(|e| fail(&e))?
        .map_err(|e| fail(&e))?
        .to_bytes();
    Ok(b.to_vec())
}

/// Fetch Google's list now and then every [`STATUS_REFRESH_MS`] (sooner after a failure),
/// keeping each good copy.
pub fn spawn_status_fetch(core: std::sync::Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let wait = match fetch_google().await {
                Ok(list) => match store_status(&core, &list, core.now()).await {
                    Ok(()) => {
                        tracing::info!(
                            entries = core.attest.with_status(StatusList::len).unwrap_or(0),
                            "attestation status list fetched"
                        );
                        STATUS_REFRESH_MS
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "attestation status list refused");
                        STATUS_RETRY_MS
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "attestation status list unavailable");
                    STATUS_RETRY_MS
                }
            };
            tokio::time::sleep(std::time::Duration::from_millis(
                u64::try_from(wait).unwrap_or(600_000),
            ))
            .await;
        }
    })
}

/// JSON for a jsonb column.
fn to_json<T: Serialize>(v: &T) -> Result<serde_json::Value> {
    serde_json::to_value(v).map_err(|e| Error::internal(e.to_string()))
}

/// The JSON core keeps about a device's attestation (for `GET /v1/me` and tests).
#[derive(Serialize, Deserialize, Debug)]
pub struct Summary {
    /// `android` / `apple`.
    pub kind: String,
    /// humid-attest's summary.
    pub detail: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit_keys() -> crate::policy::UnitKeys {
        let h = crate::hsm::SoftHsm::ephemeral().unwrap();
        crate::policy::unit_keys_from(&h, &h, &h).unwrap()
    }

    #[test]
    fn the_testkit_root_can_never_be_used_in_production() {
        let mut p = crate::policy::development(1, 0, unit_keys());
        let pki = humid_attest::testkit::TestPki::new(crate::testkit::cluster::T0);
        // development: fine
        Attest::new(&p, pki.trust()).unwrap();
        // production: refused outright, whatever trust store it is handed
        p.mode = Mode::Production;
        let e = Attest::new(&p, pki.trust()).err().unwrap();
        assert_eq!(e.code(), "test_root_in_production");
        // the pinned roots are fine in production, and refuse what the test PKI makes
        let a = Attest::new(&p, Trust::pinned()).unwrap();
        assert!(a.production());
        let phone = crate::testkit::Phone::new().unwrap().with_attest(
            crate::testkit::PhoneAttest::android(&std::sync::Arc::new(pki)),
        );
        let th = [5u8; 64];
        let en = phone.enrolment(&th).unwrap();
        let d = proofs::check_enrolment(&en, None, &th).unwrap();
        a.set_status(StatusList::parse(br#"{"entries":{}}"#, 0, true, i64::MAX / 2).unwrap())
            .unwrap();
        assert_eq!(
            a.enrolment(&en, &d, &th, crate::testkit::cluster::T0)
                .unwrap_err()
                .code(),
            "untrusted_root"
        );
    }
}
