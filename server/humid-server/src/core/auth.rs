//! Registration, sign-in (with duress), sessions, the nonce pool, closing an account.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

use super::ledger::{self, Vouch};
use super::{Core, ENVELOPE, Reply, SESSION_MAX_MS, SMALL, ok, read, token_hash};
use crate::api::{anon as anon_api, app, keys as keys_api};
use crate::crypto::{self, KemPublic, MlDsaPublic, label};
use crate::error::{Error, Result};
use crate::hsm::KeyRef;
use crate::policy::Registration;
use crate::proofs::{self, DuressProof, Enrolment, Login, Signed};
use crate::unit::ms;
use crate::wire::{B64, Id};

/// `POST /v1/auth/register`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    /// The account's ML-DSA-87 key.
    pub account_vk: B64,
    /// The account's hybrid KEM key.
    pub kem_pk: B64,
    /// The account key over `lp(th, account_vk, kem_pk)`.
    pub pop: B64,
    /// The first device.
    pub enrolment: Enrolment,
    /// Anon's `spent` statement, when registration needs a pass.
    #[serde(default)]
    pub spent: Option<B64>,
}

/// An account as its devices see it.
#[derive(Serialize, Deserialize, Debug)]
pub struct AccountView {
    /// Account id.
    pub account: Id,
    /// This device.
    pub device: Id,
    /// Active devices.
    pub devices: Vec<DeviceView>,
}

/// One device.
#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceView {
    /// Id.
    pub id: Id,
    /// What it calls itself.
    pub platform: String,
    /// How it joined.
    pub via: String,
    /// What its attestation proved.
    pub proven: String,
    /// When.
    pub enrolled_at: i64,
}

pub(super) async fn devices_of(
    c: &impl deadpool_postgres::GenericClient,
    account: &Id,
) -> Result<Vec<DeviceView>> {
    let rows = c
        .query(
            "SELECT id, platform, via, proven, enrolled_at FROM devices WHERE account = $1 AND revoked_at IS NULL ORDER BY enrolled_at",
            &[&account.as_bytes()],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(DeviceView {
                id: Id::from_slice(&r.get::<_, Vec<u8>>(0))?,
                platform: r.get(1),
                via: r.get(2),
                proven: r.get(3),
                enrolled_at: r.get(4),
            })
        })
        .collect()
}

pub(super) async fn insert_device(
    tx: &deadpool_postgres::Transaction<'_>,
    core: &Core,
    en: &Enrolment,
    d: &proofs::Device,
    proven: &str,
    via: &str,
) -> Result<()> {
    let active: i64 = tx
        .query_one(
            "SELECT count(*) FROM devices WHERE account = $1 AND revoked_at IS NULL",
            &[&d.account.as_bytes()],
        )
        .await?
        .get(0);
    if active >= i64::from(core.policy.policy.limits.devices_per_account) {
        return Err(Error::too_many(
            "too_many_devices",
            "This HumID has as many devices as it can hold. Remove one first.",
        ));
    }
    if tx
        .query_opt("SELECT 1 FROM devices WHERE id = $1", &[&d.id.as_bytes()])
        .await?
        .is_some()
    {
        return Err(Error::conflict(
            "device_exists",
            "This device key is already enrolled.",
        ));
    }
    let cert = serde_json::to_value(&en.cert).map_err(|e| Error::internal(e.to_string()))?;
    let platform: String = en
        .platform
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    tx.execute(
        "INSERT INTO devices (id, account, cert, proven, platform, via, enrolled_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[&d.id.as_bytes(), &d.account.as_bytes(), &cert, &proven, &platform, &via, &core.now()],
    )
    .await?;
    tx.execute(
        "UPDATE accounts SET devices_rev = devices_rev + 1 WHERE id = $1",
        &[&d.account.as_bytes()],
    )
    .await?;
    Ok(())
}

/// Create an account with its first device. The account key proves possession; the device
/// is certified by it; registration never adds a device to an existing account (PC-02).
pub async fn register(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let r: Register = read(body, SMALL).await?;
    let th = Core::th(&headers)?;
    let avk = MlDsaPublic::from_bytes(&r.account_vk)?;
    KemPublic::from_bytes(&r.kem_pk)?;
    let account = Id(avk.id());
    let m = crypto::lp(&[&th, &r.account_vk, &r.kem_pk])?;
    if !avk.verifies(label::REGISTER, &m, &r.pop) {
        return Err(Error::bad_proof());
    }
    let p = &core.policy.policy;
    let (d, proven) = proofs::check_enrolment(
        &r.enrolment,
        Some(&account),
        &th,
        p.device_policy.attestation_required,
    )?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    if p.registration == Registration::Pass {
        let st = r.spent.as_ref().ok_or_else(|| {
            Error::forbidden("pass_required", "Registration needs an access pass.")
        })?;
        let _: anon_api::SpentFacts =
            crate::statement::verify(&p.anon_key()?, st, "spent", core.now())?;
        core.use_statement(&tx, st).await?;
    }
    if tx
        .query_opt(
            "SELECT 1 FROM accounts WHERE id = $1",
            &[&account.as_bytes()],
        )
        .await?
        .is_some()
    {
        return Err(Error::conflict(
            "identity_exists",
            "This HumID already exists. Add this phone from one of your devices, or recover your HumID.",
        ));
    }
    let now = core.now();
    tx.execute(
        "INSERT INTO accounts (id, account_vk, kem_pk, created_at) VALUES ($1, $2, $3, $4)",
        &[&account.as_bytes(), &r.account_vk.0, &r.kem_pk.0, &now],
    )
    .await?;
    insert_device(&tx, &core, &r.enrolment, &d, proven.as_str(), "register").await?;
    let pop_hash = proofs::proof_hash(&r.pop)?;
    // the account-key binding goes into the public log at creation (V5.md: pinned at creation)
    #[derive(Serialize)]
    struct Created {
        account_key: String,
        kem_key: String,
    }
    let kem = KemPublic::from_bytes(&r.kem_pk)?;
    ledger::append(
        &tx,
        now,
        &account,
        "account.created",
        &Created {
            account_key: hex::encode(avk.id()),
            kem_key: hex::encode(crypto::key_id(&kem.to_bytes())),
        },
        Vouch::Holder(&pop_hash),
    )
    .await?;
    added(
        &tx,
        now,
        &account,
        &d.id,
        "register",
        proven.as_str(),
        &proofs::proof_hash(&r.enrolment.device_pop)?,
    )
    .await?;
    tx.commit().await?;
    super::created(&serde_json::json!({ "account": account, "device": d.id }))
}

pub(super) async fn added(
    tx: &deadpool_postgres::Transaction<'_>,
    now: i64,
    account: &Id,
    device: &Id,
    via: &str,
    proven: &str,
    proof: &[u8; 32],
) -> Result<ledger::Appended> {
    ledger::append(
        tx,
        now,
        account,
        "device.added",
        &serde_json::json!({ "device": device, "via": via, "proven": proven }),
        Vouch::Holder(proof),
    )
    .await
}

/// `POST /v1/auth/challenge`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeReq {
    /// Account.
    pub account: Id,
    /// Device.
    pub device: Id,
}

/// How long a sign-in challenge is good for.
pub const CHALLENGE_MS: i64 = 2 * ms::MINUTE;

/// `challenge = u64 issued_at ‖ 16 random ‖ KMAC(session key, account, device, issued_at, random)`.
fn challenge_tag(core: &Core, account: &Id, device: &Id, head: &[u8]) -> Result<[u8; 32]> {
    core.hsm.mac(
        KeyRef::Session,
        label::LOGIN_CHALLENGE,
        &[account.as_bytes(), device.as_bytes(), head],
    )
}

/// A single-use sign-in challenge (2 minutes). Stateless (H-3): it is a MAC under the HSM
/// `session` key over the account, the device and the time, so asking for challenges stores
/// nothing and can't use up anyone's: there is no per-device cap left to exhaust. Single use
/// is enforced when one signs someone in. An unknown account or device gets the same answer.
pub async fn challenge(State(core): State<Arc<Core>>, body: Body) -> Reply {
    let r: ChallengeReq = read(body, SMALL).await?;
    let now = core.now();
    let mut head = now.to_be_bytes().to_vec();
    head.extend_from_slice(&crypto::random::<16>()?);
    let tag = challenge_tag(&core, &r.account, &r.device, &head)?;
    head.extend_from_slice(&tag);
    ok(&serde_json::json!({ "challenge": B64(head), "expires_at": now + CHALLENGE_MS }))
}

/// Check a challenge's MAC and age (not its single use).
fn challenge_ok(core: &Core, l: &Login, now: i64) -> bool {
    let c = &l.challenge.0;
    if c.len() != 56 {
        return false;
    }
    let at = i64::from_be_bytes(c[..8].try_into().unwrap_or([0; 8]));
    if at > now + 5 * ms::SECOND || now - at > CHALLENGE_MS {
        return false;
    }
    challenge_tag(core, &l.account, &l.device, &c[..24]).is_ok_and(|t| crypto::ct_eq(&t, &c[24..]))
}

/// What a sign-in answers (the same shape for an ordinary and a duress sign-in).
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginReply {
    /// The session token (front holds it inside the HTP session).
    pub token: B64,
    /// Expires (ms).
    pub expires_at: i64,
    /// Step-up nonces.
    pub nonces: Vec<B64>,
    /// The account.
    pub me: AccountView,
}

/// Sign in. Core checks the device key's and the chip's signatures itself and issues the
/// session (front never decides who is signed in).
///
/// **Throttling never refuses a valid proof (H-3, CHECKIN.md).** The proof is checked first.
/// Only a failure an attacker can't produce for someone else is counted against the identity:
/// a well-formed challenge for this very device whose signatures then don't verify. Junk
/// (no valid challenge) is counted against the network only. So knowing an account id gets
/// nobody anywhere, and a holder's valid sign-in, which is all a check-in needs, always works.
///
/// A duress sign-in locks the account down silently, doubles recovery waits (including those
/// already waiting), records the duress sign-in for keys, and answers exactly as an ordinary
/// sign-in does. The erase request goes to keys **after** the reply, from a durable queue
/// retried until keys acts on it (M-3), so neither the answer nor its timing differs (H-1).
pub async fn login(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let l: Login = read(body, SMALL).await?;
    let th = Core::th(&headers)?;
    let now = core.now();
    let net = core.network(&headers)?;
    let lim = &core.policy.policy.limits;
    let fail_network = |e: Error| {
        core.signin_per_network.take(&net, now);
        e
    };
    if !crypto::ct_eq(&l.th, &th) || !challenge_ok(&core, &l, now) {
        // nothing here ties the attempt to the account it names
        if core.signin_per_network.peek(&net, now) >= lim.signin_failures_per_network {
            return Err(Error::too_many(
                "rate_limited",
                "Too many failed sign-ins. Wait a few minutes.",
            ));
        }
        return Err(fail_network(Error::bad_proof()));
    }
    let id_key = l.account.to_string();
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    // the proof, before any limit
    let checked = match core.device(&tx, &l.account, &l.device).await {
        Ok((cert, d)) => proofs::check_login(
            &l,
            &d,
            now,
            core.policy.policy.device_policy.p256_only_until,
        )
        .map(|ph| (cert, ph)),
        Err(e) => Err(e),
    };
    let (cert, proof_hash) = match checked {
        Ok(x) => x,
        Err(e) => {
            // a valid challenge for this device, and signatures that don't verify: only someone
            // who can reach this device's sign-in can make these; the limit slows guessing
            let over =
                core.signin_per_identity.peek(&id_key, now) >= lim.signin_failures_per_identity;
            core.signin_per_identity.take(&id_key, now);
            core.signin_per_network.take(&net, now);
            if over {
                return Err(Error::too_many(
                    "rate_limited",
                    "Too many failed sign-ins. Wait a few minutes.",
                ));
            }
            return Err(e);
        }
    };
    let ch = crypto::sha3_512(&l.challenge);
    let fresh = tx
        .execute(
            "INSERT INTO used_challenges (hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&ch.as_slice(), &(now + CHALLENGE_MS + ms::MINUTE)],
        )
        .await?;
    if fresh != 1 {
        return Err(Error::forbidden(
            "challenge_used",
            "That sign-in was already used. Try again.",
        ));
    }
    let token = crypto::random::<32>()?;
    let th_ = token_hash(&token)?;
    let duress = l.duress == 1;
    // a duress session is shown Check-in as it is now, and only its own check-ins move it
    // every sign-in asks keys where Check-in stands (CHECKIN.md), so a duress sign-in takes
    // the same time; only a duress session keeps the answer, as its own copy
    let checkin = checkin_now(&core, &l.account).await;
    let view = if duress {
        Some(serde_json::to_value(checkin).map_err(|e| Error::internal(e.to_string()))?)
    } else {
        None
    };
    tx.execute(
        "INSERT INTO sessions (token_hash, account, device, th, created_at, last_used_at, expires_at, duress, checkin_view) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8)",
        &[&th_.as_slice(), &l.account.as_bytes(), &l.device.as_bytes(), &th, &now, &(now + SESSION_MAX_MS), &duress, &view],
    )
    .await?;
    // one account holds at most N sessions: past that, its own least recently used goes
    tx.execute(
        "UPDATE sessions SET revoked_at = $3 WHERE token_hash IN (
            SELECT token_hash FROM sessions WHERE account = $1 AND revoked_at IS NULL ORDER BY last_used_at DESC OFFSET $2)",
        &[&l.account.as_bytes(), &i64::from(lim.sessions_per_account), &now],
    )
    .await?;
    tx.execute(
        "UPDATE devices SET last_seen_at = $2 WHERE id = $1",
        &[&l.device.as_bytes(), &now],
    )
    .await?;
    if duress {
        tx.execute(
            "UPDATE accounts SET lockdown_at = COALESCE(lockdown_at, $2), last_duress_at = $2 WHERE id = $1",
            &[&l.account.as_bytes(), &now],
        )
        .await?;
        tx.execute("INSERT INTO duress (account, at, proof_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", &[&l.account.as_bytes(), &now, &proof_hash.as_slice()])
            .await?;
        // L-3: recoveries already waiting wait twice as long from now
        tx.execute(
            "UPDATE recovery_requests SET release_at = $2 + 2 * GREATEST(release_at - $2, 0), expires_at = GREATEST(expires_at, $2 + 2 * GREATEST(release_at - $2, 0) + $3)
              WHERE account = $1 AND status = 'waiting' AND release_at IS NOT NULL",
            &[&l.account.as_bytes(), &now, &super::recovery::COLLECT_MS],
        )
        .await?;
        let proof = serde_json::to_value(DuressProof {
            cert,
            login: l.clone(),
        })
        .map_err(|e| Error::internal(e.to_string()))?;
        tx.execute(
            "INSERT INTO duress_pending (proof_hash, account, proof, created_at, next_at) VALUES ($1, $2, $3, $4, $4) ON CONFLICT DO NOTHING",
            &[&proof_hash.as_slice(), &l.account.as_bytes(), &proof, &now],
        )
        .await?;
        // the duress session is live from this transaction on, so this waits until it ends
        ledger::append_or_defer(
            &tx,
            now,
            &l.account,
            "session.duress",
            &serde_json::json!({ "device": l.device }),
            Vouch::Holder(&proof_hash),
        )
        .await?;
    }
    let nonces = core.nonces(&tx, &th_, &l.device).await?;
    let me = AccountView {
        account: l.account,
        device: l.device,
        devices: devices_of(&tx, &l.account).await?,
    };
    tx.commit().await?;
    if duress {
        // after the reply: the erase must not show in the answer or its timing
        let c2 = core.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Err(e) = deliver_duress(&c2).await {
                tracing::warn!(error = %e, "duress delivery will be retried");
            }
        });
    }
    ok(&LoginReply {
        token: B64(token.to_vec()),
        expires_at: now + SESSION_MAX_MS,
        nonces,
        me,
    })
}

/// Where Check-in stands at keys, for a duress session's frozen copy. If keys can't be asked,
/// the copy is "off" (an unreachable keys unit answers no ordinary session either).
async fn checkin_now(core: &Core, account: &Id) -> keys_api::CheckinStatus {
    let off = keys_api::CheckinStatus::off;
    let Ok(st) = core.statement(
        "checkin",
        &keys_api::CheckinFacts {
            account: *account,
            action: "status".into(),
            proof_hash: None,
            objects: vec![],
        },
    ) else {
        return off();
    };
    let req = keys_api::Checkin {
        statement: st,
        cert: None,
        signed: None,
    };
    core.keys
        .post::<_, keys_api::CheckinStatus>("/v1/checkin", &[], &req)
        .await
        .unwrap_or_else(|_| off())
}

/// Deliver queued duress sign-ins to keys (M-3): each is retried, with back-off, until keys
/// acts on it or says it already did. Returns how many were delivered. Run after a duress
/// sign-in's reply and by core's job loop.
///
/// # Errors
/// The database is unavailable.
pub async fn deliver_duress(core: &Core) -> Result<usize> {
    let now = core.now();
    let c = core.db.conn().await?;
    let rows = c
        .query(
            "SELECT proof_hash, account, proof, attempts FROM duress_pending WHERE next_at <= $1 ORDER BY created_at LIMIT 50",
            &[&now],
        )
        .await?;
    let mut delivered = 0;
    for r in rows {
        let ph: Vec<u8> = r.get(0);
        let account = Id::from_slice(&r.get::<_, Vec<u8>>(1))?;
        let proof: DuressProof = serde_json::from_value(r.get(2))
            .map_err(|e| Error::internal(format!("queued duress proof: {e}")))?;
        let attempts: i32 = r.get(3);
        let req = keys_api::Duress {
            statement: core.statement("duress", &keys_api::DuressFacts { account })?,
            proof,
        };
        let done = match core
            .keys
            .post::<_, serde_json::Value>("/v1/duress", &[], &req)
            .await
        {
            Ok(_) => true,
            Err(e) if e.code_str() == "already_used" => true,
            Err(e) => {
                tracing::warn!(error = %e, attempts, "keys didn't take a duress sign-in yet");
                false
            }
        };
        if done {
            c.execute("DELETE FROM duress_pending WHERE proof_hash = $1", &[&ph])
                .await?;
            delivered += 1;
        } else {
            let wait = (ms::SECOND << attempts.clamp(0, 6)).min(ms::MINUTE);
            c.execute(
                "UPDATE duress_pending SET attempts = attempts + 1, next_at = $2 WHERE proof_hash = $1",
                &[&ph, &(now + wait)],
            )
            .await?;
        }
    }
    Ok(delivered)
}

/// `POST /v1/auth/logout`.
pub async fn logout(State(core): State<Arc<Core>>, headers: HeaderMap) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    c.execute(
        "UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1",
        &[&s.token_hash, &core.now()],
    )
    .await?;
    ok(&serde_json::json!({ "signed_out": true }))
}

/// `POST /v1/auth/nonces`: top up the step-up pool.
pub async fn nonces(State(core): State<Arc<Core>>, headers: HeaderMap) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    ok(&serde_json::json!({ "nonces": core.nonces(&c, &s.token_hash, &s.device).await? }))
}

/// `GET /v1/me`. (Lockdown is never shown: whoever holds the phone may be the one who forced it.)
pub async fn me(State(core): State<Arc<Core>>, headers: HeaderMap) -> Reply {
    let s = core.session(&headers).await?;
    let c = core.db.conn().await?;
    ok(&AccountView {
        account: s.account,
        device: s.device,
        devices: devices_of(&c, &s.account).await?,
    })
}

/// A request that carries only the holder's signed approval.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approved {
    /// The signed request.
    pub signed: Signed,
}

/// `DELETE /v1/me`: close the account. Keys destroys every share first (inside the same
/// transaction's lifetime: if keys refuses, nothing here changes).
pub async fn close(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    Core::not_locked(&s)?;
    let r: Approved = read(body, SMALL).await?;
    let _: app::Empty = crate::wire::parse(&r.signed.body)?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, cert) = core.step_up(&tx, &s, &r.signed, "DELETE", "/v1/me").await?;
    let now = core.now();
    let a = s.account.as_bytes();
    tx.execute(
        "UPDATE accounts SET status = 'closed', closed_at = $2 WHERE id = $1",
        &[&a, &now],
    )
    .await?;
    tx.execute(
        "UPDATE devices SET revoked_at = $2 WHERE account = $1 AND revoked_at IS NULL",
        &[&a, &now],
    )
    .await?;
    tx.execute(
        "UPDATE sessions SET revoked_at = $2 WHERE account = $1 AND revoked_at IS NULL",
        &[&a, &now],
    )
    .await?;
    for t in [
        "recovery_cards",
        "recovery_witnesses",
        "recovery_mode",
        "objects",
        "object_tombstones",
        "duress",
    ] {
        tx.execute(
            format!("DELETE FROM {t} WHERE account = $1").as_str(),
            &[&a],
        )
        .await?;
    }
    tx.execute("UPDATE recovery_requests SET status = 'cancelled', closed_at = $2 WHERE account = $1 AND status IN ('collecting', 'waiting')", &[&a, &now])
        .await?;
    let st = core.statement(
        "close",
        &keys_api::ActionFacts {
            account: s.account,
            object: None,
            proof_hash: B64(checked.proof_hash.to_vec()),
        },
    )?;
    // keys first, then the ledger entry (M-1: the public log's lock is never held across a
    // call to another unit); if keys refuses, nothing here commits
    let _: serde_json::Value = core
        .keys
        .post(
            &format!("/v1/accounts/{}/close", s.account),
            &[],
            &keys_api::HolderAction {
                statement: st,
                cert,
                signed: r.signed,
            },
        )
        .await?;
    ledger::append(
        &tx,
        now,
        &s.account,
        "account.closed",
        &serde_json::json!({}),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "closed": true }))
}

/// `POST /v1/duress/clear`: lift a lockdown, calmly, after the cool-off.
pub async fn clear_duress(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    if s.duress {
        return Err(Error::busy());
    }
    let r: Approved = read(body, SMALL).await?;
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(&tx, &s, &r.signed, "POST", "/v1/duress/clear")
        .await?;
    let row = tx
        .query_one(
            "SELECT lockdown_at, last_duress_at FROM accounts WHERE id = $1 FOR UPDATE",
            &[&s.account.as_bytes()],
        )
        .await?;
    let (lock, last): (Option<i64>, Option<i64>) = (row.get(0), row.get(1));
    if lock.is_none() {
        tx.commit().await?;
        return ok(&serde_json::json!({ "cleared": false }));
    }
    if core.now() < last.unwrap_or(0) + core.policy.policy.recovery.duress_cooloff_ms {
        return Err(Error::conflict(
            "too_soon",
            "Lockdown can be lifted once it has been calm for a while.",
        ));
    }
    tx.execute(
        "UPDATE accounts SET lockdown_at = NULL WHERE id = $1",
        &[&s.account.as_bytes()],
    )
    .await?;
    // deferred while a duress session is live: that session must not learn of it
    ledger::append_or_defer(
        &tx,
        core.now(),
        &s.account,
        "duress.cleared",
        &serde_json::json!({}),
        Vouch::Holder(&checked.proof_hash),
    )
    .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "cleared": true }))
}

/// Live checks for post tokens per account per day (each buys up to the policy's batch).
pub const LIVE_CHECKS_PER_DAY: i32 = 32;

/// `POST /v1/live/attest`: the holder approved these blinded values with a live check. Core
/// answers with an account-free statement for anon (M1: anon mints nothing on front's word).
pub async fn live_attest(State(core): State<Arc<Core>>, headers: HeaderMap, body: Body) -> Reply {
    let s = core.session(&headers).await?;
    if s.duress {
        return Err(Error::busy()); // a duress session sends nothing (audit M-1)
    }
    let r: Approved = read(body, ENVELOPE).await?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct What {
        action: String,
        blinded: Vec<B64>,
    }
    let w: What = crate::wire::parse(&r.signed.body)?;
    if w.action != "post-tokens"
        || w.blinded.is_empty()
        || w.blinded.len() > core.policy.policy.messaging.post_tokens_per_check as usize
    {
        return Err(Error::bad(
            "bad_request",
            "One live check approves 1 to the policy's number of post tokens.",
        ));
    }
    let mut c = core.db.conn().await?;
    let tx = c.transaction().await?;
    let (checked, _) = core
        .step_up(&tx, &s, &r.signed, "POST", "/v1/live/attest")
        .await?;
    // M-6: each live check buys post tokens, and each token a relay deposit; a day's cap per
    // account bounds what one account can put in the relay
    let day = core.now().div_euclid(ms::DAY);
    let n: i32 = tx
        .query_one(
            "INSERT INTO live_check_days (account, day, n) VALUES ($1, $2, 1)
             ON CONFLICT (account, day) DO UPDATE SET n = live_check_days.n + 1 RETURNING n",
            &[&s.account.as_bytes(), &day],
        )
        .await?
        .get(0);
    if n > LIVE_CHECKS_PER_DAY {
        return Err(Error::too_many(
            "rate_limited",
            "You've sent a lot of messages today. Try again tomorrow.",
        ));
    }
    tx.commit().await?;
    let facts = anon_api::LiveCheckFacts {
        action: w.action,
        body_hash: B64(crypto::sha3_512(&r.signed.body).to_vec()),
        proof_hash: B64(checked.proof_hash.to_vec()),
    };
    ok(&serde_json::json!({ "statement": core.statement("live-check", &facts)? }))
}
