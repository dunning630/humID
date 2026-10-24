//! The anon unit: access passes, post tokens, the relay (SERVER.md §1, §10). It never sees an
//! account id, and keeps days, not times, except relay arrival to the minute.
//!
//! * **Passes** (registration): an access code buys one RFC 9474 blind signature; a pass is
//!   spent once and answered with an HSM-signed `spent` statement core needs to register.
//! * **Post tokens** (M1, M-10): issued only against core's account-free `live-check`
//!   statement over exactly these blinded values, once per check. Anon mints nothing on
//!   front's word. Deposits spend a post token; there are no IP quotas.
//! * **Relay** (H-3): `tick` only reads (fixed-size request and padded reply over prefixes);
//!   `ack` with the token whose hash the sender stored deletes. Nothing is deleted on fetch.

pub mod relay;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::api::anon as a;
use crate::crypto::{self, blind, label, object_type};
use crate::db::{Db, Migration};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::policy::SignedPolicy;
use crate::retention::{Rule, TableRule};
use crate::unit::{Clock, ms};
use crate::wire::{self, B64};

/// Anon's migrations.
pub const MIGRATIONS: &[Migration] = &[(
    1,
    "init",
    include_str!("../../migrations/anon/0001_init.sql"),
)];

/// HSM keys it needs.
pub const HSM_KEYS: &[KeyRef] = &[KeyRef::AnonStatement, KeyRef::Seal];

/// Retention (SERVER.md §5).
pub const RETENTION: &[TableRule] = &[
    TableRule {
        table: "access_codes",
        rule: Rule::Kept(
            "unused codes until their batch is withdrawn; used ones deleted 400 days after use by prune_codes()",
        ),
    },
    TableRule {
        table: "blind_keys",
        rule: Rule::Delete("accept_until < $1"),
    },
    TableRule {
        table: "spent",
        rule: Rule::Delete("accept_until < $1"),
    },
    TableRule {
        table: "used_checks",
        rule: Rule::Delete("expires_at < $1"),
    },
    TableRule {
        table: "relay_objects",
        rule: Rule::Kept("14 days, by the relay's own expiry (it keeps the byte counter right)"),
    },
    TableRule {
        table: "push_subs",
        rule: Rule::Delete("refreshed_at < $1 - 2592000000"),
    },
    TableRule {
        table: "day_counts",
        rule: Rule::Kept("400 days, by prune_codes()"),
    },
];

/// Pass keys issue for a year and are accepted for 18 months; post-token keys a week and two.
const PASS_ISSUE_MS: i64 = 365 * ms::DAY;
const PASS_ACCEPT_MS: i64 = 545 * ms::DAY;
const POST_ISSUE_MS: i64 = 7 * ms::DAY;
const POST_ACCEPT_MS: i64 = 21 * ms::DAY;

/// The anon unit.
pub struct Anon {
    pub(crate) db: Db,
    hsm: Arc<dyn Hsm>,
    pub(crate) policy: Arc<SignedPolicy>,
    pub(crate) clock: Clock,
    bits: usize,
    signers: tokio::sync::Mutex<std::collections::HashMap<Vec<u8>, Arc<blind::SigningKey>>>,
    /// The relay's total bytes (kept, not summed per deposit).
    pub(crate) relay_bytes: std::sync::atomic::AtomicI64,
}

impl Anon {
    /// An anon unit. `bits`: blind-RSA modulus (3072+ in production; tests use 2048).
    ///
    /// # Errors
    /// Database failure.
    pub async fn new(
        db: Db,
        hsm: Arc<dyn Hsm>,
        policy: Arc<SignedPolicy>,
        clock: Clock,
        bits: usize,
    ) -> Result<Arc<Self>> {
        let total: i64 = db
            .conn()
            .await?
            .query_one(
                "SELECT COALESCE(sum(size), 0)::bigint FROM relay_objects",
                &[],
            )
            .await?
            .get(0);
        Ok(Arc::new(Self {
            db,
            hsm,
            policy,
            clock,
            bits,
            signers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            relay_bytes: total.into(),
        }))
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
    }

    /// The router.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/pass/keys", get(pass_keys))
            .route("/v1/pass/issue", post(pass_issue))
            .route("/v1/pass/spend", post(pass_spend))
            .route("/v1/post-tokens/keys", get(post_keys))
            .route("/v1/post-tokens", post(post_tokens))
            .route("/v1/stamps", post(stamps))
            .route("/v1/relay/deposit", post(relay::deposit))
            .route("/v1/relay/tick", post(relay::tick))
            .route("/v1/relay/ack", post(relay::ack))
            .route("/v1/relay/retract", post(relay::retract))
            .route("/v1/push/subscribe", post(relay::push_subscribe))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self.clone())
    }

    /// The current issuing key for `purpose`, made if there is none (rotation by period).
    async fn issuing(&self, purpose: &str) -> Result<(Vec<u8>, Arc<blind::SigningKey>)> {
        let now = self.now();
        let c = self.db.conn().await?;
        let row = c
            .query_opt(
                "SELECT kid, sealed_sk FROM blind_keys WHERE purpose = $1 AND issue_until > $2 AND sealed_sk IS NOT NULL ORDER BY issue_until DESC LIMIT 1",
                &[&purpose, &now],
            )
            .await?;
        if let Some(r) = row {
            let kid: Vec<u8> = r.get(0);
            if let Some(s) = self.signers.lock().await.get(&kid) {
                return Ok((kid, s.clone()));
            }
            let der = self.hsm.unwrap(
                KeyRef::Seal,
                object_type::UNIT_SEALED,
                &[b"blind", &kid],
                &r.get::<_, Vec<u8>>(1),
            )?;
            let s = Arc::new(blind::SigningKey::from_der(&der)?);
            self.signers.lock().await.insert(kid.clone(), s.clone());
            return Ok((kid, s));
        }
        let (issue, accept) = if purpose == "pass" {
            (PASS_ISSUE_MS, PASS_ACCEPT_MS)
        } else {
            (POST_ISSUE_MS, POST_ACCEPT_MS)
        };
        let bits = self.bits;
        let sk = tokio::task::spawn_blocking(move || blind::SigningKey::generate(bits))
            .await
            .map_err(|e| Error::internal(e.to_string()))??;
        let spki = sk.public()?.to_spki()?;
        let kid = crypto::sha3_512(&spki)[..32].to_vec();
        let sealed = self.hsm.wrap(
            KeyRef::Seal,
            object_type::UNIT_SEALED,
            &[b"blind", &kid],
            &sk.to_der()?,
        )?;
        c.execute(
            "INSERT INTO blind_keys (kid, purpose, spki, sealed_sk, issue_until, accept_until) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            &[&kid, &purpose, &spki, &sealed, &(now + issue), &(now + accept)],
        )
        .await?;
        let sk = Arc::new(sk);
        self.signers.lock().await.insert(kid.clone(), sk.clone());
        Ok((kid, sk))
    }

    /// Published keys for `purpose` (issuing first), at most two.
    async fn published(&self, purpose: &str) -> Result<Vec<serde_json::Value>> {
        self.issuing(purpose).await?;
        let c = self.db.conn().await?;
        let rows = c
            .query("SELECT kid, spki, issue_until, accept_until FROM blind_keys WHERE purpose = $1 AND accept_until > $2 ORDER BY issue_until DESC LIMIT 2", &[&purpose, &self.now()])
            .await?;
        Ok(rows
            .iter()
            .map(|r| serde_json::json!({ "kid": B64(r.get(0)), "spki": B64(r.get(1)), "issue_until": r.get::<_, i64>(2), "accept_until": r.get::<_, i64>(3) }))
            .collect())
    }

    /// Verify and spend a token of `purpose`. Returns its spent id.
    pub(crate) async fn spend(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        purpose: &str,
        t: &a::Token,
    ) -> Result<Vec<u8>> {
        let now = self.now();
        let row = tx
            .query_opt("SELECT spki, accept_until FROM blind_keys WHERE kid = $1 AND purpose = $2 AND accept_until > $3", &[&t.kid.0, &purpose, &now])
            .await?
            .ok_or_else(|| Error::forbidden("token_expired", "That token has expired or isn't from this server."))?;
        let pk = blind::PublicKey::from_spki(&row.get::<_, Vec<u8>>(0))?;
        if t.msg.len() != 32 || !pk.verifies(&t.msg, &t.randomizer, &t.sig) {
            return Err(Error::forbidden("token_invalid", "That token isn't valid."));
        }
        let id = crypto::hash(label::SPENT, &[purpose.as_bytes(), &t.kid, &t.msg])?[..32].to_vec();
        let accept: i64 = row.get(1);
        let n = tx
            .execute("INSERT INTO spent (id, kid, accept_until, day) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING", &[&id, &t.kid.0, &accept, &self.clock.day()])
            .await?;
        if n != 1 {
            return Err(Error::conflict(
                "token_spent",
                "That token was already used.",
            ));
        }
        Ok(id)
    }

    pub(crate) async fn count(
        &self,
        c: &impl deadpool_postgres::GenericClient,
        col: &str,
        n: i64,
    ) -> Result<()> {
        c.execute(
            format!("INSERT INTO day_counts (day, {col}) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET {col} = day_counts.{col} + $2").as_str(),
            &[&self.clock.day(), &n],
        )
        .await?;
        Ok(())
    }

    /// Erase blind-signing private keys whose issuing ended; delete codes used 400 days ago.
    ///
    /// # Errors
    /// Database failure.
    pub async fn prune_codes(&self) -> Result<()> {
        let c = self.db.conn().await?;
        c.execute("UPDATE blind_keys SET sealed_sk = NULL WHERE issue_until < $1 AND sealed_sk IS NOT NULL", &[&self.now()]).await?;
        let cutoff = crate::unit::day_of(self.now() - 400 * ms::DAY);
        c.execute(
            "DELETE FROM access_codes WHERE used_day IS NOT NULL AND used_day < $1",
            &[&cutoff],
        )
        .await?;
        c.execute("DELETE FROM day_counts WHERE day < $1", &[&cutoff])
            .await?;
        Ok(())
    }

    /// Mint access codes (the operator's tool). Returns the codes; only their hashes are kept.
    ///
    /// # Errors
    /// Database failure.
    pub async fn mint(&self, n: usize, batch: &str) -> Result<Vec<String>> {
        let c = self.db.conn().await?;
        let mut out = vec![];
        for _ in 0..n {
            let code = wire::base32(&crypto::random::<20>()?, 32); // 160 bits
            let h = crypto::hash(label::ACCESS_CODE, &[code.as_bytes()])?;
            c.execute(
                "INSERT INTO access_codes (hash, batch, minted_day) VALUES ($1, $2, $3)",
                &[&h.as_slice(), &batch, &self.clock.day()],
            )
            .await?;
            out.push(code);
        }
        Ok(out)
    }
}

type St = State<Arc<Anon>>;
pub(crate) type Reply = Result<axum::response::Response>;

pub(crate) fn ok<T: Serialize>(v: &T) -> Reply {
    Ok(crate::net::json(axum::http::StatusCode::OK, v))
}

pub(crate) async fn read<T: serde::de::DeserializeOwned>(body: Body, max: usize) -> Result<T> {
    wire::parse(&crate::net::body_bytes(body, max).await?)
}

async fn pass_keys(State(an): St) -> Reply {
    ok(
        &serde_json::json!({ "suite": "RSABSSA-SHA384-PSS-Randomized", "keys": an.published("pass").await? }),
    )
}

async fn post_keys(State(an): St) -> Reply {
    ok(
        &serde_json::json!({ "suite": "RSABSSA-SHA384-PSS-Randomized", "keys": an.published("post").await? }),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    code: String,
    kid: B64,
    blinded: B64,
}

/// Swap an access code for a blind signature (a retry with the same request gets it again).
async fn pass_issue(State(an): St, body: Body) -> Reply {
    let r: Issue = read(body, 16 << 10).await?;
    let code = r.code.trim().to_ascii_uppercase().replace(['-', ' '], "");
    if !wire::is_code(&code, 32) {
        return Err(Error::bad(
            "code_invalid",
            "That access code isn't valid. Check it and try again.",
        ));
    }
    let (kid, sk) = an.issuing("pass").await?;
    if !crypto::ct_eq(&kid, &r.kid) {
        return Err(Error::conflict(
            "key_changed",
            "The pass key changed. Try again.",
        ));
    }
    let h = crypto::hash(label::ACCESS_CODE, &[code.as_bytes()])?;
    let bh = crypto::sha3_512(&r.blinded);
    let mut c = an.db.conn().await?;
    let tx = c.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT used_day, blinded_hash, kid FROM access_codes WHERE hash = $1 FOR UPDATE",
            &[&h.as_slice()],
        )
        .await?
        .ok_or_else(|| {
            Error::forbidden(
                "code_unknown",
                "This access code wasn't issued by this server.",
            )
        })?;
    let used: Option<String> = row.get(0);
    if used.is_some() {
        let same = row
            .get::<_, Option<Vec<u8>>>(1)
            .is_some_and(|b| crypto::ct_eq(&b, &bh))
            && row.get::<_, Option<Vec<u8>>>(2).is_some_and(|k| k == kid);
        if !same {
            return Err(Error::conflict(
                "code_used",
                "This access code has already been used.",
            ));
        }
    } else {
        tx.execute(
            "UPDATE access_codes SET used_day = $2, blinded_hash = $3, kid = $4 WHERE hash = $1",
            &[&h.as_slice(), &an.clock.day(), &bh.as_slice(), &kid],
        )
        .await?;
        an.count(&tx, "passes", 1).await?;
    }
    let sig = sk.blind_sign(&r.blinded)?;
    tx.commit().await?;
    ok(&serde_json::json!({ "kid": B64(kid), "blind_sig": B64(sig) }))
}

/// Spend a pass; the `spent` statement is what core needs to register an account.
async fn pass_spend(State(an): St, body: Body) -> Reply {
    let t: a::Token = read(body, 16 << 10).await?;
    let mut c = an.db.conn().await?;
    let tx = c.transaction().await?;
    let id = an.spend(&tx, "pass", &t).await?;
    tx.commit().await?;
    let st = crate::statement::sign(
        an.hsm.as_ref(),
        KeyRef::AnonStatement,
        "spent",
        an.now(),
        &a::SpentFacts {
            spent: B64(id),
            day: an.clock.day(),
        },
    )?;
    ok(&serde_json::json!({ "spent": st }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostTokensReq {
    /// Core's `live-check` statement.
    statement: B64,
    /// The exact JSON body the holder signed (`{action, blinded}`).
    signed_body: B64,
    kid: B64,
}

/// Blind-sign post tokens: only against core's statement that a live check approved
/// exactly these blinded values, once per check (M1).
async fn post_tokens(State(an): St, body: Body) -> Reply {
    let r: PostTokensReq = read(body, 256 << 10).await?;
    let p = &an.policy.policy;
    let f: a::LiveCheckFacts =
        crate::statement::verify(&p.core_key()?, &r.statement, "live-check", an.now())?;
    if f.action != "post-tokens" || !crypto::ct_eq(&f.body_hash, &crypto::sha3_512(&r.signed_body))
    {
        return Err(Error::forbidden(
            "not_vouched",
            "The live check approved something else.",
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct What {
        action: String,
        blinded: Vec<B64>,
    }
    let w: What = wire::parse(&r.signed_body)?;
    if w.action != "post-tokens"
        || w.blinded.is_empty()
        || w.blinded.len() > p.messaging.post_tokens_per_check as usize
    {
        return Err(Error::bad(
            "bad_request",
            "One live check buys 1 to the policy's number of post tokens.",
        ));
    }
    let (kid, sk) = an.issuing("post").await?;
    if !crypto::ct_eq(&kid, &r.kid) {
        return Err(Error::conflict(
            "key_changed",
            "The post-token key changed. Try again.",
        ));
    }
    let mut c = an.db.conn().await?;
    let tx = c.transaction().await?;
    let n = tx
        .execute("INSERT INTO used_checks (proof_hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&f.proof_hash.0, &(an.now() + 10 * ms::MINUTE)])
        .await?;
    if n != 1 {
        return Err(Error::forbidden(
            "step_up_used",
            "That live check already bought its tokens.",
        ));
    }
    let sigs = w
        .blinded
        .iter()
        .map(|b| sk.blind_sign(b).map(B64))
        .collect::<Result<Vec<_>>>()?;
    an.count(&tx, "post_tokens", i64::try_from(sigs.len()).unwrap_or(0))
        .await?;
    tx.commit().await?;
    ok(&serde_json::json!({ "kid": B64(kid), "blind_sigs": sigs }))
}

/// Live stamps: stubbed until stamp v2.
async fn stamps() -> Reply {
    Err(Error::NotImplemented {
        what: "live stamps",
        waiting_on: "stamp v2 (partially blind RSA with epoch metadata)",
    })
}
