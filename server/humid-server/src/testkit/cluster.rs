//! An in-process cluster for integration tests: core, keys and anon on real internal TLS
//! listeners (SecP384r1MLKEM1024, ML-DSA-87 certificates from a fresh CA), each with its own
//! software HSM and its own Postgres schema, and a signed development policy.
//!
//! Tests call core and anon **as front would** (front's certificate), and can also call keys
//! **as core would** or **as front would**, to prove what each unit refuses.

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::anon::Anon;
use crate::core::Core;
use crate::crypto::DualPublic;
use crate::db::{self, Db};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef, SoftHsm};
use crate::keys::Keys;
use crate::net::{self, UnitClient};
use crate::policy::{self, Policy, SignedPolicy};
use crate::tls::{DevCa, Identity};
use crate::unit::{Clock, Role};
use crate::wire::B64;

/// A running cluster.
pub struct Cluster {
    /// The shared manual clock (start: 1 Jan 2027).
    pub clock: Clock,
    /// The CA.
    pub ca: DevCa,
    /// Core.
    pub core: Arc<Core>,
    /// Keys.
    pub keys: Arc<Keys>,
    /// Anon.
    pub anon: Arc<Anon>,
    /// Core's HSM (tests sign statements "as core" with it, and forge with others).
    pub core_hsm: Arc<SoftHsm>,
    /// The policy.
    pub policy: Arc<SignedPolicy>,
    /// Front's client to core.
    pub to_core: UnitClient,
    /// Front's client to anon.
    pub to_anon: UnitClient,
    /// Core's client to keys.
    pub core_to_keys: UnitClient,
    /// Front's certificate pointed at keys (keys must refuse the connection).
    pub front_to_keys: UnitClient,
    /// Front's identity.
    pub front_identity: Identity,
    schemas: Vec<String>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// 1 Jan 2027, 00:00 UTC.
pub const T0: i64 = 1_798_761_600_000;

impl Cluster {
    /// Start one, with `tweak` applied to the development policy.
    ///
    /// # Errors
    /// Postgres unreachable, or a unit fails to start.
    pub async fn start(tweak: impl FnOnce(&mut Policy)) -> Result<Self> {
        let clock = Clock::manual(T0);
        let ca = DevCa::new()?;
        let root = SoftHsm::ephemeral()?;
        let core_hsm = Arc::new(SoftHsm::ephemeral()?);
        let keys_hsm = Arc::new(SoftHsm::ephemeral()?);
        let anon_hsm = Arc::new(SoftHsm::ephemeral()?);
        let mut p = policy::development(
            1,
            T0,
            policy::unit_keys_from(core_hsm.as_ref(), keys_hsm.as_ref(), anon_hsm.as_ref())?,
        );
        tweak(&mut p);
        let bytes = serde_json::to_vec(&p).map_err(|e| Error::internal(e.to_string()))?;
        let sig = policy::sign(&root, &bytes)?;
        let rk: DualPublic = root.dual_public(KeyRef::IdentityRoot)?;
        let signed = Arc::new(policy::verify(&bytes, &sig, &rk, T0)?);

        let (core_db, s1) = db::test::fresh("core").await?;
        let (keys_db, s2) = db::test::fresh("keys").await?;
        let (anon_db, s3) = db::test::fresh("anon").await?;
        core_db.migrate("core", crate::core::MIGRATIONS).await?;
        keys_db.migrate("keys", crate::keys::MIGRATIONS).await?;
        anon_db.migrate("anon", crate::anon::MIGRATIONS).await?;

        let id_core = ca.issue(Role::Core)?;
        let id_keys = ca.issue(Role::Keys)?;
        let id_anon = ca.issue(Role::Anon)?;
        let id_front = ca.issue(Role::Front)?;
        let any = "127.0.0.1:0".parse().map_err(|_| Error::internal("addr"))?;

        let kem = crate::crypto::KemSecret::generate()?;
        let keys = Keys::new(
            keys_db,
            keys_hsm.clone(),
            signed.clone(),
            clock.clone(),
            kem,
        )
        .await?;
        let (keys_addr, t1) = net::spawn(
            any,
            id_keys.server_config()?,
            keys.router(),
            Role::Keys.callers(),
            false,
        )
        .await?;
        let core_to_keys = UnitClient::new(&id_core, Role::Keys, &format!("https://{keys_addr}"))?;
        let front_to_keys =
            UnitClient::new(&id_front, Role::Keys, &format!("https://{keys_addr}"))?;

        let core = Core::new(
            core_db,
            core_hsm.clone(),
            signed.clone(),
            clock.clone(),
            core_to_keys.clone(),
        );
        let (core_addr, t2) = net::spawn(
            any,
            id_core.server_config()?,
            core.router(),
            Role::Core.callers(),
            false,
        )
        .await?;
        let anon = Anon::new(
            anon_db,
            anon_hsm.clone(),
            signed.clone(),
            clock.clone(),
            2048,
        )
        .await?;
        let (anon_addr, t3) = net::spawn(
            any,
            id_anon.server_config()?,
            anon.router(),
            Role::Anon.callers(),
            false,
        )
        .await?;

        Ok(Self {
            to_core: UnitClient::new(&id_front, Role::Core, &format!("https://{core_addr}"))?,
            to_anon: UnitClient::new(&id_front, Role::Anon, &format!("https://{anon_addr}"))?,
            core_to_keys,
            front_to_keys,
            front_identity: id_front,
            clock,
            ca,
            core,
            keys,
            anon,
            core_hsm,
            policy: signed,
            schemas: vec![s1, s2, s3],
            tasks: vec![t1, t2, t3],
        })
    }

    /// Drop the test schemas.
    ///
    /// # Errors
    /// Postgres unreachable.
    pub async fn stop(self) -> Result<()> {
        for t in &self.tasks {
            t.abort();
        }
        for s in &self.schemas {
            db::test::drop_schema(s).await?;
        }
        Ok(())
    }

    /// Core's database (for assertions).
    #[must_use]
    pub fn core_db(&self) -> &Db {
        &self.core.db
    }
}

/// Rows in one of the keys unit's tables (assertions only).
///
/// # Panics
/// Database failure (tests only).
pub async fn keys_count(c: &Cluster, table: &str) -> i64 {
    c.keys.count_rows(table).await.expect("count")
}

/// A test client that sits where front sits: it carries the HTP transcript and the session
/// token as headers, as front will once HTP/2 lands.
pub struct App<'a> {
    /// The cluster.
    pub c: &'a Cluster,
    /// The HTP transcript hash of this "session".
    pub th: Vec<u8>,
    /// The session token, once signed in.
    pub token: Option<Vec<u8>>,
    /// Unused step-up nonces.
    pub nonces: Vec<Vec<u8>>,
    /// The client network front would report.
    pub net: String,
    seq: u64,
}

impl<'a> App<'a> {
    /// A fresh HTP "session".
    ///
    /// # Errors
    /// Generator failure.
    pub fn new(c: &'a Cluster) -> Result<Self> {
        Ok(Self {
            c,
            th: crate::crypto::random::<64>()?.to_vec(),
            token: None,
            nonces: vec![],
            net: "v4:192.0.2.1".into(),
            seq: 0,
        })
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            (crate::api::headers::TH.to_string(), B64::encode(&self.th)),
            (net::CLIENT_NET.to_string(), self.net.clone()),
        ];
        if let Some(t) = &self.token {
            h.push((
                crate::api::headers::AUTHORIZATION.to_string(),
                format!("Session {}", B64::encode(t)),
            ));
        }
        h
    }

    /// Call core.
    ///
    /// # Errors
    /// Core's refusal.
    pub async fn core<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let h = self.headers();
        let hr: Vec<(&str, &str)> = h.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let bytes = if method == "GET" {
            vec![]
        } else {
            serde_json::to_vec(body).map_err(|e| Error::internal(e.to_string()))?
        };
        let (status, out) = self.c.to_core.raw(method, path, &hr, bytes).await?;
        net::decode(status, &out)
    }

    /// Call core, raw bytes back (chunks).
    ///
    /// # Errors
    /// Unreachable.
    pub async fn core_raw(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Result<(u16, bytes::Bytes)> {
        let h = self.headers();
        let mut hr: Vec<(&str, &str)> = h.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        hr.extend_from_slice(extra);
        self.c.to_core.raw(method, path, &hr, vec![]).await
    }

    /// Call anon.
    ///
    /// # Errors
    /// Anon's refusal.
    pub async fn anon<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let bytes = if method == "GET" {
            vec![]
        } else {
            serde_json::to_vec(body).map_err(|e| Error::internal(e.to_string()))?
        };
        let (status, out) = self.c.to_anon.raw(method, path, &[], bytes).await?;
        net::decode(status, &out)
    }

    /// Register `phone` as a new account and sign in.
    ///
    /// # Errors
    /// Any refusal.
    pub async fn register(&mut self, phone: &super::Phone) -> Result<()> {
        let kem = phone.account_kem.public().to_bytes();
        let body = serde_json::json!({
            "account_vk": B64(phone.account.public().to_bytes()),
            "kem_pk": B64(kem),
            "pop": phone.register_pop(&self.th)?,
            "enrolment": phone.enrolment(&self.th)?,
        });
        let _: serde_json::Value = self.core("POST", "/v1/auth/register", &body).await?;
        self.login(phone, 0).await
    }

    /// Sign in (duress = 1 for the duress gesture).
    ///
    /// # Errors
    /// Any refusal.
    pub async fn login(&mut self, phone: &super::Phone, duress: u8) -> Result<()> {
        let ch: serde_json::Value = self
            .core(
                "POST",
                "/v1/auth/challenge",
                &serde_json::json!({ "account": phone.account_id(), "device": phone.device_id() }),
            )
            .await?;
        let ch = B64::decode(ch["challenge"].as_str().unwrap_or_default())?;
        let l = phone.login(&self.th, &ch, duress)?;
        let r: crate::core::auth::LoginReply = self.core("POST", "/v1/auth/login", &l).await?;
        self.token = Some(r.token.0);
        self.nonces = r.nonces.into_iter().map(|n| n.0).collect();
        Ok(())
    }

    /// A step-up from `phone` for `method path` over `body`, using a pool nonce.
    ///
    /// # Errors
    /// No nonce left; signing failure.
    pub fn sign(
        &mut self,
        phone: &super::Phone,
        method: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<crate::proofs::Signed> {
        let nonce = self
            .nonces
            .pop()
            .ok_or_else(|| Error::internal("no nonce left in the test pool"))?;
        self.seq += 1;
        let b = serde_json::to_vec(body).map_err(|e| Error::internal(e.to_string()))?;
        phone.step_up(
            method,
            path,
            &self.th,
            self.seq,
            &nonce,
            self.c.clock.now(),
            &b,
        )
    }

    /// Top the nonce pool up.
    ///
    /// # Errors
    /// Core's refusal.
    pub async fn refill(&mut self) -> Result<()> {
        let r: serde_json::Value = self
            .core("POST", "/v1/auth/nonces", &serde_json::json!({}))
            .await?;
        self.nonces = r["nonces"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| n.as_str())
            .filter_map(|s| B64::decode(s).ok())
            .collect();
        Ok(())
    }
}
