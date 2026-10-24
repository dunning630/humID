//! An in-process cluster for integration tests: core, keys and anon on real internal TLS
//! listeners (SecP384r1MLKEM1024, ML-DSA-87 certificates from a fresh CA), each with its own
//! software HSM and its own Postgres schema, and a signed development policy.
//!
//! A real front runs on an outer TLS listener in front of them, and the simulated phone ([`App`])
//! talks to it the way the app will: HTP/2 through `crates/humid-link`, so every flow test
//! runs over the real protocol end to end (handshake to the certified KEM key, records,
//! chunks, the nonce pool). Tests can also call units directly **as front would** (front's
//! certificate: only `/htp/v2/*`, `/tlog/*` and health answer it) and keys **as core would**,
//! to prove what each unit refuses.

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
    /// The identity root's public key (what apps pin).
    pub root: DualPublic,
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
    /// Front's outer (public) address.
    pub front_addr: std::net::SocketAddr,
    /// Core's HTP/2 endpoint.
    pub core_htp: Arc<crate::htp::Endpoint>,
    /// Anon's HTP/2 endpoint.
    pub anon_htp: Arc<crate::htp::Endpoint>,
    /// What a front in the attacker's hands sees and does to calls (see [`Tap`]).
    pub tap: Arc<Tap>,
    /// Requests anon's router saw with a client-network header (review #97 L-2: none).
    anon_net: Arc<std::sync::atomic::AtomicUsize>,
    /// The test attestation PKI core trusts besides the vendors' roots (development policy
    /// only: a production core refuses it, `test_root_in_production`).
    pub pki: Arc<humid_attest::testkit::TestPki>,
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
        // every simulated phone opens its HTP/2 session from one test network at the same
        // instant of a manual clock; front's per-network handshake limit isn't what a flow
        // test probes (a test that does sets it in `tweak`)
        p.limits.handshakes_per_minute = 10_000;
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

        let pki = Arc::new(humid_attest::testkit::TestPki::new(T0));
        let core = Core::with_trust(
            core_db,
            core_hsm.clone(),
            signed.clone(),
            clock.clone(),
            core_to_keys.clone(),
            pki.trust(),
        )?;
        let htp_cfg = |unit| {
            let mut c = humid_htp::server::Config::new(unit);
            // tests move the clock by days: sessions end only when a test ends them
            c.idle_ms = u64::MAX / 4;
            c.max_age_ms = u64::MAX / 4;
            c.ticket_ms = u64::MAX / 4;
            c.answer_ms = u64::MAX / 4;
            c.assembly_idle_ms = u64::MAX / 4;
            // every simulated phone shares one test network (the testkit's front stands in
            // per-App addresses for limits, but a flow test opens many sessions at once)
            c.max_sessions_per_net = 10_000;
            c
        };
        let body_limit = crate::htp::max_body_for(&signed.policy);
        let core_htp = crate::htp::Endpoint::with_config(
            Role::Core,
            core_hsm.clone(),
            KeyRef::CoreStatement,
            clock.clone(),
            htp_cfg(humid_htp::Unit::Core),
            body_limit,
        );
        let (core_addr, t2) = net::spawn(
            any,
            id_core.server_config()?,
            crate::htp::mount(core.router(), &core_htp),
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
        let anon_net = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let anon_htp = crate::htp::Endpoint::with_config(
            Role::Anon,
            anon_hsm.clone(),
            KeyRef::AnonStatement,
            clock.clone(),
            htp_cfg(humid_htp::Unit::Anon),
            body_limit,
        );
        let (anon_addr, t3) = net::spawn(
            any,
            id_anon.server_config()?,
            {
                let seen = anon_net.clone();
                crate::htp::mount(anon.router(), &anon_htp).layer(axum::middleware::from_fn(
                    move |req: axum::extract::Request, next: axum::middleware::Next| {
                        let seen = seen.clone();
                        async move {
                            if req.headers().contains_key(net::CLIENT_NET) {
                                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            next.run(req).await
                        }
                    },
                ))
            },
            Role::Anon.callers(),
            false,
        )
        .await?;

        let to_core = UnitClient::new(&id_front, Role::Core, &format!("https://{core_addr}"))?;
        let to_anon = UnitClient::new(&id_front, Role::Anon, &format!("https://{anon_addr}"))?;
        let front = crate::front::Front::new(
            signed.clone(),
            clock.clone(),
            to_core.clone(),
            to_anon.clone(),
        );
        let tap = Arc::new(Tap::default());
        let outer = outer_config(&id_front)?;
        let (front_addr, t4) =
            net::spawn(any, outer, tap.clone().wrap(front.router()), &[], true).await?;

        Ok(Self {
            to_core,
            to_anon,
            front_addr,
            core_htp,
            anon_htp,
            tap,
            anon_net,
            pki,
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
            root: rk,
            schemas: vec![s1, s2, s3],
            tasks: vec![t1, t2, t3, t4],
        })
    }

    /// Give core a copy of Google's status list (`{"entries": …}` JSON) fetched now, as the
    /// fetcher would.
    ///
    /// # Errors
    /// Core's refusal.
    pub async fn status_list(&self, json: &str) -> Result<()> {
        crate::core::attest::store_status(&self.core, json.as_bytes(), self.clock.now()).await
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

/// How many requests anon's router has seen carrying a client network (assertions only).
#[must_use]
pub fn anon_saw_client_net(c: &Cluster) -> usize {
    c.anon_net.load(std::sync::atomic::Ordering::SeqCst)
}

/// Rows in one of the keys unit's tables (assertions only).
///
/// # Panics
/// Database failure (tests only).
pub async fn keys_count(c: &Cluster, table: &str) -> i64 {
    c.keys.count_rows(table).await.expect("count")
}

/// What front relays, seen from front: every call and every answer, in the clear as far as
/// front can see them (the bytes on its side of the outer TLS). A test can also have front
/// **change** calls (a compromised front), with [`Tap::set_mangle`].
#[derive(Default)]
pub struct Tap {
    /// `(call, answer)` bytes, in order.
    pub seen: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    mangle: std::sync::Mutex<Option<Mangle>>,
}

/// A function front applies to each call body before forwarding it.
pub type Mangle = Box<dyn Fn(&mut Vec<u8>) + Send + Sync>;

impl Tap {
    /// Have front rewrite calls (until cleared with `None`).
    pub fn set_mangle(&self, f: Option<Mangle>) {
        if let Ok(mut g) = self.mangle.lock() {
            *g = f;
        }
    }

    /// Everything front has relayed so far, calls and answers concatenated.
    #[must_use]
    pub fn all_bytes(&self) -> Vec<u8> {
        self.seen
            .lock()
            .map(|v| {
                v.iter()
                    .flat_map(|(a, b)| [a.clone(), b.clone()].concat())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn wrap(self: Arc<Self>, r: axum::Router) -> axum::Router {
        let me = self;
        r.layer(axum::middleware::from_fn(
            move |mut req: axum::extract::Request, next: axum::middleware::Next| {
                let me = me.clone();
                async move {
                    // every simulated phone connects from 127.0.0.1: stand its own address in
                    // for the socket's, as the socket would give it on a real network
                    let stand_in = req
                        .headers()
                        .get(TEST_PEER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<std::net::IpAddr>().ok());
                    if let Some(ip) = stand_in
                        && let Some(p) = req.extensions_mut().get_mut::<net::Peer>()
                    {
                        p.addr.set_ip(ip);
                    }
                    if req.uri().path() != "/htp/v2/call" {
                        return next.run(req).await;
                    }
                    let (parts, body) = req.into_parts();
                    let mut bytes = net::body_bytes(body, crate::htp::MAX_CALL)
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default();
                    if let Ok(g) = me.mangle.lock()
                        && let Some(f) = &*g
                    {
                        f(&mut bytes);
                    }
                    let call = bytes.clone();
                    let resp = next
                        .run(axum::extract::Request::from_parts(
                            parts,
                            axum::body::Body::from(bytes),
                        ))
                        .await;
                    let (rp, rb) = resp.into_parts();
                    let out = net::body_bytes(rb, 128 << 20)
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default();
                    if let Ok(mut g) = me.seen.lock() {
                        g.push((call, out.clone()));
                    }
                    axum::response::Response::from_parts(rp, axum::body::Body::from(out))
                }
            },
        ))
    }
}

/// Test-only header: the address a simulated phone stands in for (the testkit's front only).
pub const TEST_PEER: &str = "x-test-peer";

/// The address every [`App`] connects from unless a test moves it.
pub const DEFAULT_NET: &str = "v4:192.0.2.1";

/// The phone's transport: HTTPS to front's outer listener (TLS 1.3, a PQ group), the way the
/// app's platform TLS stack will reach it.
#[derive(Clone)]
pub struct OuterTransport {
    client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<bytes::Bytes>,
    >,
    base: String,
    /// The address this phone stands in for (`v4:…`), sent as [`TEST_PEER`].
    pub peer: Arc<std::sync::Mutex<String>>,
}

impl OuterTransport {
    /// A transport to `addr`, trusting `ca` for front's outer certificate.
    ///
    /// # Errors
    /// A bad CA certificate.
    pub fn new(
        addr: std::net::SocketAddr,
        ca: &rustls::pki_types::CertificateDer<'static>,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.clone())
            .map_err(|e| Error::internal(e.to_string()))?;
        let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::outer_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::internal(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(cfg)
            .https_only()
            .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(
                crate::tls::server_name(Role::Front)?,
            ))
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https);
        Ok(Self {
            client,
            base: format!("https://{addr}"),
            peer: Arc::new(std::sync::Mutex::new(DEFAULT_NET.into())),
        })
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, humid_link::NetError> {
        use http_body_util::BodyExt;
        let peer = self
            .peer
            .lock()
            .map(|p| p.trim_start_matches("v4:").to_string())
            .unwrap_or_default();
        let req = axum::http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("content-type", crate::htp::CONTENT_TYPE)
            .header(TEST_PEER, peer)
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|_| humid_link::NetError)?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|_| humid_link::NetError)?;
        let b = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| humid_link::NetError)?
            .to_bytes();
        Ok(b.to_vec())
    }
}

impl humid_link::Transport for OuterTransport {
    fn call(
        &mut self,
        body: Vec<u8>,
    ) -> impl std::future::Future<Output = std::result::Result<Vec<u8>, humid_link::NetError>> + Send
    {
        let me = self.clone();
        async move { me.send("POST", "/htp/v2/call", body).await }
    }
    fn keys(
        &mut self,
    ) -> impl std::future::Future<Output = std::result::Result<Vec<u8>, humid_link::NetError>> + Send
    {
        let me = self.clone();
        async move { me.send("GET", "/htp/v2/keys", vec![]).await }
    }
}

/// The app's link to one unit through front.
pub type Link = humid_link::Link<OuterTransport>;

fn link(c: &Cluster, unit: humid_htp::Unit, t: OuterTransport) -> Result<Link> {
    let root = humid_pq2::DualVerifyingKey::from_bytes(&c.root.to_bytes())?;
    let clock = c.clock.clone();
    Ok(humid_link::Link::new(
        unit,
        root,
        crate::htp::policy_of,
        t,
        Box::new(move || u64::try_from(clock.now()).unwrap_or(0)),
    ))
}

fn link_err(e: humid_link::LinkError) -> Error {
    match e {
        humid_link::LinkError::Offline => Error::unavailable("offline", "No network."),
        humid_link::LinkError::IdentityChanged => Error::forbidden(
            "server_identity_changed",
            "The server doesn't prove the identity this app pins.",
        ),
        humid_link::LinkError::Protocol(c) => Error::Upstream {
            status: c.http_status(),
            code: c.as_str().into(),
            message: "The secure channel refused that.".into(),
        },
        humid_link::LinkError::Unit { status, code } => Error::Upstream {
            status,
            code,
            message: String::new(),
        },
        humid_link::LinkError::NoNonce => Error::internal("no nonce left in the test pool"),
        humid_link::LinkError::PolicyRollback => Error::forbidden(
            "policy_rollback",
            "The server offered an older policy than this app accepted.",
        ),
        humid_link::LinkError::Unknown => Error::unavailable(
            "outcome_unknown",
            "The session ended before the answer came: check before trying again.",
        ),
    }
}

/// Fields every app body sends as bytes (typed parts) rather than base64 inside JSON.
const BLOBS: &[&str] = &["envelope", "sealed_share"];

/// A simulated phone's app: one HTP/2 session to core and one to anon, through front.
pub struct App<'a> {
    /// The cluster.
    pub c: &'a Cluster,
    /// The HTP/2 transcript of the core session (what sign-ins and proofs name). Tests may
    /// overwrite it to make a phone sign for another session.
    pub th: Vec<u8>,
    /// The session token, once signed in.
    pub token: Option<Vec<u8>>,
    /// Unused step-up nonces.
    pub nonces: Vec<Vec<u8>>,
    /// The network this phone connects from: front takes it from the socket, and the
    /// testkit's front stands this address in for 127.0.0.1 (IPv4 only).
    pub net: String,
    /// The session mode its proofs carry (`1` after a duress sign-in), as the phone's core does.
    pub mode: u8,
    core: tokio::sync::Mutex<Link>,
    anon: tokio::sync::Mutex<Link>,
    /// Request ids reserved for proofs made by [`App::sign`] (by proof `seq`).
    reserved: std::sync::Mutex<std::collections::BTreeMap<u64, u32>>,
    peer: Arc<std::sync::Mutex<String>>,
}

impl<'a> App<'a> {
    /// A fresh app: opens its HTP/2 session to core at once (the transcript is needed to
    /// sign anything); the anonymous session to anon opens on first use.
    ///
    /// # Errors
    /// The handshake failed.
    pub async fn new(c: &'a Cluster) -> Result<Self> {
        let t = OuterTransport::new(c.front_addr, &c.front_identity.ca)?;
        let peer = t.peer.clone();
        let mut core = link(c, humid_htp::Unit::Core, t.clone())?;
        let anon = link(c, humid_htp::Unit::Anon, t)?;
        core.connect().await.map_err(link_err)?;
        let th = core.th().ok_or_else(|| Error::internal("no session"))?;
        Ok(Self {
            c,
            th: th.to_vec(),
            token: None,
            nonces: vec![],
            net: DEFAULT_NET.into(),
            mode: 0,
            core: tokio::sync::Mutex::new(core),
            anon: tokio::sync::Mutex::new(anon),
            reserved: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            peer,
        })
    }

    /// The core session's HTP/2 session id.
    pub async fn sid(&self) -> Option<[u8; 16]> {
        self.core.lock().await.sid()
    }

    /// Lock the app and unlock it again: the core session is resumed from its ticket (a new
    /// session, the same chain transcript) and the sign-in still holds.
    ///
    /// # Errors
    /// The resumption failed.
    pub async fn relock(&self) -> Result<(usize, usize)> {
        let mut l = self.core.lock().await;
        l.lock();
        // ids reserved in the old session mean nothing in the new one
        if let Ok(mut g) = self.reserved.lock() {
            g.clear();
        }
        l.connect().await.map_err(link_err)?;
        Ok((l.handshakes(), l.resumptions()))
    }

    /// Send one request through the link: a JSON body is split into typed parts (a top-level
    /// `signed` becomes the binary proof, the [`BLOBS`] fields bytes; the rest stays JSON).
    async fn send(
        &self,
        unit: humid_htp::Unit,
        method: &str,
        path: &str,
        v: Option<&serde_json::Value>,
        extra: &[(humid_htp::msg::HeaderName, &[u8])],
    ) -> Result<(u16, Vec<u8>)> {
        let m = humid_htp::msg::Method::parse(method).ok_or_else(|| Error::internal("method"))?;
        if let Ok(mut p) = self.peer.lock() {
            p.clone_from(&self.net);
        }
        let mut l = match unit {
            humid_htp::Unit::Core => self.core.lock().await,
            humid_htp::Unit::Anon => self.anon.lock().await,
        };
        let mut h: Vec<(humid_htp::msg::HeaderName, &[u8])> = extra.to_vec();
        if unit == humid_htp::Unit::Core
            && let Some(t) = &self.token
        {
            h.push((humid_htp::msg::HeaderName::Session, t.as_slice()));
        }
        let (rid, owned) = match v {
            Some(v) => humid_link_body::split(self, v)?,
            None => (None, humid_link_body::Owned::default()),
        };
        let blobs: Vec<(&str, &[u8])> = owned
            .blobs
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let body = if owned.parts {
            humid_link::Body::Parts {
                proof: owned.proof,
                json: &owned.json,
                blobs: &blobs,
            }
        } else {
            humid_link::Body::Raw(&owned.json)
        };
        let r = l.call(rid, m, path, body, &h).await.map_err(link_err)?;
        Ok((r.status, r.body.to_vec()))
    }

    /// Call core through HTP/2.
    ///
    /// # Errors
    /// Core's refusal, or the channel's.
    pub async fn core<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let v = serde_json::to_value(body).map_err(|e| Error::internal(e.to_string()))?;
        let v = (method != "GET").then_some(&v);
        let (status, out) = self
            .send(humid_htp::Unit::Core, method, path, v, &[])
            .await?;
        net::decode(status, &out)
    }

    /// Call core through HTP/2, raw bytes back (chunks). `extra` may carry the download
    /// ticket as `("x-humid-ticket", base64url)`.
    ///
    /// # Errors
    /// The channel's refusal.
    pub async fn core_raw(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Result<(u16, bytes::Bytes)> {
        let mut h = vec![];
        let mut keep = vec![];
        for (k, v) in extra {
            if *k == crate::api::headers::TICKET {
                keep.push(B64::decode(v).unwrap_or_else(|_| vec![0]));
            }
        }
        for t in &keep {
            h.push((humid_htp::msg::HeaderName::DownloadTicket, t.as_slice()));
        }
        let (status, out) = self
            .send(humid_htp::Unit::Core, method, path, None, &h)
            .await?;
        Ok((status, bytes::Bytes::from(out)))
    }

    /// Call anon through the anonymous HTP/2 session.
    ///
    /// # Errors
    /// Anon's refusal.
    pub async fn anon<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let v = serde_json::to_value(body).map_err(|e| Error::internal(e.to_string()))?;
        let v = (method != "GET").then_some(&v);
        let (status, out) = self
            .send(humid_htp::Unit::Anon, method, path, v, &[])
            .await?;
        net::decode(status, &out)
    }

    /// Call anon, raw bytes back (fixed-size ticks).
    ///
    /// # Errors
    /// The channel's refusal.
    pub async fn anon_raw<T: Serialize + ?Sized>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<(u16, Vec<u8>)> {
        let v = serde_json::to_value(body).map_err(|e| Error::internal(e.to_string()))?;
        self.send(humid_htp::Unit::Anon, method, path, Some(&v), &[])
            .await
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
        self.mode = duress;
        Ok(())
    }

    /// A step-up from `phone` for `method path` over `body`, using a pool nonce. Its `seq`
    /// names the request id reserved for it in this app's core session.
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
        // tests make one call at a time, so the link is free here
        let st = self
            .core
            .try_lock()
            .map_err(|_| Error::internal("the app is busy"))?
            .reserve()
            .map_err(link_err)?;
        if let Ok(mut g) = self.reserved.lock() {
            g.insert(st.seq, st.rid);
        }
        let b = serde_json::to_vec(body).map_err(|e| Error::internal(e.to_string()))?;
        phone.step_up_mode(
            method,
            path,
            &self.th,
            st.seq,
            &nonce,
            self.c.clock.now(),
            &b,
            self.mode,
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

/// Turning a test's JSON body into what the app sends.
mod humid_link_body {
    use super::{App, B64, BLOBS, Error, Result};

    /// An owned typed body.
    #[derive(Default)]
    pub struct Owned {
        pub parts: bool,
        pub proof: Option<Box<humid_htp::parts::Proof>>,
        pub json: Vec<u8>,
        pub blobs: Vec<(String, Vec<u8>)>,
    }

    pub fn split(app: &App<'_>, v: &serde_json::Value) -> Result<(Option<u32>, Owned)> {
        let Some(obj) = v.as_object() else {
            return Ok((
                None,
                Owned {
                    json: serde_json::to_vec(v).map_err(|e| Error::internal(e.to_string()))?,
                    ..Owned::default()
                },
            ));
        };
        let mut obj = obj.clone();
        let mut out = Owned::default();
        let mut rid = None;
        if let Some(s) = obj.remove("signed") {
            let s: crate::proofs::Signed =
                serde_json::from_value(s).map_err(|e| Error::bad("bad_json", e.to_string()))?;
            let fixed =
                |b: &[u8], n: usize| -> Option<Vec<u8>> { (b.len() == n).then(|| b.to_vec()) };
            let (Some(th), Some(nonce)) = (fixed(&s.proof.th, 64), fixed(&s.proof.nonce, 32))
            else {
                // a malformed proof can't be sent as binary: let the unit see it as JSON
                obj.insert(
                    "signed".into(),
                    serde_json::to_value(&s).map_err(|e| Error::internal(e.to_string()))?,
                );
                return Ok((
                    None,
                    Owned {
                        json: serde_json::to_vec(&obj)
                            .map_err(|e| Error::internal(e.to_string()))?,
                        ..Owned::default()
                    },
                ));
            };
            let mut th_a = [0u8; 64];
            th_a.copy_from_slice(&th);
            let mut n_a = [0u8; 32];
            n_a.copy_from_slice(&nonce);
            // the request id this proof's seq was reserved under, if it is this app's own
            // and still unsent; otherwise (a replayed or foreign proof) a fresh request
            if let Ok(mut g) = app.reserved.lock()
                && let Some(r) = g.remove(&s.proof.seq)
            {
                rid = Some(r);
            }
            out.proof = Some(Box::new(humid_htp::parts::Proof {
                method: s.proof.method,
                path: s.proof.path,
                th: th_a,
                seq: s.proof.seq,
                device: s.proof.device.0,
                nonce: n_a,
                at: u64::try_from(s.proof.at).unwrap_or(0),
                mode: s.proof.mode,
                device_sig: s.proof.device_sig.0,
                live_p256: s.proof.live_p256.0,
                live_mldsa: s.proof.live_mldsa.map(|b| b.0),
                body: s.body.0,
                app_attest: s.proof.app_attest.map(|b| b.0),
            }));
            out.parts = true;
        }
        for name in BLOBS {
            if let Some(serde_json::Value::String(t)) = obj.get(*name) {
                let b = B64::decode(t)?;
                obj.remove(*name);
                out.blobs.push(((*name).to_string(), b));
                out.parts = true;
            }
        }
        out.json = serde_json::to_vec(&serde_json::Value::Object(obj))
            .map_err(|e| Error::internal(e.to_string()))?;
        Ok((rid, out))
    }
}

fn outer_config(id: &Identity) -> Result<Arc<rustls::ServerConfig>> {
    let cfg = rustls::ServerConfig::builder_with_provider(crate::tls::outer_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::internal(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            id.chain.clone(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(id.key.clone_key()),
        )
        .map_err(|e| Error::internal(e.to_string()))?;
    Ok(Arc::new(cfg))
}
