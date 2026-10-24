//! HTP/2 inside the unit that acts on the request (docs/v5/HTP2.md §7).
//!
//! Core and anon each run one [`Endpoint`]: front forwards `POST /htp/v2/call` to it over
//! internal TLS without being able to read or change what's inside, and the endpoint
//! dispatches each authenticated request to the unit's own routes **in-process**. The unit's
//! app routes (`/v1/…`) answer only such dispatched requests: over the network, front (or
//! anyone holding its certificate) reaches only `/htp/v2/*`, `/tlog/*` and `/healthz`, so it
//! can no longer name a session transcript, add a session token or swap a body.
//!
//! What the endpoint adds to a dispatched request, from the HTP/2 session itself:
//! `x-humid-th` (the chain transcript sign-ins and proofs are bound to), `authorization`
//! from the typed session header, `x-humid-ticket`, and the client network front reported.
//! Typed bodies become the JSON the unit already reads: binary fields as base64url, the live
//! proof as `signed`. A proof made in this session must name this request's `seq`.

use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use humid_htp::msg::{Encoding, HeaderName, RequestHead};
use humid_htp::parts::{self, Part};
use humid_htp::server::{Config, Ready, Server};
use humid_htp::{Code, Unit};
use serde::Deserialize;
use tower::ServiceExt;

use crate::api::headers;
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::net::CLIENT_NET;
use crate::proofs::{Signed, StepUp};
use crate::unit::{Clock, Role, ms};
use crate::wire::{B64, Id};

/// Largest call body a unit (or front) reads: a client batches up to 8 MiB of chunks.
pub const MAX_CALL: usize = 9 << 20;
/// A KEM certificate is valid this long; the key rotates halfway through.
pub const CERT_MS: i64 = 24 * ms::HOUR;
/// Content type of HTP/2 calls and answers.
pub const CONTENT_TYPE: &str = "application/vnd.humid.htp2";

/// A request that came in through the endpoint (only the endpoint inserts it).
#[derive(Clone, Copy, Debug)]
pub struct Dispatched;

/// One unit's HTP/2 endpoint.
pub struct Endpoint {
    unit: Unit,
    role: Role,
    hsm: Arc<dyn Hsm>,
    key: KeyRef,
    clock: Clock,
    server: Mutex<Option<Server>>,
    router: OnceLock<Router>,
}

fn now_u64(c: &Clock) -> u64 {
    u64::try_from(c.now()).unwrap_or(0)
}

fn code_err(c: Code) -> Error {
    Error::Upstream {
        status: c.http_status(),
        code: c.as_str().into(),
        message: "The secure channel refused that.".into(),
    }
}

impl Endpoint {
    /// The endpoint of `role` (core or anon), certifying its KEM keys with `key` in `hsm`.
    #[must_use]
    pub fn new(role: Role, hsm: Arc<dyn Hsm>, key: KeyRef, clock: Clock) -> Arc<Self> {
        let unit = if role == Role::Anon {
            Unit::Anon
        } else {
            Unit::Core
        };
        Self::with_config(role, hsm, key, clock, Config::new(unit))
    }

    /// As [`Endpoint::new`] with other limits (tests stretch session lifetimes so a test can
    /// move its clock by days).
    #[must_use]
    pub fn with_config(
        role: Role,
        hsm: Arc<dyn Hsm>,
        key: KeyRef,
        clock: Clock,
        cfg: Config,
    ) -> Arc<Self> {
        let unit = cfg.unit;
        Arc::new(Self {
            unit,
            role,
            hsm,
            key,
            clock,
            server: Mutex::new(Server::new(cfg).ok()),
            router: OnceLock::new(),
        })
    }

    /// Run `f` on the protocol state, creating it and rotating its KEM key as needed.
    fn with<R>(&self, f: impl FnOnce(&mut Server, u64) -> R) -> Result<R> {
        let now = self.clock.now();
        let mut g = self
            .server
            .lock()
            .map_err(|_| Error::internal("htp state poisoned"))?;
        if g.is_none() {
            *g = Some(Server::new(Config::new(self.unit)).map_err(code_err)?);
        }
        let s = g.as_mut().ok_or_else(|| Error::internal("htp state"))?;
        let due = s
            .current_cert()
            .is_none_or(|(_, until)| i64::try_from(until).unwrap_or(0) - now < CERT_MS / 2);
        if due {
            let nb = u64::try_from(now - 5 * ms::MINUTE).unwrap_or(0);
            let na = u64::try_from(now + CERT_MS).unwrap_or(0);
            let pk = Server::prepare_key(nb, na).map_err(code_err)?;
            let sig = self.hsm.mldsa_sign(
                self.key,
                humid_htp::label::KEM_CERT,
                &pk.to_be_signed(self.unit),
            )?;
            s.install_key(pk, &sig).map_err(code_err)?;
            tracing::info!(unit = self.role.as_str(), "HTP/2 KEM key rotated");
        }
        Ok(f(s, now_u64(&self.clock)))
    }

    /// The current KEM certificate (front puts it in the key bundle).
    ///
    /// # Errors
    /// HSM failure.
    pub fn cert(&self) -> Result<Vec<u8>> {
        self.with(|s, _| s.current_cert().map(|(c, _)| c.to_vec()))?
            .ok_or_else(|| Error::internal("no KEM certificate"))
    }

    /// Live HTP/2 sessions (tests, metrics).
    ///
    /// # Errors
    /// Never in practice.
    pub fn sessions(&self) -> Result<usize> {
        self.with(|s, _| s.session_count())
    }

    /// Drop expired sessions.
    pub fn tick(&self) {
        let _ = self.with(|s, now| s.tick(now));
    }

    /// One call: open, dispatch every complete request to the unit, answer.
    async fn call(&self, net: &str, body: &[u8]) -> Result<Vec<u8>> {
        let r = self.with(|s, now| s.receive(body, now))?;
        let mut out = r.frames;
        for ready in r.ready {
            let rid = ready.head.rid;
            let sid = ready.sid;
            let answer = match self.check(&ready) {
                Ok(()) => match self.dispatch(ready, net).await {
                    Ok((status, ctype, bytes)) => {
                        self.with(|s, now| s.respond(&sid, rid, status, ctype, &bytes, now))?
                    }
                    Err(c) => self.with(|s, _| s.refuse(&sid, rid, c))?,
                },
                Err(c) => self.with(|s, _| s.refuse(&sid, rid, c))?,
            };
            match answer {
                Ok(frames) => out.extend_from_slice(&frames),
                Err(c) => tracing::debug!(code = c.as_str(), "an answer couldn't be sealed"),
            }
        }
        Ok(out)
    }

    /// The route allow-list and the session rule, before the unit sees anything.
    fn check(&self, r: &Ready) -> std::result::Result<(), Code> {
        use crate::front::routes::{Auth, resolve};
        let route = resolve(r.head.method.as_str(), &r.head.path).ok_or(Code::RouteNotFound)?;
        if route.unit != self.role {
            return Err(Code::RouteNotFound);
        }
        if route.auth == Auth::NeverSignedIn && r.head.header(HeaderName::Session).is_some() {
            return Err(Code::AuthNotAllowed);
        }
        Ok(())
    }

    async fn dispatch(&self, r: Ready, net: &str) -> std::result::Result<(u16, u8, Vec<u8>), Code> {
        let router = self.router.get().ok_or(Code::Internal)?.clone();
        let body = unit_body(&r.head, &r.body, &r.th)?;
        let mut b = Request::builder()
            .method(r.head.method.as_str())
            .uri(&r.head.path)
            .header(headers::TH, B64::encode(&r.th))
            .header(CLIENT_NET, net)
            .header("content-type", "application/json");
        if let Some(t) = r.head.header(HeaderName::Session) {
            b = b.header(
                headers::AUTHORIZATION,
                format!("Session {}", B64::encode(t)),
            );
        }
        if let Some(t) = r.head.header(HeaderName::DownloadTicket) {
            b = b.header(headers::TICKET, B64::encode(t));
        }
        let mut req = b.body(Body::from(body)).map_err(|_| Code::BadFrame)?;
        req.extensions_mut().insert(Dispatched);
        let resp = router.oneshot(req).await.map_err(|_| Code::Internal)?;
        let status = resp.status().as_u16();
        let ctype = u8::from(
            resp.headers()
                .get("content-type")
                .is_some_and(|v| v.as_bytes() == b"application/octet-stream"),
        );
        let max = usize::try_from(humid_htp::MAX_RESPONSE).unwrap_or(usize::MAX);
        let bytes = crate::net::body_bytes(resp.into_body(), max)
            .await
            .map_err(|_| Code::TooLarge)?;
        Ok((status, ctype, bytes.to_vec()))
    }
}

#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    signed: Option<serde::de::IgnoredAny>,
}

/// The JSON body the unit reads. A raw body passes as is, except that a live proof travels
/// only as a typed part (so the endpoint can check its `seq`): raw JSON with a top-level
/// `signed` is refused.
fn unit_body(head: &RequestHead, body: &[u8], th: &[u8; 64]) -> std::result::Result<Vec<u8>, Code> {
    let _ = th;
    match head.enc {
        Encoding::Raw => {
            if serde_json::from_slice::<Probe>(body).is_ok_and(|p| p.signed.is_some()) {
                return Err(Code::BadFrame);
            }
            Ok(body.to_vec())
        }
        Encoding::Parts => {
            let ps = parts::decode(body)?;
            let mut obj = serde_json::Map::new();
            for p in &ps {
                if let Part::Json(j) = p {
                    match serde_json::from_slice(j) {
                        Ok(serde_json::Value::Object(m)) => obj = m,
                        _ => return Err(Code::BadFrame),
                    }
                }
            }
            for p in ps {
                let (k, v) = match p {
                    Part::Json(_) => continue,
                    Part::Bytes(n, b) => (n, serde_json::Value::String(B64::encode(&b))),
                    Part::Proof(p) => {
                        let s = Signed {
                            proof: StepUp {
                                method: p.method,
                                path: p.path,
                                th: B64(p.th.to_vec()),
                                seq: p.seq,
                                device: Id(p.device),
                                nonce: B64(p.nonce.to_vec()),
                                at: i64::try_from(p.at).map_err(|_| Code::BadFrame)?,
                                device_sig: B64(p.device_sig),
                                live_p256: B64(p.live_p256),
                                live_mldsa: p.live_mldsa.map(B64),
                            },
                            body: B64(p.body),
                        };
                        (
                            "signed".to_string(),
                            serde_json::to_value(&s).map_err(|_| Code::Internal)?,
                        )
                    }
                };
                if obj.insert(k, v).is_some() {
                    return Err(Code::BadFrame);
                }
            }
            serde_json::to_vec(&serde_json::Value::Object(obj)).map_err(|_| Code::Internal)
        }
    }
}

type St = State<Arc<Endpoint>>;

async fn call(State(ep): St, headers: HeaderMap, body: Body) -> Result<Response> {
    let net = headers
        .get(CLIENT_NET)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 64)
        .unwrap_or("unknown")
        .to_string();
    let body = crate::net::body_bytes(body, MAX_CALL).await?;
    let out = ep.call(&net, &body).await?;
    Ok((StatusCode::OK, [("content-type", CONTENT_TYPE)], out).into_response())
}

async fn cert(State(ep): St) -> Result<Response> {
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        ep.cert()?,
    )
        .into_response())
}

async fn gate(req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/v1/") && req.extensions().get::<Dispatched>().is_none() {
        return Error::not_found("not_found", "No such route.").into_response();
    }
    next.run(req).await
}

/// The unit's network router: its own routes, reachable for `/v1/…` only through the HTP/2
/// endpoint, plus `POST /htp/v2/call` and `GET /htp/v2/cert`.
pub fn mount(app: Router, ep: &Arc<Endpoint>) -> Router {
    let full = app
        .merge(
            Router::new()
                .route("/htp/v2/call", post(call))
                .route("/htp/v2/cert", get(cert))
                .with_state(ep.clone()),
        )
        .layer(axum::middleware::from_fn(gate));
    let _ = ep.router.set(full.clone());
    full
}

/// Drop expired sessions once a minute (and rotate the KEM key when due).
pub fn spawn_ticks(ep: Arc<Endpoint>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            t.tick().await;
            ep.tick();
        }
    });
}

/// The statement key the signed policy names for `unit` (what the app does with the bundle).
#[must_use]
pub fn statement_key_of(policy: &[u8], unit: Unit) -> Option<Vec<u8>> {
    let p: crate::policy::Policy = serde_json::from_slice(policy).ok()?;
    Some(match unit {
        Unit::Core => p.unit_keys.core.0,
        Unit::Anon => p.unit_keys.anon.0,
    })
}
