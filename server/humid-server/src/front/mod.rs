//! The front unit: edge + gateway (SERVER.md §1). The only unit on the internet.
//!
//! * Outer TLS 1.3 with a post-quantum group required (tls::outer_provider); rate limits on
//!   the **socket's** peer address (no forwarded headers, no shared buckets: M4).
//! * HTP/2 (docs/v5/HTP2.md) **passes through** front: it reads the 32-byte cleartext header
//!   of each frame (version, kind, unit, size class, session id, counter), checks that a call
//!   is well formed and goes to one unit, rate-limits it, and forwards the bytes to that unit
//!   over internal TLS. The session ends inside core or anon, so front can neither read nor
//!   change a request, a body, a session token or a proof.
//! * Serves the key bundle (the signed policy as is, and each unit's KEM certificate), the
//!   public log, and health.
//!
//! Front holds no database and no secret beyond its TLS key. It never decides who is signed
//! in (core does) and never sees a document key or a share in the clear (H2).

pub mod routes;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use humid_htp::cert::Bundle;
use humid_htp::frame::{self, Kind};
use humid_htp::{Code, Unit};

use crate::error::{Error, Result};
use crate::limits::Sketch;
use crate::net::{CLIENT_NET, Peer, UnitClient, network_of};
use crate::policy::SignedPolicy;
use crate::unit::{Clock, ms};

/// The front unit.
pub struct Front {
    /// The verified policy.
    pub policy: Arc<SignedPolicy>,
    /// The clock.
    pub clock: Clock,
    /// Core.
    pub core: UnitClient,
    /// Anon.
    pub anon: UnitClient,
    handshakes: Sketch,
    calls: Sketch,
    public_reads: Sketch,
    bundle: std::sync::Mutex<Option<(i64, Vec<u8>)>>,
}

/// How long front serves one key bundle before asking the units for their certificates again.
pub const BUNDLE_MS: i64 = 10 * ms::MINUTE;

impl Front {
    /// A front unit.
    #[must_use]
    pub fn new(
        policy: Arc<SignedPolicy>,
        clock: Clock,
        core: UnitClient,
        anon: UnitClient,
    ) -> Arc<Self> {
        let l = &policy.policy.limits;
        Arc::new(Self {
            handshakes: Sketch::new(l.handshakes_per_minute, ms::MINUTE),
            calls: Sketch::new(l.calls_per_minute, ms::MINUTE),
            public_reads: Sketch::new(120, ms::MINUTE),
            policy,
            clock,
            core,
            anon,
            bundle: std::sync::Mutex::new(None),
        })
    }

    /// The router (served on the outer TLS listener).
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/htp/v2/keys", get(keys))
            .route("/htp/v2/call", post(call))
            .route("/tlog/v2/checkpoint", get(checkpoint))
            .route("/tlog/v2/consistency", get(consistency))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self.clone())
    }

    fn net(headers: &axum::http::Extensions) -> Result<String> {
        let peer = headers
            .get::<Peer>()
            .ok_or_else(|| Error::internal("no peer"))?;
        Ok(network_of(peer.addr.ip()))
    }

    fn limit(&self, sketch: &Sketch, key: &str) -> Result<()> {
        if !sketch.take(key, self.clock.now()) {
            return Err(Error::too_many(
                "rate_limited",
                "Too many requests from your network. Wait a minute.",
            ));
        }
        Ok(())
    }

    fn unit(&self, u: Unit) -> &UnitClient {
        match u {
            Unit::Core => &self.core,
            Unit::Anon => &self.anon,
        }
    }

    /// The key bundle: the policy file and its signature exactly as the root signed them,
    /// and each unit's current KEM certificate (cached for [`BUNDLE_MS`]).
    ///
    /// # Errors
    /// A unit is unreachable.
    pub async fn bundle(&self) -> Result<Vec<u8>> {
        let now = self.clock.now();
        if let Ok(g) = self.bundle.lock()
            && let Some((at, b)) = &*g
            && now - at < BUNDLE_MS
        {
            return Ok(b.clone());
        }
        let mut certs = vec![];
        for u in [Unit::Core, Unit::Anon] {
            let (status, b) = self.unit(u).raw("GET", "/htp/v2/cert", &[], vec![]).await?;
            if status != 200 {
                return Err(Error::unavailable(
                    "unit_unavailable",
                    "A service has no HTP/2 key yet.",
                ));
            }
            certs.push(b.to_vec());
        }
        let b = Bundle {
            policy: self.policy.bytes.clone(),
            policy_sig: self.policy.sig.clone(),
            certs,
        }
        .encode();
        if let Ok(mut g) = self.bundle.lock() {
            *g = Some((now, b.clone()));
        }
        Ok(b)
    }
}

type St = State<Arc<Front>>;

/// The key bundle (binary; the app verifies it against the identity root it pins).
async fn keys(State(f): St) -> Result<axum::response::Response> {
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        f.bundle().await?,
    )
        .into_response())
}

fn refuse(unit: Unit, sid: [u8; 16], c: Code) -> axum::response::Response {
    (
        StatusCode::from_u16(c.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
        [("content-type", crate::htp::CONTENT_TYPE)],
        frame::error(unit, sid, c),
    )
        .into_response()
}

/// `POST /htp/v2/call`: check the frames' cleartext headers, rate-limit, forward the bytes
/// unchanged to the unit the header names. Front never holds a key to open them.
async fn call(State(f): St, req: axum::extract::Request) -> Result<axum::response::Response> {
    let net = Front::net(req.extensions())?;
    let body: Body = req.into_body();
    let bytes = crate::net::body_bytes(body, crate::htp::MAX_CALL).await?;
    let (unit, kind, sid) = match frame::route(&bytes) {
        Ok(r) => r,
        Err(c) => return Ok(refuse(Unit::Core, [0; 16], c)),
    };
    let (sketch, key) = match kind {
        Kind::Hello | Kind::Resume => (&f.handshakes, net.clone()),
        _ => (&f.calls, hex::encode(sid)),
    };
    if f.limit(sketch, &key).is_err() {
        return Ok(refuse(unit, sid, Code::RateLimited));
    }
    let (status, out) = match f
        .unit(unit)
        .raw(
            "POST",
            "/htp/v2/call",
            &[(CLIENT_NET, &net)],
            bytes.to_vec(),
        )
        .await
    {
        Ok(r) => r,
        Err(_) => return Ok(refuse(unit, sid, Code::UnitUnavailable)),
    };
    if status != 200 {
        return Ok(refuse(unit, sid, Code::UnitUnavailable));
    }
    Ok((
        StatusCode::OK,
        [("content-type", crate::htp::CONTENT_TYPE)],
        out,
    )
        .into_response())
}

async fn checkpoint(State(f): St, req: axum::extract::Request) -> Result<axum::response::Response> {
    let net = Front::net(req.extensions())?;
    f.limit(&f.public_reads, &net)?;
    let v: serde_json::Value = f
        .core
        .get("/tlog/checkpoint", &[(CLIENT_NET, &net)])
        .await?;
    Ok((StatusCode::OK, axum::Json(v)).into_response())
}

#[derive(serde::Deserialize)]
struct Range {
    from: i64,
    to: i64,
}

async fn consistency(
    State(f): St,
    Query(q): Query<Range>,
    req: axum::extract::Request,
) -> Result<axum::response::Response> {
    let net = Front::net(req.extensions())?;
    f.limit(&f.public_reads, &net)?;
    let v: serde_json::Value = f
        .core
        .get(
            &format!("/tlog/consistency?from={}&to={}", q.from, q.to),
            &[(CLIENT_NET, &net)],
        )
        .await?;
    Ok((StatusCode::OK, axum::Json(v)).into_response())
}
