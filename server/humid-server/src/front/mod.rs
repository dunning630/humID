//! The front unit: edge + gateway (SERVER.md §1). The only unit on the internet.
//!
//! * Outer TLS 1.3 with a post-quantum group required (tls::outer_provider); rate limits on
//!   the **socket's** peer address (no forwarded headers, no shared buckets: M4).
//! * Serves the signed policy as is, the public log, and health.
//! * HTP/2 (the inner protocol that carries app traffic) is **stubbed** until it is specified;
//!   [`routes::resolve`] is the allow-list the frames will be dispatched through, so the
//!   mapping from app routes to units is fixed and tested now.
//!
//! Front holds no database and no secret beyond its TLS key. It never decides who is signed
//! in (core does) and never sees a document key or a share in the clear (H2).

pub mod routes;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};

use crate::error::{Error, Result};
use crate::limits::Sketch;
use crate::net::{CLIENT_NET, Peer, UnitClient, network_of};
use crate::policy::SignedPolicy;
use crate::unit::{Clock, ms};
use crate::wire::B64;

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
    public_reads: Sketch,
}

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
            public_reads: Sketch::new(120, ms::MINUTE),
            policy,
            clock,
            core,
            anon,
        })
    }

    /// The router (served on the outer TLS listener).
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/htp/v2/keys", get(keys))
            .route("/htp/v2/hello", post(hello))
            .route("/htp/v2/call", post(call))
            .route("/tlog/v2/checkpoint", get(checkpoint))
            .route("/tlog/v2/consistency", get(consistency))
            .route("/healthz", get(|| async { "ok" }))
            .with_state(self.clone())
    }

    fn limit(&self, sketch: &Sketch, headers: &axum::http::Extensions) -> Result<String> {
        let peer = headers
            .get::<Peer>()
            .ok_or_else(|| Error::internal("no peer"))?;
        let net = network_of(peer.addr.ip());
        if !sketch.take(&net, self.clock.now()) {
            return Err(Error::too_many(
                "rate_limited",
                "Too many requests from your network. Wait a minute.",
            ));
        }
        Ok(net)
    }
}

type St = State<Arc<Front>>;

/// The signed policy, exactly as the root signed it, for the app to check and warn on.
async fn keys(State(f): St) -> impl IntoResponse {
    let body = serde_json::json!({
        "policy": B64(f.policy.bytes.clone()),
        "sig": B64(f.policy.sig.clone()),
        "htp": { "status": "not_implemented", "waiting_on": "the HTP/2 specification" },
    });
    (StatusCode::OK, axum::Json(body))
}

async fn hello(State(f): St, req: axum::extract::Request) -> Result<axum::response::Response> {
    f.limit(&f.handshakes, req.extensions())?;
    Err(Error::NotImplemented {
        what: "the HTP/2 handshake",
        waiting_on: "the HTP/2 specification",
    })
}

async fn call(State(_f): St) -> Result<axum::response::Response> {
    Err(Error::NotImplemented {
        what: "HTP/2 frames",
        waiting_on: "the HTP/2 specification",
    })
}

async fn checkpoint(State(f): St, req: axum::extract::Request) -> Result<axum::response::Response> {
    let net = f.limit(&f.public_reads, req.extensions())?;
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
    let net = f.limit(&f.public_reads, req.extensions())?;
    let v: serde_json::Value = f
        .core
        .get(
            &format!("/tlog/consistency?from={}&to={}", q.from, q.to),
            &[(CLIENT_NET, &net)],
        )
        .await?;
    Ok((StatusCode::OK, axum::Json(v)).into_response())
}
