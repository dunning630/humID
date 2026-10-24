//! Serving and calling over TLS (SERVER.md §8). There is no plain-HTTP listener anywhere.
//!
//! * [`serve`] accepts TLS connections, reads the verified peer certificate, refuses a peer
//!   whose role may not call this unit, and hands each request to the router with a [`Peer`]
//!   extension (role, and the client network for rate limits).
//! * [`UnitClient`] calls another unit over internal TLS, verifying that the server's
//!   certificate names the role it means to reach.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpListener;
use tower::ServiceExt;

use crate::error::{Error, Result};
use crate::tls;
use crate::unit::Role;

/// Who is calling: the verified certificate's role (none on the outer listener) and the
/// client's network, from the socket's peer address (never a header).
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    /// The calling unit, from its verified certificate.
    pub role: Option<Role>,
    /// The socket's peer address.
    pub addr: SocketAddr,
}

/// The rate-limit key for an address: IPv4 address, IPv6 /64.
#[must_use]
pub fn network_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("v4:{v4}"),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("v4:{v4}"),
            None => {
                let s = v6.segments();
                format!("v6:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Header front uses to pass the client network to core and anon, for their own limits.
/// Units use it only for availability limits, never for authorisation.
pub const CLIENT_NET: &str = "x-humid-client-net";

/// Largest request body any unit reads (a document upload).
pub const MAX_BODY: usize = 72 << 20;
/// Open connections per listener.
pub const MAX_CONNECTIONS: usize = 4096;
/// A request body must arrive within this long.
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Serve `router` on `listener` with `tls_cfg`. `callers`: the roles allowed to connect
/// (empty = the public outer listener: no client certificate). Runs until the task is
/// dropped.
pub async fn serve(
    listener: TcpListener,
    tls_cfg: Arc<rustls::ServerConfig>,
    router: Router,
    callers: &'static [Role],
    public: bool,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    // L-17: a cap on open connections, and a back-off when accept fails (EMFILE and the like)
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return;
        };
        let (sock, addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed; backing off");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(sock),
            )
            .await
            {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "tls handshake refused");
                    return;
                }
                Err(_) => return,
            };
            let role = tls::peer_role(tls.get_ref().1.peer_certificates());
            if !public && !role.is_some_and(|r| callers.contains(&r)) {
                tracing::warn!(?role, "a peer that may not call this unit was refused");
                return;
            }
            let peer = Peer { role, addr };
            let svc = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                let router = router.clone();
                async move {
                    req.extensions_mut().insert(peer);
                    let req = req.map(Body::new);
                    router.oneshot(req).await
                }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(15))
                .serve_connection(TokioIo::new(tls), svc);
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

/// Bind and spawn a server; returns its address and the task.
///
/// # Errors
/// The address can't be bound.
pub async fn spawn(
    addr: SocketAddr,
    tls_cfg: Arc<rustls::ServerConfig>,
    router: Router,
    callers: &'static [Role],
    public: bool,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let l = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::internal(format!("bind {addr}: {e}")))?;
    let local = l.local_addr().map_err(|e| Error::internal(e.to_string()))?;
    Ok((
        local,
        tokio::spawn(serve(l, tls_cfg, router, callers, public)),
    ))
}

type Https = hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// A client for one other unit.
#[derive(Clone)]
pub struct UnitClient {
    role: Role,
    base: String,
    client: hyper_util::client::legacy::Client<Https, Full<bytes::Bytes>>,
}

impl UnitClient {
    /// A client for `role` at `base` (`https://host:port`), verifying the server certificate
    /// names `role` under the internal CA.
    ///
    /// # Errors
    /// A bad TLS identity.
    pub fn new(identity: &tls::Identity, role: Role, base: &str) -> Result<Self> {
        let cfg = (*identity.client_config()?).clone();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(cfg)
            .https_only()
            .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(
                tls::server_name(role)?,
            ))
            .enable_http1()
            .build();
        let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build(https);
        Ok(Self {
            role,
            base: base.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// Which unit this reaches.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Send a request with raw bytes; returns status and body.
    ///
    /// # Errors
    /// `unit_unavailable` if the unit can't be reached.
    pub async fn raw(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<(u16, bytes::Bytes)> {
        self.raw_limited(method, path, headers, body, MAX_BODY + (8 << 20))
            .await
    }

    /// As [`UnitClient::raw`], reading at most `max` bytes of the answer (front forwarding
    /// HTP/2 answers: review #97 H-1).
    ///
    /// # Errors
    /// `unit_unavailable` if the unit can't be reached; `too_large` for a bigger answer.
    pub async fn raw_limited(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
        max: usize,
    ) -> Result<(u16, bytes::Bytes)> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if !body.is_empty() {
            b = b.header("content-type", "application/json");
        }
        let req = b
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| Error::internal(e.to_string()))?;
        let fut = self.client.request(req);
        let resp = match tokio::time::timeout(std::time::Duration::from_secs(30), fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(unit = self.role.as_str(), error = %e, "unit unreachable");
                return Err(Error::unavailable(
                    "unit_unavailable",
                    format!("The {} service is unavailable.", self.role.as_str()),
                ));
            }
            Err(_) => {
                return Err(Error::unavailable(
                    "unit_unavailable",
                    format!("The {} service didn't answer.", self.role.as_str()),
                ));
            }
        };
        let status = resp.status().as_u16();
        let body = body_bytes(Body::new(resp.into_body()), max).await?;
        Ok((status, body))
    }

    /// POST JSON, expect JSON; another unit's refusal comes back as [`Error::Upstream`].
    ///
    /// # Errors
    /// Unreachable, or the unit refused.
    pub async fn post<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: &T,
    ) -> Result<R> {
        let bytes = serde_json::to_vec(body).map_err(|e| Error::internal(e.to_string()))?;
        let (status, body) = self.raw("POST", path, headers, bytes).await?;
        decode(status, &body)
    }

    /// GET, expect JSON.
    ///
    /// # Errors
    /// Unreachable, or the unit refused.
    pub async fn get<R: DeserializeOwned>(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<R> {
        let (status, body) = self.raw("GET", path, headers, vec![]).await?;
        decode(status, &body)
    }
}

/// Turn a unit's answer into `R` or its error.
///
/// # Errors
/// The unit's own refusal, or an unreadable answer.
pub fn decode<R: DeserializeOwned>(status: u16, body: &[u8]) -> Result<R> {
    if (200..300).contains(&status) {
        return serde_json::from_slice(body)
            .map_err(|e| Error::internal(format!("unit answer: {e}")));
    }
    #[derive(serde::Deserialize)]
    struct E {
        error: String,
        message: String,
    }
    match serde_json::from_slice::<E>(body) {
        Ok(e) => Err(Error::Upstream {
            status,
            code: e.error,
            message: e.message,
        }),
        Err(_) => Err(Error::Upstream {
            status,
            code: "upstream".into(),
            message: format!("A service answered {status}."),
        }),
    }
}

/// Read a request body, at most `max` bytes.
///
/// # Errors
/// `too_large`.
pub async fn body_bytes(body: Body, max: usize) -> Result<bytes::Bytes> {
    let limited = http_body_util::Limited::new(body, max);
    match tokio::time::timeout(BODY_TIMEOUT, limited.collect()).await {
        Ok(Ok(c)) => Ok(c.to_bytes()),
        Ok(Err(_)) => Err(Error::TooLarge(
            "too_large",
            "That request is too large.".into(),
        )),
        Err(_) => Err(Error::bad(
            "too_slow",
            "That request took too long to send.",
        )),
    }
}

/// A JSON reply.
pub fn json<T: Serialize>(status: StatusCode, v: &T) -> axum::response::Response {
    use axum::response::IntoResponse;
    (status, axum::Json(v)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks() {
        assert_eq!(network_of("192.0.2.7".parse().unwrap()), "v4:192.0.2.7");
        assert_eq!(
            network_of("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "v6:2001:db8:1:2::/64"
        );
        assert_eq!(
            network_of("2001:db8:1:2:ffff::1".parse().unwrap()),
            network_of("2001:db8:1:2::9".parse().unwrap()),
            "one /64 is one network"
        );
        assert_eq!(
            network_of("::ffff:192.0.2.7".parse().unwrap()),
            "v4:192.0.2.7"
        );
    }

    #[test]
    fn upstream_errors_pass_through() {
        let e = decode::<serde_json::Value>(
            423,
            br#"{"error":"checkin_missed","message":"Check in."}"#,
        )
        .unwrap_err();
        assert_eq!(e.code_str(), "checkin_missed");
        assert_eq!(e.status().as_u16(), 423);
    }
}
