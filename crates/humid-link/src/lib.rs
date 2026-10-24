//! # humid-link
//!
//! What the app core (crates/humid-core) uses to talk to the server (docs/v5/HTP2.md §8):
//! one [`Link`] per unit, over a [`Transport`] the platform supplies (an HTTPS POST to
//! `/htp/v2/call` through the platform TLS stack). The link:
//!
//! * pins the server through the **identity root** built into the app: the key bundle's
//!   policy must verify under it, and the unit's KEM certificate under the statement key the
//!   policy names; a signature that fails is a hard stop ([`LinkError::IdentityChanged`]),
//!   an older policy than one it has seen is refused ([`LinkError::PolicyRollback`]), and the
//!   policy's mode is surfaced so the app can warn on a non-production server;
//! * uses a certificate only within its dates, and fetches the bundle again past its half
//!   life (the unit has a new key by then);
//! * opens an HTP/2 session, and on the next unlock **resumes** with the ticket instead of a
//!   full handshake (no certificate check, and the session transcript a sign-in is bound to
//!   carries over, so no new sign-in either);
//! * keeps the **step-up nonce pool** from sign-in and `/sync` replies, so a sensitive action
//!   is one round trip; [`Link::step_up`] reserves the request id the live proof names before
//!   the prompt opens;
//! * sends bodies over 1 MiB in chunks and resumes a cut upload or download from the next
//!   chunk, without a new live check;
//! * never lets an unauthenticated error change its state: it first proves the session with
//!   an authenticated pull of the request's answer, and sends a request again in a new
//!   session only when it is idempotent (GET), so a forged `session_unknown` can't make a
//!   request run twice (review #97 M-5).
//!
//! The link holds the HTP/2 session keys and the session token; it never holds a document
//! key, a share or a seed (those stay in humid-core, which hands the link opaque bodies).
//! It is async and owns no runtime: the app shell drives it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;
use std::future::Future;

use humid_htp::cert::{Bundle, Cert};
use humid_htp::client::{Event, Handshake, Session, Ticket};
use humid_htp::msg::{Encoding, HeaderName, Method};
use humid_htp::parts::{self, Part, Proof};
use humid_htp::{Code, Unit};
use humid_pq2::DualVerifyingKey;
use zeroize::Zeroizing;

/// The platform's transport.
pub trait Transport {
    /// POST `body` to `/htp/v2/call`; the response body, whatever its HTTP status (HTP/2
    /// carries its own errors; a status alone is never trusted).
    fn call(&mut self, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, NetError>> + Send;
    /// GET `/htp/v2/keys`.
    fn keys(&mut self) -> impl Future<Output = Result<Vec<u8>, NetError>> + Send;
}

/// A network failure (no answer at all).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetError;

/// Why a call didn't produce an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// No network.
    Offline,
    /// The key bundle doesn't verify under the identity root the app pins. Hard stop: the app
    /// shows its warning screen and sends nothing.
    IdentityChanged,
    /// The protocol refused (authenticated, or a fresh session failed too).
    Protocol(Code),
    /// The unit answered with an error status ([`Link::request`] only).
    Unit {
        /// HTTP-style status.
        status: u16,
        /// The unit's stable code (`bad_proof`, `step_up_used`, …).
        code: String,
    },
    /// No step-up nonce left: `/v1/sync` or `/v1/auth/nonces` refills the pool.
    NoNonce,
    /// The server offered a policy older than one this app has already accepted (or the same
    /// version with other bytes): refused, like a changed identity, but its own code.
    PolicyRollback,
    /// The session ended while a non-idempotent request was outstanding: it may or may not
    /// have run. The app re-reads its state (`/v1/sync`) before trying again.
    Unknown,
}

impl From<Code> for LinkError {
    fn from(c: Code) -> Self {
        LinkError::Protocol(c)
    }
}

/// What a unit answered.
pub struct Reply {
    /// Status.
    pub status: u16,
    /// 0 JSON, 1 bytes.
    pub ctype: u8,
    /// Body (wiped on drop).
    pub body: Zeroizing<Vec<u8>>,
}

/// A request body.
pub enum Body<'a> {
    /// The unit's own bytes (JSON, or nothing).
    Raw(&'a [u8]),
    /// Typed parts: an optional live proof, the JSON object, named binary fields.
    Parts {
        /// The step-up proof.
        proof: Option<Box<Proof>>,
        /// The JSON object (without the binary fields).
        json: &'a [u8],
        /// Binary fields, sent as bytes rather than base64.
        blobs: &'a [(&'a str, &'a [u8])],
    },
}

impl Body<'_> {
    fn encode(&self) -> (Encoding, Vec<u8>) {
        match self {
            Body::Raw(b) => (Encoding::Raw, b.to_vec()),
            Body::Parts { proof, json, blobs } => {
                let mut ps = vec![];
                if let Some(p) = proof {
                    ps.push(Part::Proof(p.clone()));
                }
                if !json.is_empty() {
                    ps.push(Part::Json(json.to_vec()));
                }
                for (n, b) in *blobs {
                    ps.push(Part::Bytes((*n).to_string(), b.to_vec()));
                }
                (Encoding::Parts, parts::encode(&ps))
            }
        }
    }
}

/// What the app needs from the policy file: its version (forward-only), whether the server
/// runs in production mode, and the statement key it names for a unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyView {
    /// The policy's version (it only rises).
    pub version: u64,
    /// The server runs in production mode (the app warns on anything else).
    pub production: bool,
    /// The unit's statement key (ML-DSA-87 encoding).
    pub statement_key: Vec<u8>,
}

/// Read a [`PolicyView`] for a unit from the policy file's bytes. The policy's format belongs
/// to the server (SERVER.md §7); the app passes its parser in.
pub type PolicyOf = fn(&[u8], Unit) -> Option<PolicyView>;

/// The highest policy a link has accepted: its version and the SHA3-512 of its bytes. The app
/// persists it ([`Link::policy_seen`]) and restores it at start ([`Link::set_policy_floor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySeen {
    /// Version.
    pub version: u64,
    /// SHA3-512 of the file.
    pub hash: [u8; 64],
}

/// The clock the link reads (ms): hello times and ticket expiry.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// What a live proof names, reserved before the prompt opens.
#[derive(Clone, Copy, Debug)]
pub struct StepUp {
    /// The reserved request id (send the request with it).
    pub rid: u32,
    /// The `seq` the proof names (session generation and request id).
    pub seq: u64,
    /// The session transcript the proof names.
    pub th: [u8; 64],
    /// A single-use nonce from the pool (zero from [`Link::reserve`]).
    pub nonce: [u8; 32],
}

/// A link to one unit.
pub struct Link<T: Transport> {
    unit: Unit,
    root: DualVerifyingKey,
    policy_of: PolicyOf,
    policy_seen: Option<PolicySeen>,
    production: Option<bool>,
    transport: T,
    clock: Clock,
    cert: Option<Cert>,
    session: Option<Session>,
    ticket: Option<Ticket>,
    token: Option<Zeroizing<Vec<u8>>>,
    nonces: VecDeque<[u8; 32]>,
    handshakes: usize,
    resumptions: usize,
}

impl<T: Transport> Link<T> {
    /// A link to `unit`, pinned to `root`.
    #[must_use]
    pub fn new(
        unit: Unit,
        root: DualVerifyingKey,
        policy_of: PolicyOf,
        transport: T,
        clock: Clock,
    ) -> Self {
        Self {
            unit,
            root,
            policy_of,
            policy_seen: None,
            production: None,
            transport,
            clock,
            cert: None,
            session: None,
            ticket: None,
            token: None,
            nonces: VecDeque::new(),
            handshakes: 0,
            resumptions: 0,
        }
    }

    /// The highest policy accepted so far (persist it).
    #[must_use]
    pub fn policy_seen(&self) -> Option<PolicySeen> {
        self.policy_seen
    }

    /// Restore the highest policy accepted in an earlier run: an older one is refused.
    pub fn set_policy_floor(&mut self, p: PolicySeen) {
        if self.policy_seen.is_none_or(|q| p.version >= q.version) {
            self.policy_seen = Some(p);
        }
    }

    /// Whether the server runs in production mode (`None` until a bundle was verified). The
    /// app shows a warning when this is `Some(false)`.
    #[must_use]
    pub fn server_is_production(&self) -> Option<bool> {
        self.production
    }

    /// Full handshakes so far.
    #[must_use]
    pub fn handshakes(&self) -> usize {
        self.handshakes
    }

    /// Resumptions so far.
    #[must_use]
    pub fn resumptions(&self) -> usize {
        self.resumptions
    }

    /// The open session's transcript (what a sign-in names).
    #[must_use]
    pub fn th(&self) -> Option<[u8; 64]> {
        self.session.as_ref().map(Session::th)
    }

    /// The open session's id.
    #[must_use]
    pub fn sid(&self) -> Option<[u8; 16]> {
        self.session.as_ref().map(Session::sid)
    }

    /// Sign-in finished: keep the token (sent with every request) and the nonce pool.
    pub fn signed_in(&mut self, token: &[u8], nonces: &[[u8; 32]]) {
        self.token = Some(Zeroizing::new(token.to_vec()));
        self.set_nonces(nonces);
    }

    /// Replace the nonce pool (every signed-in reply carries one).
    pub fn set_nonces(&mut self, nonces: &[[u8; 32]]) {
        self.nonces = nonces.iter().copied().collect();
    }

    /// Unused nonces.
    #[must_use]
    pub fn nonces_left(&self) -> usize {
        self.nonces.len()
    }

    /// Lock: drop the session, the token and the nonces. The ticket stays, so the next
    /// unlock resumes (it carries the transcript a sign-in is bound to, but no token: the
    /// core asks for a new sign-in if its own session ended).
    pub fn lock(&mut self) {
        self.session = None;
        self.token = None;
        self.nonces.clear();
    }

    /// Forget everything, the ticket too (sign-out; the next session is a fresh chain).
    pub fn forget(&mut self) {
        self.lock();
        self.ticket = None;
    }

    /// Fetch and verify the key bundle. Only a bundle whose signatures fail is
    /// `IdentityChanged`; an answer that isn't a bundle at all (front's error while a unit
    /// restarts) is `Offline` (review #97 L-3).
    async fn verify_bundle(&mut self) -> Result<Cert, LinkError> {
        let now = (self.clock)();
        let b = self
            .transport
            .keys()
            .await
            .map_err(|_| LinkError::Offline)?;
        let bundle = Bundle::decode(&b).map_err(|_| LinkError::Offline)?;
        let policy = bundle
            .verify_policy(&self.root)
            .map_err(|_| LinkError::IdentityChanged)?;
        let view = (self.policy_of)(policy, self.unit).ok_or(LinkError::IdentityChanged)?;
        let seen = PolicySeen {
            version: view.version,
            hash: humid_pq2::sha3_512(policy),
        };
        if let Some(floor) = self.policy_seen
            && (seen.version < floor.version
                || (seen.version == floor.version && !humid_pq2::ct_eq(&seen.hash, &floor.hash)))
        {
            return Err(LinkError::PolicyRollback);
        }
        let key = view.statement_key.clone();
        let cert = bundle
            .verified(&self.root, self.unit, now, |_, _| Some(key.clone()))
            .map_err(|_| LinkError::IdentityChanged)?;
        self.policy_seen = Some(seen);
        self.production = Some(view.production);
        Ok(cert)
    }

    /// Open a session if none is open: resume with the ticket when there is one, else a
    /// full handshake to the pinned, certified key (fetching the bundle once, and again if
    /// the server no longer holds the key).
    ///
    /// # Errors
    /// `Offline`; `IdentityChanged`; `Protocol` if the server refuses a fresh handshake.
    pub async fn connect(&mut self) -> Result<(), LinkError> {
        if self.session.is_some() {
            return Ok(());
        }
        let now = (self.clock)();
        if let Some(t) = self.ticket.take() {
            let keep = Ticket {
                unit: t.unit,
                ticket: t.ticket.clone(),
                expires_at: t.expires_at,
                secret: t.secret.duplicate(),
                chain_th: t.chain_th,
            };
            if let Ok((hs, call)) = Handshake::resume(t, now) {
                let ans = match self.transport.call(call).await {
                    Ok(a) => a,
                    Err(_) => {
                        // no answer: the server never saw it, so the ticket is still good
                        self.ticket = Some(keep);
                        return Err(LinkError::Offline);
                    }
                };
                if let Ok(mut s) = hs.finish(&ans) {
                    self.ticket = s.take_ticket();
                    self.session = Some(s);
                    self.resumptions += 1;
                    return Ok(());
                }
            }
        }
        // a certificate outside its dates is never used; past its half life the unit has a
        // new key, so fetch the bundle again (and keep the old one if that fails while it is
        // still valid) (review #97 M-6)
        if let Some(c) = &self.cert
            && (!c.valid_at(now) || c.past_half_life(now))
        {
            match self.verify_bundle().await {
                Ok(c) => self.cert = Some(c),
                Err(LinkError::Offline) if self.cert.as_ref().is_some_and(|c| c.valid_at(now)) => {}
                Err(e) => {
                    self.cert = None;
                    return Err(e);
                }
            }
        }
        for attempt in 0..2 {
            if self.cert.is_none() || attempt == 1 {
                self.cert = Some(self.verify_bundle().await?);
            }
            let cert = self.cert.as_ref().ok_or(LinkError::IdentityChanged)?;
            let (hs, call) = Handshake::full(self.unit, cert, now)?;
            let ans = self
                .transport
                .call(call)
                .await
                .map_err(|_| LinkError::Offline)?;
            match hs.finish(&ans) {
                Ok(mut s) => {
                    self.ticket = s.take_ticket();
                    self.session = Some(s);
                    self.handshakes += 1;
                    return Ok(());
                }
                Err(Code::KeyUnknown | Code::BadCert) if attempt == 0 => {}
                Err(c) => return Err(c.into()),
            }
        }
        Err(LinkError::Protocol(Code::HandshakeFailed))
    }

    /// Reserve what a live proof names, before the prompt opens: the request id (and so the
    /// proof's `seq`), a pool nonce and the transcript. Send the request with
    /// [`Link::call`] and `Some(rid)`.
    ///
    /// # Errors
    /// `NoNonce`; as [`Link::connect`].
    pub async fn step_up(&mut self) -> Result<StepUp, LinkError> {
        self.connect().await?;
        if self.nonces.is_empty() {
            return Err(LinkError::NoNonce);
        }
        let mut st = self.reserve()?;
        st.nonce = self.nonces.pop_front().ok_or(LinkError::NoNonce)?;
        Ok(st)
    }

    /// Reserve a request id in the open session (no nonce: the caller keeps its own pool).
    ///
    /// # Errors
    /// `session_unknown` with no open session.
    pub fn reserve(&mut self) -> Result<StepUp, LinkError> {
        let s = self
            .session
            .as_mut()
            .ok_or(LinkError::Protocol(Code::SessionUnknown))?;
        let rid = s.reserve()?;
        Ok(StepUp {
            rid,
            seq: s.proof_seq(rid),
            th: s.th(),
            nonce: [0; 32],
        })
    }

    /// One request and its answer, whatever the status. Cut uploads resume from the
    /// server's ack, cut downloads are pulled from the next chunk. An unauthenticated error
    /// is first checked with an authenticated pull; a session the server really no longer
    /// knows is replaced once and the request sent again only if it is a GET and carries no
    /// proof. Anything else that may have run comes back as [`LinkError::Unknown`].
    ///
    /// # Errors
    /// `Offline`, `Protocol`, `Unknown`.
    pub async fn call(
        &mut self,
        rid: Option<u32>,
        method: Method,
        path: &str,
        body: Body<'_>,
        headers: &[(HeaderName, &[u8])],
    ) -> Result<Reply, LinkError> {
        let (enc, bytes) = body.encode();
        for attempt in 0..2 {
            self.connect().await?;
            let mut h: Vec<(HeaderName, &[u8])> = headers.to_vec();
            if let Some(t) = &self.token
                && !h.iter().any(|(n, _)| *n == HeaderName::Session)
            {
                h.push((HeaderName::Session, t.as_slice()));
            }
            let s = self
                .session
                .as_mut()
                .ok_or(LinkError::Protocol(Code::Internal))?;
            let (sent, call) = match rid {
                Some(r) => s.request_reserved(r, method, path, enc, &h, &bytes)?,
                None => s.request(method, path, enc, &h, &bytes)?,
            };
            match self.drive(sent, call).await {
                Err(LinkError::Protocol(Code::SessionUnknown)) => {
                    self.session = None;
                    if attempt == 1 || rid.is_some() {
                        return Err(LinkError::Protocol(Code::SessionUnknown));
                    }
                    if method != Method::Get {
                        return Err(LinkError::Unknown);
                    }
                }
                r => return r,
            }
        }
        Err(LinkError::Protocol(Code::SessionUnknown))
    }

    /// [`Link::call`] for a raw body, with a non-2xx status as [`LinkError::Unit`].
    ///
    /// # Errors
    /// As [`Link::call`]; `Unit` for the unit's refusal.
    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: &[u8],
    ) -> Result<Reply, LinkError> {
        let r = self.call(None, method, path, Body::Raw(body), &[]).await?;
        if (200..300).contains(&r.status) {
            Ok(r)
        } else {
            Err(LinkError::Unit {
                status: r.status,
                code: unit_code(&r.body),
            })
        }
    }

    async fn drive(&mut self, rid: u32, mut call: Vec<u8>) -> Result<Reply, LinkError> {
        // unauthenticated answers in a row: each is checked with an authenticated pull before
        // it is believed
        let mut unauth = 0;
        let mut probed = false;
        for _ in 0..1024 {
            let ans = self
                .transport
                .call(call)
                .await
                .map_err(|_| LinkError::Offline)?;
            let s = self
                .session
                .as_mut()
                .ok_or(LinkError::Protocol(Code::Internal))?;
            let events = match s.receive(&ans) {
                Ok(e) => {
                    unauth = 0;
                    e
                }
                Err(c) if c.is_session_level() && unauth < UNAUTH_PROBES => {
                    unauth += 1;
                    probed = true;
                    call = s.pull(rid, 0)?;
                    continue;
                }
                Err(c) => return Err(c.into()),
            };
            let mut next = None;
            for e in events {
                match e {
                    Event::Response {
                        rid: r,
                        status,
                        ctype,
                        body,
                    } if r == rid => {
                        return Ok(Reply {
                            status,
                            ctype,
                            body,
                        });
                    }
                    // our probing pull found no kept answer: the request ran (or not) and its
                    // answer is gone; only the caller can tell what to do next
                    Event::Refused {
                        rid: r,
                        code: Code::RidUnknown,
                    } if r == rid && probed => return Err(LinkError::Unknown),
                    Event::Refused { rid: r, code } if r == rid || r == 0 => {
                        return Err(code.into());
                    }
                    Event::Ack { rid: r, next: n } if r == rid => next = Some(s.resend(rid, n)?),
                    Event::Partial { rid: r, next: n } if r == rid => next = Some(s.pull(rid, n)?),
                    _ => {}
                }
            }
            // nothing for us yet (a slow unit, or the answer was lost): ask for it
            call = match next {
                Some(c) => c,
                None => s.pull(rid, 0)?,
            };
        }
        Err(LinkError::Protocol(Code::Busy))
    }
}

/// Authenticated pulls the link sends to check an unauthenticated error before it believes
/// one.
pub const UNAUTH_PROBES: usize = 2;

/// The `error` field of a unit's JSON refusal (`{"error":"<code>",…}`, a snake_case code),
/// without a JSON parser.
#[must_use]
pub fn unit_code(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    s.split("\"error\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .filter(|c| {
            !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_codes() {
        assert_eq!(
            unit_code(br#"{"error":"bad_proof","message":"x"}"#),
            "bad_proof"
        );
        assert_eq!(unit_code(b"garbage"), "unknown");
        assert_eq!(unit_code(br#"{"error":"<script>"}"#), "unknown");
    }
}
