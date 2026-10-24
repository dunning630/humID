//! Typed error codes (HTP2.md §9). One registry for both ends; a code never carries data.

use core::fmt;

/// Every refusal HTP/2 itself can give. `0x00xx` are frame- and session-level (they may come
/// back unauthenticated, as an error frame); `0x01xx` are per request (they always come back
/// inside an authenticated `ERROR` message). A unit's own refusals (`bad_proof`,
/// `step_up_used`, …) are not here: they travel inside an authenticated `RESPONSE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// Bytes that are not an HTP/2 message: wrong magic, length, class, field or trailing data.
    BadFrame,
    /// Another HTP/2 revision (`v`) or another suite.
    VersionUnsupported,
    /// A unit byte this endpoint doesn't serve.
    UnitUnknown,
    /// No such session (expired, evicted, or never existed): handshake again.
    SessionUnknown,
    /// A record or hello that was already accepted, or a `seq` older than the window.
    Replay,
    /// A record that didn't authenticate (tampered, truncated, wrong session or key).
    BadRecord,
    /// Over a size cap.
    TooLarge,
    /// Over a rate limit.
    RateLimited,
    /// The endpoint is full; try again later.
    Busy,
    /// A hello whose time is more than 5 minutes from the server's.
    StaleHello,
    /// A hello to a KEM key the server doesn't hold (any more): fetch the key bundle again.
    KeyUnknown,
    /// A resumption ticket the server can't use (unknown, expired, used): full handshake.
    TicketUnknown,
    /// The handshake failed (bad confirmation, bad key agreement, bad early data).
    HandshakeFailed,
    /// A KEM certificate or key bundle that doesn't verify against the pinned root.
    BadCert,
    /// A request id already used for another request in this session.
    RidReused,
    /// A body chunk or pull for a request id the server doesn't hold.
    RidUnknown,
    /// Method and path are not on the unit's allow-list.
    RouteNotFound,
    /// The assembled body doesn't match the hash its head announced.
    BodyMismatch,
    /// A session token on a unit whose sessions never sign in (anon).
    AuthNotAllowed,
    /// Too many requests being assembled at once in this session.
    TooManyInFlight,
    /// The unit behind the endpoint didn't answer.
    UnitUnavailable,
    /// The endpoint failed unexpectedly.
    Internal,
    /// The request is still being processed; ask again shortly.
    InProgress,
    /// A live proof that names another session, request id, method or path than the request
    /// carrying it.
    ProofMismatch,
}

const TABLE: &[(Code, u16, &str, u16)] = &[
    (Code::BadFrame, 0x0001, "bad_frame", 400),
    (Code::VersionUnsupported, 0x0002, "version_unsupported", 400),
    (Code::UnitUnknown, 0x0003, "unit_unknown", 404),
    (Code::SessionUnknown, 0x0004, "session_unknown", 404),
    (Code::Replay, 0x0005, "replay", 409),
    (Code::BadRecord, 0x0006, "bad_record", 400),
    (Code::TooLarge, 0x0007, "too_large", 413),
    (Code::RateLimited, 0x0008, "rate_limited", 429),
    (Code::Busy, 0x0009, "busy", 503),
    (Code::StaleHello, 0x000A, "stale_hello", 400),
    (Code::KeyUnknown, 0x000B, "key_unknown", 404),
    (Code::TicketUnknown, 0x000C, "ticket_unknown", 404),
    (Code::HandshakeFailed, 0x000D, "handshake_failed", 400),
    (Code::BadCert, 0x000E, "bad_cert", 400),
    (Code::RidReused, 0x0101, "rid_reused", 409),
    (Code::RidUnknown, 0x0102, "rid_unknown", 404),
    (Code::RouteNotFound, 0x0103, "route_not_found", 404),
    (Code::BodyMismatch, 0x0104, "body_mismatch", 400),
    (Code::AuthNotAllowed, 0x0105, "auth_not_allowed", 403),
    (Code::TooManyInFlight, 0x0106, "too_many_in_flight", 429),
    (Code::UnitUnavailable, 0x0107, "unit_unavailable", 503),
    (Code::Internal, 0x0108, "internal", 500),
    (Code::InProgress, 0x010A, "in_progress", 409),
    (Code::ProofMismatch, 0x010B, "proof_mismatch", 403),
];

impl Code {
    fn row(self) -> &'static (Code, u16, &'static str, u16) {
        TABLE.iter().find(|r| r.0 == self).unwrap_or(&TABLE[21]) // Internal; every variant is in the table (tested)
    }

    /// The 16-bit wire code.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self.row().1
    }

    /// The code for a wire value, if it is one.
    #[must_use]
    pub fn from_u16(v: u16) -> Option<Self> {
        TABLE.iter().find(|r| r.1 == v).map(|r| r.0)
    }

    /// The stable snake_case name (what the app maps to its own words).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.row().2
    }

    /// The HTTP status an endpoint answers with when it sends this code unauthenticated.
    #[must_use]
    pub fn http_status(self) -> u16 {
        self.row().3
    }

    /// Frame- and session-level (may arrive unauthenticated) rather than per request.
    #[must_use]
    pub fn is_session_level(self) -> bool {
        self.to_u16() < 0x0100
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Code {}

impl From<humid_pq2::Error> for Code {
    fn from(e: humid_pq2::Error) -> Self {
        match e {
            humid_pq2::Error::Decrypt => Code::BadRecord,
            humid_pq2::Error::Counter => Code::Replay,
            humid_pq2::Error::Encoding | humid_pq2::Error::Length => Code::BadFrame,
            humid_pq2::Error::KeyAgreement | humid_pq2::Error::Verify => Code::HandshakeFailed,
            _ => Code::Internal,
        }
    }
}

/// `Result` with [`Code`].
pub type Result<T> = core::result::Result<T, Code>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips_and_is_unique() {
        for (i, r) in TABLE.iter().enumerate() {
            assert_eq!(Code::from_u16(r.1), Some(r.0));
            assert_eq!(r.0.to_u16(), r.1);
            assert!(TABLE[i + 1..].iter().all(|o| o.1 != r.1 && o.2 != r.2));
        }
        assert_eq!(TABLE[21].0, Code::Internal);
        assert_eq!(Code::from_u16(0xFFFF), None);
        assert!(Code::SessionUnknown.is_session_level());
        assert!(!Code::RidReused.is_session_level());
    }
}
