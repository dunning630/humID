//! # HTP/2
//!
//! The HumID 5.0 transport between the phone's Rust core and the server units
//! (docs/v5/HTP2.md, byte for byte). It runs inside the outer TLS that front terminates, and
//! ends in the unit that acts on the request (core, or anon for anonymous sessions), so front
//! sees only routing metadata: which unit, which session, when, and a size class.
//!
//! | Piece | Module |
//! | --- | --- |
//! | Frames: the cleartext 28-byte header front routes on, size classes, padding | [`frame`] |
//! | Handshake: hybrid KEM to a certified server key + an ephemeral client key; resumption | [`handshake`], [`client`], [`server`] |
//! | Server KEM certificates and the key bundle the app pins through the identity root | [`cert`] |
//! | Messages inside records: requests, 1 MiB chunks, responses, pulls, typed errors | [`msg`] |
//! | Request bodies as typed parts, live proofs as binary TLV | [`parts`] |
//!
//! Everything is **sans-io**: [`client::Session`] and [`server::Server`] take bytes and
//! return bytes; the caller owns sockets, clocks and threads. Secrets live in wiping
//! containers ([`humid_pq2::Secret`], [`zeroize::Zeroizing`]); per-direction, per-session keys
//! come only from [`humid_pq2::transit_channel`], so a (key, nonce) pair can't repeat.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cert;
pub mod client;
mod error;
pub mod frame;
pub mod handshake;
pub mod msg;
pub mod parts;
pub mod server;

pub use error::{Code, Result};

/// The HTP/2 revision in every frame header. A change to any layout, label or rule is a new
/// revision; there is no negotiation (so nothing to downgrade).
pub const VERSION: u8 = 1;
/// Body bytes per chunk (requests and responses).
pub const CHUNK: usize = 1 << 20;
/// Largest request body (a document upload: the envelope plus its signed request).
pub const MAX_BODY: u64 = 72 << 20;
/// Largest response body.
pub const MAX_RESPONSE: u64 = 80 << 20;
/// Session id bytes.
pub const SID_LEN: usize = 16;
/// Transcript hash bytes (`th`): what sign-ins and live proofs name.
pub const TH_LEN: usize = 64;

/// Which unit a session ends in (the one routing byte front reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    /// Identity, vault, ledger, recovery: signed-in traffic.
    Core,
    /// Access passes and the relay: anonymous sessions only.
    Anon,
}

impl Unit {
    /// The wire byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Unit::Core => 1,
            Unit::Anon => 2,
        }
    }

    /// The unit for a wire byte.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Unit::Core),
            2 => Some(Unit::Anon),
            _ => None,
        }
    }
}

/// Number of chunks a body of `len` bytes travels in (at least one, even when empty).
#[must_use]
pub fn n_chunks(len: u64) -> u32 {
    let c = CHUNK as u64;
    u32::try_from(len.div_ceil(c).max(1)).unwrap_or(u32::MAX)
}

/// Length of chunk `index` of a body of `len` bytes.
#[must_use]
pub fn chunk_len(len: u64, index: u32) -> usize {
    let start = u64::from(index) * CHUNK as u64;
    usize::try_from(len.saturating_sub(start).min(CHUNK as u64)).unwrap_or(0)
}

/// HUMID-PQ2 type codes HTP/2 uses (proposed `0x03xx` block of the PQ2.md registry).
pub mod types {
    use humid_pq2::ObjectType;
    /// A unit's HTP/2 KEM certificate.
    pub const KEM_CERT: ObjectType = ObjectType(0x0300);
    /// The key bundle served at `GET /htp/v2/keys`.
    pub const KEY_BUNDLE: ObjectType = ObjectType(0x0301);
    /// The sealed body of a resumption ticket (server-private; AAD only).
    pub const TICKET: ObjectType = ObjectType(0x0302);
    /// A live proof as binary TLV.
    pub const PROOF: ObjectType = ObjectType(0x0303);
}

/// KDF, hash and signature labels.
pub mod label {
    /// The transcript of a full handshake.
    pub const TRANSCRIPT: &str = "HUMID-PQ2 htp2-transcript";
    /// The transcript of a resumption.
    pub const TRANSCRIPT_RESUME: &str = "HUMID-PQ2 htp2-transcript-resume";
    /// The master secret of a full handshake.
    pub const MASTER: &str = "HUMID-PQ2 htp2-master";
    /// The master secret of a resumption.
    pub const RESUME_MASTER: &str = "HUMID-PQ2 htp2-resume-master";
    /// The server's key confirmation.
    pub const CONFIRM: &str = "HUMID-PQ2 htp2-confirm";
    /// The session secret handed to `transit_channel`.
    pub const SESSION: &str = "HUMID-PQ2 htp2-session";
    /// The resumption secret a ticket carries.
    pub const RESUMPTION: &str = "HUMID-PQ2 htp2-resumption";
    /// A unit statement key's signature over a KEM certificate.
    pub const KEM_CERT: &str = "HUMID-PQ2 htp2-kem-cert";
    /// The identity root's signature over the policy file (SERVER.md §7).
    pub const POLICY: &str = "HUMID-PQ2 server-policy";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking() {
        assert_eq!(n_chunks(0), 1);
        assert_eq!(n_chunks(1), 1);
        assert_eq!(n_chunks(CHUNK as u64), 1);
        assert_eq!(n_chunks(CHUNK as u64 + 1), 2);
        assert_eq!(chunk_len(CHUNK as u64 + 1, 1), 1);
        assert_eq!(chunk_len(0, 0), 0);
        assert_eq!(chunk_len(5, 3), 0);
        assert_eq!(Unit::from_u8(Unit::Anon.to_u8()), Some(Unit::Anon));
        assert_eq!(Unit::from_u8(0), None);
    }
}
