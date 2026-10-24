//! The handshake bodies and the key schedule (HTP2.md §4).
//!
//! ```text
//! HELLO   kid (32) ‖ ct_s (1613) ‖ ek_c (1613) ‖ nonce_c (32) ‖ u64 time_c
//! RESUME  lp(ticket) ‖ ek_c (1613) ‖ nonce_c (32) ‖ u64 time_c
//! REPLY   u8 mode ‖ u32 gen ‖ ct_c (1613) ‖ nonce_s (32) ‖ u64 time_s ‖ confirm (32)
//!
//! th        = H(htp2-transcript,        [v ‖ unit, kid, ct_s, ek_c, nonce_c, time_c, sid, mode, gen, ct_c, nonce_s, time_s])
//! th_r      = H(htp2-transcript-resume, [v ‖ unit, RESUME body, sid, mode, gen, ct_c, nonce_s, time_s])
//! master    = KDF(htp2-master,        [ss_s, ss_e], [th])        full
//!           = KDF(htp2-resume-master, [res,  ss_e], [th_r])      resumption
//! confirm   = KDF(htp2-confirm,    [master], [th], 32)
//! session   = KDF(htp2-session,    [master], [th], 32)  → transit_channel(session, "HTP2" ‖ unit ‖ sid, role)
//! res'      = KDF(htp2-resumption, [master], [th], 32)  → sealed into the next ticket
//! ```
//!
//! There is no early (0-RTT) data: every record is under keys that include a fresh
//! ephemeral KEM secret, so nothing a session carries can be replayed into another.

use humid_pq2::encoding::Reader;
use humid_pq2::{
    KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN, KemCiphertext, KemPublicKey, Role, Secret32,
    TransitOpener, TransitSealer, ct_eq, kdf, labelled_hash, transit_channel,
};

use crate::msg::MAX_TICKET;
use crate::{Code, Result, SID_LEN, TH_LEN, Unit, VERSION, label};

/// Nonce bytes in hellos and replies.
pub const NONCE_LEN: usize = 32;
/// How far a hello's clock may be from the server's.
pub const HELLO_SKEW_MS: i64 = 5 * 60_000;

/// A full hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// `key_id` of the server KEM key it encapsulates to.
    pub kid: [u8; 32],
    /// Hybrid KEM ciphertext to that key.
    pub ct_s: Vec<u8>,
    /// The client's one-time hybrid KEM public key.
    pub ek_c: Vec<u8>,
    /// Client nonce.
    pub nonce_c: [u8; NONCE_LEN],
    /// Client clock (ms).
    pub time_c: u64,
}

/// A resumption hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resume {
    /// The ticket from an earlier session.
    pub ticket: Vec<u8>,
    /// The client's one-time hybrid KEM public key.
    pub ek_c: Vec<u8>,
    /// Client nonce.
    pub nonce_c: [u8; NONCE_LEN],
    /// Client clock (ms).
    pub time_c: u64,
}

/// The server's answer to either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// 0 full, 1 resumption.
    pub mode: u8,
    /// Which session of its chain this is: 0 for a full handshake, +1 per resumption.
    pub generation: u32,
    /// Hybrid KEM ciphertext to the client's one-time key.
    pub ct_c: Vec<u8>,
    /// Server nonce.
    pub nonce_s: [u8; NONCE_LEN],
    /// Server clock (ms).
    pub time_s: u64,
    /// Key confirmation.
    pub confirm: [u8; 32],
}

fn e(_: humid_pq2::Error) -> Code {
    Code::BadFrame
}

impl Hello {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.kid[..],
            &self.ct_s,
            &self.ek_c,
            &self.nonce_c,
            &self.time_c.to_be_bytes(),
        ]
        .concat()
    }

    /// Decode (sizes only; the keys are checked when used).
    ///
    /// # Errors
    /// `bad_frame`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let h = Self {
            kid: r.array().map_err(e)?,
            ct_s: r.take(KEM_CIPHERTEXT_LEN).map_err(e)?.to_vec(),
            ek_c: r.take(KEM_PUBLIC_KEY_LEN).map_err(e)?.to_vec(),
            nonce_c: r.array().map_err(e)?,
            time_c: r.u64().map_err(e)?,
        };
        r.finish().map_err(e)?;
        Ok(h)
    }
}

impl Resume {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut o = u32::try_from(self.ticket.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        o.extend_from_slice(&self.ticket);
        o.extend_from_slice(&self.ek_c);
        o.extend_from_slice(&self.nonce_c);
        o.extend_from_slice(&self.time_c.to_be_bytes());
        o
    }

    /// Decode.
    ///
    /// # Errors
    /// `bad_frame`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let h = Self {
            ticket: r.lp(MAX_TICKET).map_err(e)?.to_vec(),
            ek_c: r.take(KEM_PUBLIC_KEY_LEN).map_err(e)?.to_vec(),
            nonce_c: r.array().map_err(e)?,
            time_c: r.u64().map_err(e)?,
        };
        r.finish().map_err(e)?;
        if h.ticket.is_empty() {
            return Err(Code::BadFrame);
        }
        Ok(h)
    }
}

impl Reply {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &[self.mode][..],
            &self.generation.to_be_bytes(),
            &self.ct_c,
            &self.nonce_s,
            &self.time_s.to_be_bytes(),
            &self.confirm,
        ]
        .concat()
    }

    /// Decode.
    ///
    /// # Errors
    /// `bad_frame`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let h = Self {
            mode: r.array::<1>().map_err(e)?[0],
            generation: r.u32().map_err(e)?,
            ct_c: r.take(KEM_CIPHERTEXT_LEN).map_err(e)?.to_vec(),
            nonce_s: r.array().map_err(e)?,
            time_s: r.u64().map_err(e)?,
            confirm: r.array().map_err(e)?,
        };
        r.finish().map_err(e)?;
        if h.mode > 1 || (h.mode == 0) != (h.generation == 0) {
            return Err(Code::BadFrame);
        }
        Ok(h)
    }
}

/// The full-handshake transcript hash.
///
/// # Errors
/// Never in practice.
pub fn transcript(unit: Unit, h: &Hello, sid: &[u8; SID_LEN], r: &Reply) -> Result<[u8; TH_LEN]> {
    labelled_hash(
        label::TRANSCRIPT,
        &[
            &[VERSION, unit.to_u8()],
            &h.kid,
            &h.ct_s,
            &h.ek_c,
            &h.nonce_c,
            &h.time_c.to_be_bytes(),
            sid,
            &[r.mode],
            &r.generation.to_be_bytes(),
            &r.ct_c,
            &r.nonce_s,
            &r.time_s.to_be_bytes(),
        ],
    )
    .map_err(|_| Code::Internal)
}

/// The resumption transcript hash (`resume` is the RESUME body as sent).
///
/// # Errors
/// Never in practice.
pub fn transcript_resume(
    unit: Unit,
    resume: &[u8],
    sid: &[u8; SID_LEN],
    r: &Reply,
) -> Result<[u8; TH_LEN]> {
    labelled_hash(
        label::TRANSCRIPT_RESUME,
        &[
            &[VERSION, unit.to_u8()],
            resume,
            sid,
            &[r.mode],
            &r.generation.to_be_bytes(),
            &r.ct_c,
            &r.nonce_s,
            &r.time_s.to_be_bytes(),
        ],
    )
    .map_err(|_| Code::Internal)
}

/// What a finished handshake yields on either end.
pub struct Keys {
    /// The transcript hash.
    pub th: [u8; TH_LEN],
    /// Key confirmation (public once sent).
    pub confirm: [u8; 32],
    /// This end's sealer.
    pub tx: TransitSealer,
    /// This end's opener.
    pub rx: TransitOpener,
    /// The secret for the next resumption ticket.
    pub resumption: Secret32,
}

/// The session channel id.
#[must_use]
pub fn channel(unit: Unit, sid: &[u8; SID_LEN]) -> Vec<u8> {
    [&b"HTP2"[..], &[unit.to_u8()], sid].concat()
}

/// Derive both directions' keys from a master secret. `master_label` picks full or resumed.
///
/// # Errors
/// Never in practice.
pub fn schedule(
    master_label: &str,
    secrets: [&Secret32; 2],
    th: [u8; TH_LEN],
    unit: Unit,
    sid: &[u8; SID_LEN],
    role: Role,
) -> Result<Keys> {
    let i = |_| Code::Internal;
    let master = kdf::<32>(
        master_label,
        &[secrets[0].expose(), secrets[1].expose()],
        &[&th],
    )
    .map_err(i)?;
    let confirm = *kdf::<32>(label::CONFIRM, &[master.expose()], &[&th])
        .map_err(i)?
        .expose();
    let session = kdf::<32>(label::SESSION, &[master.expose()], &[&th]).map_err(i)?;
    let resumption = kdf::<32>(label::RESUMPTION, &[master.expose()], &[&th]).map_err(i)?;
    let (tx, rx) = transit_channel(session, &channel(unit, sid), role).map_err(i)?;
    Ok(Keys {
        th,
        confirm,
        tx,
        rx,
        resumption,
    })
}

/// Parse a hybrid KEM public key.
///
/// # Errors
/// `handshake_failed`.
pub fn kem_pk(b: &[u8]) -> Result<KemPublicKey> {
    KemPublicKey::from_bytes(b).map_err(|_| Code::HandshakeFailed)
}

/// Parse a hybrid KEM ciphertext.
///
/// # Errors
/// `handshake_failed`.
pub fn kem_ct(b: &[u8]) -> Result<KemCiphertext> {
    KemCiphertext::from_bytes(b).map_err(|_| Code::HandshakeFailed)
}

/// Constant-time check of a confirmation.
#[must_use]
pub fn confirms(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_round_trip_and_refuse_bad_sizes() {
        let h = Hello {
            kid: [1; 32],
            ct_s: vec![2; KEM_CIPHERTEXT_LEN],
            ek_c: vec![3; KEM_PUBLIC_KEY_LEN],
            nonce_c: [4; 32],
            time_c: 5,
        };
        let b = h.encode();
        assert_eq!(b.len(), 3298);
        assert_eq!(Hello::decode(&b).unwrap(), h);
        assert!(Hello::decode(&b[1..]).is_err());
        assert!(Hello::decode(&[b.clone(), vec![0]].concat()).is_err());
        let r = Resume {
            ticket: vec![9; 98],
            ek_c: vec![3; KEM_PUBLIC_KEY_LEN],
            nonce_c: [4; 32],
            time_c: 5,
        };
        assert_eq!(Resume::decode(&r.encode()).unwrap(), r);
        let mut empty = r.clone();
        empty.ticket.clear();
        assert!(Resume::decode(&empty.encode()).is_err());
        let p = Reply {
            mode: 1,
            generation: 3,
            ct_c: vec![1; KEM_CIPHERTEXT_LEN],
            nonce_s: [2; 32],
            time_s: 3,
            confirm: [4; 32],
        };
        assert_eq!(Reply::decode(&p.encode()).unwrap(), p);
        let mut bad = p.encode();
        bad[0] = 2;
        assert!(Reply::decode(&bad).is_err());
    }
}
