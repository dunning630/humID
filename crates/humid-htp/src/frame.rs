//! Frames: what front sees (HTP2.md §3).
//!
//! ```text
//! frame   = header (32) ‖ payload                      total length = CLASSES[class], exactly
//! header  = "HT" ‖ u8 v ‖ u8 kind ‖ u8 unit ‖ u8 class ‖ 00 00 ‖ sid (16) ‖ u64 seq
//! payload = u32 len ‖ body ‖ 00…                       kinds HELLO, RESUME, REPLY, ERROR (cleartext)
//!         = AES-256-GCM record of (u32 len ‖ msg ‖ 00…)  kind RECORD (the header is its AAD)
//! ```
//!
//! The header is all front can read: version, kind, which unit, a size class, the session
//! id and the record counter. Everything else is either a fixed-size handshake field (KEM
//! ciphertexts and public keys, nonces) or inside a record.

use crate::{Code, Result, SID_LEN, Unit, VERSION};

/// Header bytes.
pub const HEADER_LEN: usize = 32;
/// The two magic bytes.
pub const MAGIC: [u8; 2] = *b"HT";
/// Frame sizes, by class: 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, and 1 MiB + 8 KiB (one
/// full body chunk with its message framing).
pub const CLASSES: [usize; 6] = [
    1 << 10,
    4 << 10,
    16 << 10,
    64 << 10,
    256 << 10,
    (1 << 20) + (8 << 10),
];
/// AEAD tag bytes in a record.
pub const TAG_LEN: usize = 16;

/// What a frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A full handshake (client → server), cleartext.
    Hello,
    /// A resumption (client → server), cleartext.
    Resume,
    /// The server's handshake answer, cleartext; its header carries the new session id.
    Reply,
    /// An encrypted record inside a session.
    Record,
    /// An unauthenticated refusal (anyone on the path could have sent it).
    Error,
}

impl Kind {
    /// The wire byte.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Kind::Hello => 1,
            Kind::Resume => 2,
            Kind::Reply => 3,
            Kind::Record => 4,
            Kind::Error => 5,
        }
    }

    /// The kind for a wire byte.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Kind::Hello,
            2 => Kind::Resume,
            3 => Kind::Reply,
            4 => Kind::Record,
            5 => Kind::Error,
            _ => return None,
        })
    }
}

/// A frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Kind.
    pub kind: Kind,
    /// Unit.
    pub unit: Unit,
    /// Size class (index into [`CLASSES`]).
    pub class: u8,
    /// Session id (zero in hellos).
    pub sid: [u8; SID_LEN],
    /// Record counter (zero outside records).
    pub seq: u64,
}

impl Header {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..2].copy_from_slice(&MAGIC);
        h[2] = VERSION;
        h[3] = self.kind.to_u8();
        h[4] = self.unit.to_u8();
        h[5] = self.class;
        h[8..24].copy_from_slice(&self.sid);
        h[24..].copy_from_slice(&self.seq.to_be_bytes());
        h
    }

    /// Decode and check a header (not the payload).
    ///
    /// # Errors
    /// `version_unsupported` for another `v`; `bad_frame` for anything else malformed;
    /// `unit_unknown` for an unknown unit byte.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN || b[..2] != MAGIC {
            return Err(Code::BadFrame);
        }
        if b[2] != VERSION {
            return Err(Code::VersionUnsupported);
        }
        let kind = Kind::from_u8(b[3]).ok_or(Code::BadFrame)?;
        let unit = Unit::from_u8(b[4]).ok_or(Code::UnitUnknown)?;
        let class = b[5];
        if usize::from(class) >= CLASSES.len() || b[6] != 0 || b[7] != 0 {
            return Err(Code::BadFrame);
        }
        let mut sid = [0u8; SID_LEN];
        sid.copy_from_slice(&b[8..24]);
        let mut s = [0u8; 8];
        s.copy_from_slice(&b[24..32]);
        let seq = u64::from_be_bytes(s);
        let zero_sid = sid == [0u8; SID_LEN];
        let ok = match kind {
            Kind::Hello | Kind::Resume => zero_sid && seq == 0,
            Kind::Reply => !zero_sid && seq == 0,
            Kind::Record => !zero_sid,
            Kind::Error => seq == 0,
        };
        if !ok {
            return Err(Code::BadFrame);
        }
        Ok(Self {
            kind,
            unit,
            class,
            sid,
            seq,
        })
    }

    /// Total frame length for this header's class.
    #[must_use]
    pub fn frame_len(&self) -> usize {
        CLASSES[usize::from(self.class)]
    }
}

/// The smallest class whose frames hold `payload` bytes, at least `min_class`.
///
/// # Errors
/// `too_large` when no class does.
pub fn class_for(payload: usize, min_class: u8) -> Result<u8> {
    CLASSES
        .iter()
        .enumerate()
        .skip(usize::from(min_class))
        .find(|(_, c)| **c - HEADER_LEN >= payload)
        .map(|(i, _)| u8::try_from(i).unwrap_or(0))
        .ok_or(Code::TooLarge)
}

/// Largest message one record of the top class carries.
pub const MAX_RECORD_MSG: usize = CLASSES[CLASSES.len() - 1] - HEADER_LEN - TAG_LEN - 4;
/// Largest body a cleartext frame carries.
pub const MAX_CLEAR_BODY: usize = CLASSES[CLASSES.len() - 1] - HEADER_LEN - 4;

/// `u32 len ‖ body ‖ zeros` to exactly `size` bytes.
///
/// # Errors
/// `too_large` if it doesn't fit.
pub fn pad(body: &[u8], size: usize) -> Result<Vec<u8>> {
    let n = u32::try_from(body.len()).map_err(|_| Code::TooLarge)?;
    if body.len() + 4 > size {
        return Err(Code::TooLarge);
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(body);
    out.resize(size, 0);
    Ok(out)
}

/// The body inside `u32 len ‖ body ‖ zeros`; the padding must be all zero.
///
/// # Errors
/// `bad_frame`.
pub fn unpad(p: &[u8]) -> Result<&[u8]> {
    if p.len() < 4 {
        return Err(Code::BadFrame);
    }
    let n = usize::try_from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
        .map_err(|_| Code::BadFrame)?;
    let end = n.checked_add(4).ok_or(Code::BadFrame)?;
    if end > p.len() || p[end..].iter().any(|&b| b != 0) {
        return Err(Code::BadFrame);
    }
    Ok(&p[4..end])
}

/// A cleartext frame: header and padded body.
///
/// # Errors
/// `too_large`.
pub fn clear(
    kind: Kind,
    unit: Unit,
    sid: [u8; SID_LEN],
    body: &[u8],
    min_class: u8,
) -> Result<Vec<u8>> {
    let class = class_for(body.len() + 4, min_class)?;
    let h = Header {
        kind,
        unit,
        class,
        sid,
        seq: 0,
    };
    let mut out = h.encode().to_vec();
    out.extend_from_slice(&pad(body, h.frame_len() - HEADER_LEN)?);
    Ok(out)
}

/// An unauthenticated error frame.
#[must_use]
pub fn error(unit: Unit, sid: [u8; SID_LEN], code: Code) -> Vec<u8> {
    clear(Kind::Error, unit, sid, &code.to_u16().to_be_bytes(), 0).unwrap_or_default()
}

/// One frame cut from a byte stream: its header and its full bytes.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The header.
    pub header: Header,
    /// The whole frame, header included.
    pub bytes: &'a [u8],
}

impl<'a> Frame<'a> {
    /// The payload (after the header).
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_LEN..]
    }

    /// The body of a cleartext frame.
    ///
    /// # Errors
    /// `bad_frame` for a record, or bad padding.
    pub fn clear_body(&self) -> Result<&'a [u8]> {
        if self.header.kind == Kind::Record {
            return Err(Code::BadFrame);
        }
        unpad(self.payload())
    }

    /// The code in an error frame.
    ///
    /// # Errors
    /// `bad_frame`.
    pub fn error_code(&self) -> Result<Code> {
        if self.header.kind != Kind::Error {
            return Err(Code::BadFrame);
        }
        let b = self.clear_body()?;
        if b.len() != 2 {
            return Err(Code::BadFrame);
        }
        Code::from_u16(u16::from_be_bytes([b[0], b[1]])).ok_or(Code::BadFrame)
    }
}

/// Cut a byte stream (one HTTP body) into frames. Checks every header and every length
/// before returning anything; never reads past the input.
///
/// # Errors
/// The first malformed header, or `bad_frame` for a cut-short frame or an empty input.
pub fn split(mut b: &[u8]) -> Result<Vec<Frame<'_>>> {
    let mut out = vec![];
    if b.is_empty() {
        return Err(Code::BadFrame);
    }
    while !b.is_empty() {
        let header = Header::decode(b)?;
        let n = header.frame_len();
        if b.len() < n {
            return Err(Code::BadFrame);
        }
        out.push(Frame {
            header,
            bytes: &b[..n],
        });
        b = &b[n..];
        if out.len() > 4096 {
            return Err(Code::TooLarge);
        }
    }
    Ok(out)
}

/// What front checks before forwarding a call: every frame well-formed, one unit, and either
/// one handshake frame or records of a single session. Returns the unit and the session id
/// (zero for a handshake).
///
/// # Errors
/// `bad_frame` for mixed units or sessions, a server-side kind, or a malformed frame.
pub fn route(b: &[u8]) -> Result<(Unit, Kind, [u8; SID_LEN])> {
    let frames = split(b)?;
    let first = frames[0].header;
    match first.kind {
        Kind::Hello | Kind::Resume if frames.len() == 1 => {}
        Kind::Record
            if frames.iter().all(|f| {
                f.header.kind == Kind::Record
                    && f.header.unit == first.unit
                    && f.header.sid == first.sid
            }) => {}
        _ => return Err(Code::BadFrame),
    }
    Ok((first.unit, first.kind, first.sid))
}

/// Seal one message as a record frame of at least `min_class`. The header (with the
/// sealer's next `seq`) is the record's additional data.
///
/// # Errors
/// `too_large` if no class holds it.
pub fn seal_record(
    tx: &mut humid_pq2::TransitSealer,
    unit: Unit,
    sid: [u8; SID_LEN],
    msg: &[u8],
    min_class: u8,
) -> Result<Vec<u8>> {
    let class = class_for(msg.len() + 4 + TAG_LEN, min_class)?;
    let h = Header {
        kind: Kind::Record,
        unit,
        class,
        sid,
        seq: tx.next_seq(),
    };
    let hb = h.encode();
    let pt = zeroize::Zeroizing::new(pad(msg, h.frame_len() - HEADER_LEN - TAG_LEN)?);
    let (seq, ct) = tx.seal(&hb, &pt).map_err(Code::from)?;
    if seq != h.seq {
        return Err(Code::Internal);
    }
    let mut out = hb.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a record frame: its tag, under its header, once. Returns the message.
///
/// # Errors
/// `bad_record` (didn't authenticate), `replay` (seen, or older than the window),
/// `bad_frame` (bad padding inside).
pub fn open_record(
    rx: &mut humid_pq2::TransitOpener,
    f: &Frame<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if f.header.kind != Kind::Record {
        return Err(Code::BadFrame);
    }
    let pt = rx
        .open(f.header.seq, &f.bytes[..HEADER_LEN], f.payload())
        .map_err(Code::from)?;
    Ok(zeroize::Zeroizing::new(unpad(&pt)?.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_and_checks() {
        let h = Header {
            kind: Kind::Record,
            unit: Unit::Core,
            class: 2,
            sid: [7; 16],
            seq: 9,
        };
        let e = h.encode();
        assert_eq!(Header::decode(&e).unwrap(), h);
        let mut v = e;
        v[2] = 2;
        assert_eq!(Header::decode(&v), Err(Code::VersionUnsupported));
        let mut v = e;
        v[2] = 0;
        assert_eq!(
            Header::decode(&v),
            Err(Code::VersionUnsupported),
            "no downgrade to an older v"
        );
        let mut v = e;
        v[4] = 9;
        assert_eq!(Header::decode(&v), Err(Code::UnitUnknown));
        let mut v = e;
        v[5] = 6;
        assert_eq!(Header::decode(&v), Err(Code::BadFrame));
        let mut v = e;
        v[7] = 1;
        assert_eq!(Header::decode(&v), Err(Code::BadFrame));
        let mut v = e;
        v[8..24].fill(0);
        assert_eq!(
            Header::decode(&v),
            Err(Code::BadFrame),
            "a record needs a session"
        );
        assert_eq!(Header::decode(&e[..31]), Err(Code::BadFrame));
    }

    #[test]
    fn padding() {
        let p = pad(b"abc", 16).unwrap();
        assert_eq!(p.len(), 16);
        assert_eq!(unpad(&p).unwrap(), b"abc");
        let mut q = p.clone();
        q[15] = 1;
        assert_eq!(unpad(&q), Err(Code::BadFrame), "padding is zeros");
        let mut q = p;
        q[3] = 13;
        assert_eq!(unpad(&q), Err(Code::BadFrame));
        assert!(pad(&[0; 13], 16).is_err());
    }

    #[test]
    fn split_and_route() {
        let a = clear(Kind::Hello, Unit::Core, [0; 16], b"hi", 0).unwrap();
        assert_eq!(a.len(), CLASSES[0]);
        assert_eq!(route(&a).unwrap().0, Unit::Core);
        let two = [a.clone(), a.clone()].concat();
        assert_eq!(route(&two), Err(Code::BadFrame), "one hello per call");
        assert_eq!(split(&a[..a.len() - 1]).unwrap_err(), Code::BadFrame);
        assert_eq!(split(&[]).unwrap_err(), Code::BadFrame);
        let e = error(Unit::Anon, [0; 16], Code::Busy);
        assert_eq!(split(&e).unwrap()[0].error_code().unwrap(), Code::Busy);
        assert_eq!(
            route(&e),
            Err(Code::BadFrame),
            "clients never send error frames"
        );
        assert_eq!(
            class_for(CLASSES[5] - HEADER_LEN + 1, 0),
            Err(Code::TooLarge)
        );
        assert_eq!(class_for(10, 3).unwrap(), 3);
    }
}
