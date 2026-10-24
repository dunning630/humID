//! Byte encodings shared by every HUMID-PQ2 object (docs/v5/PQ2.md, "Encodings").
//!
//! * Integers are big-endian.
//! * `lp(a, b, …)` = `u32(len a) ‖ a ‖ u32(len b) ‖ b …`, so no two part lists encode alike.
//! * Every stand-alone object and every AAD starts with the 13-byte header
//!   `"HUMID-PQ2" ‖ u16 version ‖ u16 type`: the `{suite, v}` tag plus what the bytes are.

use crate::{Error, Result};

/// The suite's name, as it appears in every header.
pub const SUITE_NAME: &[u8; 9] = b"HUMID-PQ2";
/// The suite version. Any change to a primitive, label or layout is a new version.
pub const VERSION: u16 = 1;
/// `{suite, v}`: `"HUMID-PQ2" ‖ u16 version` (11 bytes). Starts every header, and is the
/// second part of every KDF and labelled-hash input.
pub const SUITE: [u8; 11] = *b"HUMID-PQ2\x00\x01";
/// Length of an object header: `SUITE ‖ u16 type`.
pub const HEADER_LEN: usize = 13;

/// What a run of bytes is. One registry for the whole of HumID 5.0 (PQ2.md, "Type codes"):
/// `0x00xx` are suite objects, `0x01xx` are humid-core records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectType(pub u16);

impl ObjectType {
    /// Hybrid KEM public key (ML-KEM-1024 ek ‖ X25519 pk).
    pub const KEM_PUBLIC_KEY: Self = Self(0x0001);
    /// Hybrid KEM ciphertext (ML-KEM-1024 ct ‖ X25519 ephemeral pk).
    pub const KEM_CIPHERTEXT: Self = Self(0x0002);
    /// ML-DSA-87 verifying key.
    pub const MLDSA_VERIFYING_KEY: Self = Self(0x0003);
    /// ML-DSA-87 signature.
    pub const MLDSA_SIGNATURE: Self = Self(0x0004);
    /// SLH-DSA-SHA2-256s verifying key.
    pub const SLH_VERIFYING_KEY: Self = Self(0x0005);
    /// SLH-DSA-SHA2-256s signature.
    pub const SLH_SIGNATURE: Self = Self(0x0006);
    /// Dual (ML-DSA-87 + SLH-DSA-SHA2-256s) verifying key.
    pub const DUAL_VERIFYING_KEY: Self = Self(0x0007);
    /// Dual signature.
    pub const DUAL_SIGNATURE: Self = Self(0x0008);
    /// Generic AES-256-GCM-SIV box at rest (callers normally use their own record type).
    pub const AT_REST_BOX: Self = Self(0x0009);
    /// Generic box sealed to a hybrid KEM public key.
    pub const SEALED_BOX: Self = Self(0x000A);
    /// A document key share sealed by the phone to the key-share service.
    pub const SHARE_UPLOAD: Self = Self(0x0010);
    /// A document key share sealed by the key-share service to a phone's one-time key.
    pub const SHARE_RELEASE: Self = Self(0x0011);
    /// A phone's request for one document's share (names the one-time key to seal it to).
    pub const SHARE_REQUEST: Self = Self(0x0012);
    /// AAD header of an AES-256-GCM transit record.
    pub const TRANSIT_RECORD: Self = Self(0x0020);

    /// humid-core: the device wrap `W_n` of the seeds.
    pub const DEVICE_WRAP: Self = Self(0x0100);
    /// humid-core: a document manifest (the signed header of a document envelope).
    pub const DOC_MANIFEST: Self = Self(0x0101);
    /// humid-core: AAD of each document chunk.
    pub const DOC_CHUNK: Self = Self(0x0102);
    /// humid-core: what the account key signs for a document.
    pub const DOC_SIGNED: Self = Self(0x0103);
    /// humid-core: one device's slot holding a document's `r_doc`.
    pub const DEVICE_SLOT: Self = Self(0x0104);
    /// humid-core: a document's `r_doc` sealed to a joining device, until it has its own slot.
    pub const PENDING_SLOT: Self = Self(0x0105);
    /// humid-core: the account seed sealed to a joining device.
    pub const JOIN_SEED: Self = Self(0x0106);
    /// humid-core: a document's metadata box (name, type, size), under the document's key.
    pub const DOC_META: Self = Self(0x0107);
    /// humid-core: a joining device's self-signed request (also its signature context).
    pub const JOIN_REQUEST: Self = Self(0x0108);
    /// humid-core: a joined device's per-join KEM key, kept until its pending slots are adopted.
    pub const JOIN_KEY: Self = Self(0x0109);
    /// humid-core: a vault index entry.
    pub const INDEX_ENTRY: Self = Self(0x0110);
    /// humid-core: sealed device settings.
    pub const SETTINGS: Self = Self(0x0111);
    /// humid-core: the offline copy.
    pub const OFFLINE_COPY: Self = Self(0x0112);
    /// humid-core: the highest record revision seen per id.
    pub const RECORD_REVS: Self = Self(0x0113);
    /// humid-core: the message store key.
    pub const MSG_STORE: Self = Self(0x0114);

    /// The 2-byte big-endian code.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// `SUITE ‖ u16 type`.
#[must_use]
pub fn header(t: ObjectType) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..11].copy_from_slice(&SUITE);
    h[11..].copy_from_slice(&t.to_be_bytes());
    h
}

/// Check that `bytes` starts with the header for `t`; returns the rest.
///
/// # Errors
/// [`Error::Encoding`] if the bytes are shorter than a header, or name another suite,
/// version or type.
pub fn strip_header(bytes: &[u8], t: ObjectType) -> Result<&[u8]> {
    if bytes.len() < HEADER_LEN || bytes[..HEADER_LEN] != header(t) {
        return Err(Error::Encoding);
    }
    Ok(&bytes[HEADER_LEN..])
}

/// `u32(len)` of a part, refusing parts of 4 GiB or more.
pub(crate) fn len_u32(len: usize) -> Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| Error::Length)
}

/// Append `u32(len part) ‖ part`.
///
/// # Errors
/// [`Error::Length`] for a part of 4 GiB or more.
pub fn lp_push(out: &mut Vec<u8>, part: &[u8]) -> Result<()> {
    out.extend_from_slice(&len_u32(part.len())?);
    out.extend_from_slice(part);
    Ok(())
}

/// `lp(parts…)`.
///
/// # Errors
/// [`Error::Length`] for a part of 4 GiB or more.
pub fn lp(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for p in parts {
        lp_push(&mut out, p)?;
    }
    Ok(out)
}

/// The one AAD builder: `SUITE ‖ u16 type ‖ lp(parts…)`.
///
/// # Errors
/// [`Error::Length`] for a part of 4 GiB or more.
pub fn aad(t: ObjectType, parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut out = header(t).to_vec();
    for p in parts {
        lp_push(&mut out, p)?;
    }
    Ok(out)
}

/// A bounds-checked cursor for decoders. Every read is checked; nothing panics.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Read `buf` from the start.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not read yet.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The next `n` bytes.
    ///
    /// # Errors
    /// [`Error::Encoding`] if fewer remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Encoding)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Encoding)?;
        self.pos = end;
        Ok(s)
    }

    /// The next `N` bytes as an array.
    ///
    /// # Errors
    /// [`Error::Encoding`] if fewer remain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// A big-endian `u16`.
    ///
    /// # Errors
    /// [`Error::Encoding`] if fewer than 2 bytes remain.
    pub fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_be_bytes)
    }

    /// A big-endian `u32`.
    ///
    /// # Errors
    /// [`Error::Encoding`] if fewer than 4 bytes remain.
    pub fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// A big-endian `u64`.
    ///
    /// # Errors
    /// [`Error::Encoding`] if fewer than 8 bytes remain.
    pub fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// A length-prefixed part of at most `max` bytes.
    ///
    /// # Errors
    /// [`Error::Encoding`] if the prefix is cut short, claims more than `max` bytes, or more
    /// than remain.
    pub fn lp(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).map_err(|_| Error::Encoding)?;
        if n > max {
            return Err(Error::Encoding);
        }
        self.take(n)
    }

    /// The header for `t`.
    ///
    /// # Errors
    /// [`Error::Encoding`] if the next 13 bytes are not exactly that header.
    pub fn header(&mut self, t: ObjectType) -> Result<()> {
        if self.take(HEADER_LEN)? == header(t) {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }

    /// Everything left.
    #[must_use]
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Succeeds only when every byte was read: decoders refuse trailing data.
    ///
    /// # Errors
    /// [`Error::Encoding`] if bytes remain.
    pub fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bytes() {
        assert_eq!(
            &header(ObjectType::KEM_PUBLIC_KEY),
            b"HUMID-PQ2\x00\x01\x00\x01"
        );
        assert_eq!(
            &header(ObjectType::DEVICE_WRAP),
            b"HUMID-PQ2\x00\x01\x01\x00"
        );
        assert!(strip_header(b"HUMID-PQ2\x00\x02\x00\x01xx", ObjectType::KEM_PUBLIC_KEY).is_err());
        assert_eq!(
            strip_header(b"HUMID-PQ2\x00\x01\x00\x01xx", ObjectType::KEM_PUBLIC_KEY),
            Ok(&b"xx"[..])
        );
    }

    #[test]
    fn lp_is_unambiguous() {
        assert_eq!(lp(&[b"ab", b""]).unwrap(), b"\0\0\0\x02ab\0\0\0\0");
        assert_ne!(lp(&[b"ab", b"c"]).unwrap(), lp(&[b"a", b"bc"]).unwrap());
        assert_eq!(
            aad(ObjectType::SEALED_BOX, &[b"x"]).unwrap(),
            b"HUMID-PQ2\x00\x01\x00\x0a\0\0\0\x01x"
        );
    }

    #[test]
    fn reader_never_overreads() {
        let mut r = Reader::new(b"\0\0\0\x05abc");
        assert_eq!(r.lp(100), Err(Error::Encoding));
        let mut r = Reader::new(b"\xff\xff\xff\xff");
        assert_eq!(r.lp(usize::MAX), Err(Error::Encoding));
        let mut r = Reader::new(b"\0\0\0\x02ab!");
        assert_eq!(r.lp(2).unwrap(), b"ab");
        assert_eq!(r.finish(), Err(Error::Encoding));
    }
}
