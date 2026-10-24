//! SHA3-512, SHAKE256 and the suite's labelled hash and key ids.

use sha3::{Digest, Sha3_512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

use crate::Result;
use crate::encoding::{SUITE, len_u32};
use crate::kdf::check_label;

/// SHA3-512 (FIPS 202).
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

/// SHAKE256 (FIPS 202) of `data`, filling `out`.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut h = Shake256::default();
    h.update(data);
    h.finalize_xof().read(out);
}

/// Streaming SHA3-512, for hashing a document chunk by chunk.
#[derive(Clone, Default)]
pub struct Sha3_512Stream(Sha3_512);

impl Sha3_512Stream {
    /// A fresh hash.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb more bytes.
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    /// The digest.
    #[must_use]
    pub fn finish(self) -> [u8; 64] {
        self.0.finalize().into()
    }
}

/// The labelled hash: `SHA3-512(SUITE ‖ lp(label, p1, p2, …))`.
///
/// # Errors
/// [`Error::Label`] for a malformed label, [`Error::Length`] for a part of 4 GiB or more.
pub fn labelled_hash(label: &str, parts: &[&[u8]]) -> Result<[u8; 64]> {
    check_label(label)?;
    let mut h = Sha3_512::new();
    Digest::update(&mut h, SUITE);
    Digest::update(&mut h, len_u32(label.len())?);
    Digest::update(&mut h, label.as_bytes());
    for p in parts {
        Digest::update(&mut h, len_u32(p.len())?);
        Digest::update(&mut h, p);
    }
    Ok(h.finalize().into())
}

/// A 32-byte key id: the first 32 bytes of `labelled_hash("HUMID-PQ2 key-id", [encoding])`,
/// where `encoding` is the key's full stand-alone encoding (header included).
#[must_use]
pub fn key_id(encoding: &[u8]) -> [u8; 32] {
    // The label is a constant and an encoding over 4 GiB cannot exist in memory as a key.
    let full = labelled_hash("HUMID-PQ2 key-id", &[encoding]).unwrap_or([0u8; 64]);
    let mut id = [0u8; 32];
    id.copy_from_slice(&full[..32]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips202_empty() {
        assert_eq!(
            hex::encode(sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let mut o = [0u8; 32];
        shake256(b"", &mut o);
        assert_eq!(
            hex::encode(o),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn stream_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut s = Sha3_512Stream::new();
        for c in data.chunks(77) {
            s.update(c);
        }
        assert_eq!(s.finish(), sha3_512(&data));
    }

    #[test]
    fn labelled_hash_layout() {
        let mut want = SUITE.to_vec();
        want.extend_from_slice(&crate::encoding::lp(&[b"HUMID-PQ2 key-id", b"abc"]).unwrap());
        assert_eq!(
            labelled_hash("HUMID-PQ2 key-id", &[b"abc"]).unwrap(),
            sha3_512(&want)
        );
        assert_eq!(key_id(b"abc")[..], sha3_512(&want)[..32]);
    }
}
