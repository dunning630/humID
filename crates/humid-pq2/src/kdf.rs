//! KMAC256 (NIST SP 800-185) and the one HUMID-PQ2 key-derivation function.
//!
//! ```text
//! KDF(label, key = [k1, k2, …], context = [c1, c2, …], L bytes) =
//!     KMAC256(K = lp(k1, k2, …), X = SUITE ‖ lp(c1, c2, …), L·8, S = label)
//! ```
//!
//! KMAC256 is built here on cSHAKE256 (`N = "KMAC"`), exactly as SP 800-185 §4.3 defines
//! it; it is checked against NIST's ACVP KMAC-256 vectors and the SP 800-185 samples.

use cshake::CShake256;
use cshake::digest::{ExtendableOutput, Update, XofReader};

use crate::encoding::{SUITE, len_u32};
use crate::secret::Secret;
use crate::{Error, Result};

/// The cSHAKE256 / KMAC256 rate in bytes.
const RATE: usize = 136;

/// SP 800-185 `left_encode(x)`: the minimal big-endian bytes of `x` (at least one),
/// preceded by their count.
fn left_encode(x: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[1..].copy_from_slice(&x.to_be_bytes());
    let skip = buf[1..8].iter().take_while(|&&b| b == 0).count();
    // `skip` ≤ 7, so the count is 1..=8 and fits a byte.
    buf[skip] = (8 - skip) as u8;
    &buf[skip..]
}

/// SP 800-185 `right_encode(x)`: the minimal big-endian bytes of `x`, followed by their count.
fn right_encode(x: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[..8].copy_from_slice(&x.to_be_bytes());
    let skip = buf[..7].iter().take_while(|&&b| b == 0).count();
    buf[8] = (8 - skip) as u8;
    &buf[skip..]
}

/// A KMAC256 computation whose key is absorbed piece by piece, so a key made of several
/// secrets never has to be copied into one buffer.
struct Kmac256 {
    inner: CShake256,
}

impl Kmac256 {
    /// Start KMAC256 with customization `s`, for a key of `key_len` bytes that the caller
    /// then absorbs with [`Kmac256::key`] before [`Kmac256::end_key`].
    fn start(s: &[u8], key_len: usize) -> Result<(Self, usize)> {
        let mut inner = CShake256::new_with_function_name(b"KMAC", s);
        let mut b = [0u8; 9];
        let bits = u64::try_from(key_len)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::Length)?;
        // bytepad(encode_string(K), 136) = left_encode(136) ‖ left_encode(|K|·8) ‖ K ‖ 0…
        let a = left_encode(RATE as u64, &mut b);
        let mut absorbed = a.len();
        inner.update(a);
        let e = left_encode(bits, &mut b);
        absorbed += e.len();
        inner.update(e);
        Ok((Self { inner }, absorbed + key_len))
    }

    fn key(&mut self, part: &[u8]) {
        self.inner.update(part);
    }

    fn end_key(&mut self, absorbed: usize) {
        let pad = (RATE - absorbed % RATE) % RATE;
        let zeros = [0u8; RATE];
        self.inner.update(&zeros[..pad]);
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish with `right_encode(L)` (`L = 0` for the XOF form) and squeeze `out`.
    fn finish(mut self, out: &mut [u8], xof: bool) -> Result<()> {
        let mut b = [0u8; 9];
        let bits = if xof {
            0
        } else {
            u64::try_from(out.len())
                .ok()
                .and_then(|n| n.checked_mul(8))
                .ok_or(Error::Length)?
        };
        self.inner.update(right_encode(bits, &mut b));
        self.inner.finalize_xof().read(out);
        Ok(())
    }
}

/// KMAC256(K, X, L, S) or, with `xof`, KMACXOF256. Used by the KATs; the suite itself
/// only ever calls [`kdf`].
pub(crate) fn kmac256(
    key: &[u8],
    msg: &[u8],
    custom: &[u8],
    out: &mut [u8],
    xof: bool,
) -> Result<()> {
    let (mut k, absorbed) = Kmac256::start(custom, key.len())?;
    k.key(key);
    k.end_key(absorbed);
    k.update(msg);
    k.finish(out, xof)
}

/// Every label is `"HUMID-PQ2 "` followed by 1–48 characters from `a-z 0-9 -`.
pub(crate) fn check_label(label: &str) -> Result<()> {
    let rest = label.strip_prefix("HUMID-PQ2 ").ok_or(Error::Label)?;
    if rest.is_empty()
        || rest.len() > 48
        || !rest
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(Error::Label);
    }
    Ok(())
}

/// The HUMID-PQ2 KDF, writing `out.len()` bytes (1 to 8192).
///
/// # Errors
/// [`Error::Label`] for a malformed label, [`Error::Length`] for an output outside 1–8192
/// bytes or a part of 4 GiB or more.
pub fn kdf_into(label: &str, key: &[&[u8]], context: &[&[u8]], out: &mut [u8]) -> Result<()> {
    check_label(label)?;
    if out.is_empty() || out.len() > 8192 {
        return Err(Error::Length);
    }
    let mut key_len = 0usize;
    for p in key {
        len_u32(p.len())?;
        key_len = key_len.checked_add(4 + p.len()).ok_or(Error::Length)?;
    }
    let (mut k, absorbed) = Kmac256::start(label.as_bytes(), key_len)?;
    for p in key {
        k.key(&len_u32(p.len())?);
        k.key(p);
    }
    k.end_key(absorbed);
    k.update(&SUITE);
    for c in context {
        k.update(&len_u32(c.len())?);
        k.update(c);
    }
    k.finish(out, false)
}

/// The HUMID-PQ2 KDF, returning `N` secret bytes.
///
/// # Errors
/// As [`kdf_into`].
pub fn kdf<const N: usize>(label: &str, key: &[&[u8]], context: &[&[u8]]) -> Result<Secret<N>> {
    let mut s = Secret::<N>::zero();
    kdf_into(label, key, context, s.as_mut())?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_sp800_185() {
        let mut b = [0u8; 9];
        assert_eq!(left_encode(0, &mut b), [1, 0]);
        assert_eq!(left_encode(136, &mut b), [1, 136]);
        assert_eq!(left_encode(256, &mut b), [2, 1, 0]);
        assert_eq!(right_encode(0, &mut b), [0, 1]);
        assert_eq!(right_encode(512, &mut b), [2, 0, 2]);
        assert_eq!(
            left_encode(u64::MAX, &mut b),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn labels() {
        assert!(check_label("HUMID-PQ2 doc").is_ok());
        assert!(check_label("HUMID-PQ2 device-wrap").is_ok());
        for bad in [
            "HUMID-PQ2 ",
            "HUMID-PQ1 doc",
            "HUMID-PQ2 Doc",
            "HUMID-PQ2 a b",
            "doc",
        ] {
            assert_eq!(check_label(bad), Err(Error::Label), "{bad}");
        }
    }

    #[test]
    fn kdf_is_the_documented_kmac() {
        // KDF(label, [a, b], [c]) == KMAC256(lp(a, b), SUITE ‖ lp(c), L, label)
        let k = crate::encoding::lp(&[b"key-one", b"k2"]).unwrap();
        let mut x = SUITE.to_vec();
        x.extend_from_slice(&crate::encoding::lp(&[b"ctx"]).unwrap());
        let mut want = [0u8; 48];
        kmac256(&k, &x, b"HUMID-PQ2 test", &mut want, false).unwrap();
        let mut got = [0u8; 48];
        kdf_into("HUMID-PQ2 test", &[b"key-one", b"k2"], &[b"ctx"], &mut got).unwrap();
        assert_eq!(got, want);
        // Every input matters, and the part boundaries do too.
        let mut other = [0u8; 48];
        kdf_into(
            "HUMID-PQ2 test",
            &[b"key-on", b"ek2"],
            &[b"ctx"],
            &mut other,
        )
        .unwrap();
        assert_ne!(got, other);
        kdf_into(
            "HUMID-PQ2 test2",
            &[b"key-one", b"k2"],
            &[b"ctx"],
            &mut other,
        )
        .unwrap();
        assert_ne!(got, other);
        kdf_into(
            "HUMID-PQ2 test",
            &[b"key-one", b"k2"],
            &[b"ctx", b""],
            &mut other,
        )
        .unwrap();
        assert_ne!(got, other);
        // L is part of the input: a shorter output is not a prefix.
        let mut short = [0u8; 32];
        kdf_into(
            "HUMID-PQ2 test",
            &[b"key-one", b"k2"],
            &[b"ctx"],
            &mut short,
        )
        .unwrap();
        assert_ne!(short[..], got[..32]);
    }

    #[test]
    fn long_keys_cross_the_rate_boundary() {
        // Key lengths around the 136-byte block, so the bytepad arithmetic is exercised.
        for n in [
            0usize, 1, 127, 128, 129, 130, 131, 132, 135, 136, 137, 271, 272, 400,
        ] {
            let key = vec![0x5au8; n];
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            kmac256(&key, b"m", b"S", &mut a, false).unwrap();
            // the same, absorbing the key in two pieces
            let (mut k, absorbed) = Kmac256::start(b"S", n).unwrap();
            k.key(&key[..n / 2]);
            k.key(&key[n / 2..]);
            k.end_key(absorbed);
            k.update(b"m");
            k.finish(&mut b, false).unwrap();
            assert_eq!(a, b, "{n}");
        }
    }
}
