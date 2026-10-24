//! Symmetric encryption.
//!
//! * **At rest:** AES-256-GCM-SIV (RFC 8452), random 96-bit nonce. Nonce-misuse resistant,
//!   so a repeated nonce under a long-lived key leaks only equality of identical messages.
//!   Box: `header(type) ‖ nonce (12) ‖ ciphertext ‖ tag (16)`, AAD
//!   `header(type) ‖ lp(aad parts…)`.
//! * **In transit:** AES-256-GCM with counter nonces `0x00000000 ‖ u64 seq`, one key per
//!   direction, each `seq` used once; the receiver keeps a 256-record replay window.
//!   AAD `header(0x0020) ‖ lp(channel, u64 seq, aad)`.
//! * **Sealed to a public key:** hybrid KEM, then AES-256-GCM-SIV under a one-time key.

use aes_gcm::Aes256Gcm;
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{AeadInOut, KeyInit, array::Array};
use zeroize::Zeroizing;

use crate::encoding::{HEADER_LEN, ObjectType, aad, header};
use crate::kdf::kdf;
use crate::kem::{KemCiphertext, KemPublicKey, KemSecretKey, MLKEM_CT_LEN, X25519_LEN};
use crate::secret::Secret32;
use crate::{Error, Result, rng};

/// AEAD nonce bytes.
pub const NONCE_LEN: usize = 12;
/// AEAD tag bytes.
pub const TAG_LEN: usize = 16;
/// Largest plaintext one at-rest box or transit record may hold (64 MiB). Larger data is
/// chunked (humid-core's document envelope).
pub const MAX_PLAINTEXT: usize = 64 << 20;
/// Overhead of an at-rest box: header + nonce + tag.
pub const BOX_OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;
/// Overhead of a sealed box: header + raw KEM ciphertext + tag.
pub const SEALED_OVERHEAD: usize = HEADER_LEN + MLKEM_CT_LEN + X25519_LEN + TAG_LEN;

fn siv(key: &Secret32) -> Aes256GcmSiv {
    Aes256GcmSiv::new(&Array::from(*key.expose()))
}

/// Raw AES-256-GCM-SIV (RFC 8452): returns `ciphertext ‖ tag`. The caller owns the nonce:
/// use it only under a one-time key or with a counter that never repeats under that key
/// (humid-core's document chunks and device slots). Everything else uses [`seal_at_rest`].
///
/// # Errors
/// [`Error::Length`] over [`MAX_PLAINTEXT`].
pub fn siv_seal(key: &Secret32, nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    if pt.len() > MAX_PLAINTEXT {
        return Err(Error::Length);
    }
    let mut buf = pt.to_vec();
    let tag = siv(key)
        .encrypt_inout_detached(&Array::from(*nonce), aad, buf.as_mut_slice().into())
        .map_err(|_| Error::Length)?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Open raw AES-256-GCM-SIV `ciphertext ‖ tag`. The plaintext is wiped on drop.
///
/// # Errors
/// [`Error::Decrypt`] if authentication fails; [`Error::Length`] over [`MAX_PLAINTEXT`].
pub fn siv_open(
    key: &Secret32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let n = ct.len().checked_sub(TAG_LEN).ok_or(Error::Decrypt)?;
    if n > MAX_PLAINTEXT {
        return Err(Error::Length);
    }
    let tag = Array::try_from(&ct[n..]).map_err(|_| Error::Decrypt)?;
    let mut buf = Zeroizing::new(ct[..n].to_vec());
    siv(key)
        .decrypt_inout_detached(&Array::from(*nonce), aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Decrypt)?;
    Ok(buf)
}

/// Seal `pt` at rest as object type `t`, binding `aad_parts` (ids, revisions…).
///
/// # Errors
/// [`Error::Length`] over [`MAX_PLAINTEXT`]; [`Error::Rng`] if the generator fails.
pub fn seal_at_rest(
    key: &Secret32,
    t: ObjectType,
    aad_parts: &[&[u8]],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;
    seal_at_rest_with_nonce(key, t, aad_parts, pt, &nonce)
}

pub(crate) fn seal_at_rest_with_nonce(
    key: &Secret32,
    t: ObjectType,
    aad_parts: &[&[u8]],
    pt: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let a = aad(t, aad_parts)?;
    let ct = siv_seal(key, nonce, &a, pt)?;
    let mut out = Vec::with_capacity(BOX_OVERHEAD + pt.len());
    out.extend_from_slice(&header(t));
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open an at-rest box of type `t` with the same `aad_parts`.
///
/// # Errors
/// [`Error::Encoding`] for a wrong header or a box too short; [`Error::Decrypt`] if
/// authentication fails.
pub fn open_at_rest(
    key: &Secret32,
    t: ObjectType,
    aad_parts: &[&[u8]],
    boxed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if boxed.len() < BOX_OVERHEAD || boxed[..HEADER_LEN] != header(t) {
        return Err(Error::Encoding);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&boxed[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let a = aad(t, aad_parts)?;
    siv_open(key, &nonce, &a, &boxed[HEADER_LEN + NONCE_LEN..])
}

/* ------------------------------ sealed boxes ------------------------------ */

fn sealed_key(
    ss: &Secret32,
    t: ObjectType,
    kem_raw: &[u8],
    recipient: &KemPublicKey,
) -> Result<Secret32> {
    kdf::<32>(
        "HUMID-PQ2 sealed-box",
        &[ss.expose()],
        &[&header(t), kem_raw, &recipient.key_id()],
    )
}

/// Seal `pt` to `recipient` as object type `t`:
/// `header(t) ‖ ML-KEM ct (1568) ‖ X25519 eph (32) ‖ GCM-SIV(k, nonce 0¹², aad, pt)`, with
/// `k = KDF("HUMID-PQ2 sealed-box", [ss], [header(t), kem ct, key_id(recipient)])` and
/// `aad = header(t) ‖ lp(aad_parts…)`. The key is used once, so the zero nonce is safe.
///
/// # Errors
/// [`Error::Length`] over [`MAX_PLAINTEXT`]; [`Error::Rng`]; [`Error::KeyAgreement`].
pub fn seal_to(
    recipient: &KemPublicKey,
    t: ObjectType,
    aad_parts: &[&[u8]],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let (ct, ss) = recipient.encapsulate()?;
    seal_to_with(recipient, &ct, &ss, t, aad_parts, pt)
}

pub(crate) fn seal_to_with(
    recipient: &KemPublicKey,
    ct: &KemCiphertext,
    ss: &Secret32,
    t: ObjectType,
    aad_parts: &[&[u8]],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let kem_raw = &ct.to_bytes()[HEADER_LEN..];
    let k = sealed_key(ss, t, kem_raw, recipient)?;
    let a = aad(t, aad_parts)?;
    let body = siv_seal(&k, &[0u8; NONCE_LEN], &a, pt)?;
    let mut out = Vec::with_capacity(SEALED_OVERHEAD + pt.len());
    out.extend_from_slice(&header(t));
    out.extend_from_slice(kem_raw);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a box sealed to `sk` as type `t`.
///
/// # Errors
/// [`Error::Encoding`] for a wrong header or a box too short; [`Error::Decrypt`] if it was
/// not sealed to this key with these `aad_parts`; [`Error::KeyAgreement`].
pub fn open_sealed(
    sk: &KemSecretKey,
    t: ObjectType,
    aad_parts: &[&[u8]],
    boxed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if boxed.len() < SEALED_OVERHEAD || boxed[..HEADER_LEN] != header(t) {
        return Err(Error::Encoding);
    }
    let kem_end = HEADER_LEN + MLKEM_CT_LEN + X25519_LEN;
    let mut enc = header(ObjectType::KEM_CIPHERTEXT).to_vec();
    enc.extend_from_slice(&boxed[HEADER_LEN..kem_end]);
    let ct = KemCiphertext::from_bytes(&enc)?;
    let ss = sk.decapsulate(&ct)?;
    let k = sealed_key(&ss, t, &boxed[HEADER_LEN..kem_end], sk.public_key())?;
    let a = aad(t, aad_parts)?;
    siv_open(&k, &[0u8; NONCE_LEN], &a, &boxed[kem_end..])
}

/* -------------------------------- transit -------------------------------- */

/// Replay window, in records.
pub const REPLAY_WINDOW: u64 = 256;

fn transit_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn transit_aad(channel: &[u8], seq: u64, extra: &[u8]) -> Result<Vec<u8>> {
    aad(
        ObjectType::TRANSIT_RECORD,
        &[channel, &seq.to_be_bytes(), extra],
    )
}

/// Raw AES-256-GCM: `ciphertext ‖ tag`.
pub(crate) fn gcm_seal(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    if pt.len() > MAX_PLAINTEXT {
        return Err(Error::Length);
    }
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&Array::from(*nonce), aad, buf.as_mut_slice().into())
        .map_err(|_| Error::Length)?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Raw AES-256-GCM open of `ciphertext ‖ tag`.
pub(crate) fn gcm_open(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let n = ct.len().checked_sub(TAG_LEN).ok_or(Error::Decrypt)?;
    if n > MAX_PLAINTEXT {
        return Err(Error::Length);
    }
    let tag = Array::try_from(&ct[n..]).map_err(|_| Error::Decrypt)?;
    let mut buf = Zeroizing::new(ct[..n].to_vec());
    cipher
        .decrypt_inout_detached(&Array::from(*nonce), aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Decrypt)?;
    Ok(buf)
}

pub(crate) fn gcm_cipher(key: &Secret32) -> Aes256Gcm {
    Aes256Gcm::new(&Array::from(*key.expose()))
}

/// The sending half of one direction of a channel. Never reuses a nonce: `seq` only grows.
pub struct TransitSealer {
    cipher: Aes256Gcm,
    channel: Vec<u8>,
    next: u64,
}

impl TransitSealer {
    /// A sealer for `channel` (a session id, say) under this direction's key.
    #[must_use]
    pub fn new(key: &Secret32, channel: &[u8]) -> Self {
        Self {
            cipher: gcm_cipher(key),
            channel: channel.to_vec(),
            next: 0,
        }
    }

    /// The `seq` the next record will use.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next
    }

    /// Seal one record. Returns `(seq, ciphertext ‖ tag)`; send `seq` with it.
    ///
    /// # Errors
    /// [`Error::Counter`] after 2⁶⁴−1 records; [`Error::Length`] over [`MAX_PLAINTEXT`].
    pub fn seal(&mut self, extra_aad: &[u8], pt: &[u8]) -> Result<(u64, Vec<u8>)> {
        if pt.len() > MAX_PLAINTEXT {
            return Err(Error::Length);
        }
        let seq = self.next;
        self.next = seq.checked_add(1).ok_or(Error::Counter)?;
        let a = transit_aad(&self.channel, seq, extra_aad)?;
        Ok((seq, gcm_seal(&self.cipher, &transit_nonce(seq), &a, pt)?))
    }
}

/// The receiving half: accepts each `seq` at most once, within a 256-record window.
pub struct TransitOpener {
    cipher: Aes256Gcm,
    channel: Vec<u8>,
    /// One past the highest `seq` accepted (0 = none yet).
    top: u64,
    /// Bit i set = `top - 1 - i` was accepted.
    seen: [u64; 4],
}

impl TransitOpener {
    /// An opener for `channel` under the peer's sending key.
    #[must_use]
    pub fn new(key: &Secret32, channel: &[u8]) -> Self {
        Self {
            cipher: gcm_cipher(key),
            channel: channel.to_vec(),
            top: 0,
            seen: [0; 4],
        }
    }

    fn bit(&self, i: u64) -> bool {
        (self.seen[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }

    fn shift(&mut self, by: u64) {
        if by >= REPLAY_WINDOW {
            self.seen = [0; 4];
            return;
        }
        let words = (by / 64) as usize;
        let bits = by % 64;
        let old = self.seen;
        for (i, w) in self.seen.iter_mut().enumerate() {
            let src = i.checked_sub(words);
            let lo = src.map_or(0, |s| old[s]);
            let carry = src.and_then(|s| s.checked_sub(1)).map_or(0, |s| old[s]);
            *w = if bits == 0 {
                lo
            } else {
                (lo << bits) | (carry >> (64 - bits))
            };
        }
    }

    /// Open record `seq`. A record is accepted only after its tag checks, and only once.
    ///
    /// # Errors
    /// [`Error::Counter`] for a replayed `seq` or one older than the window;
    /// [`Error::Decrypt`] if authentication fails.
    pub fn open(&mut self, seq: u64, extra_aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if seq < self.top {
            let age = self.top - 1 - seq;
            if age >= REPLAY_WINDOW || self.bit(age) {
                return Err(Error::Counter);
            }
        }
        let a = transit_aad(&self.channel, seq, extra_aad)?;
        let buf = gcm_open(&self.cipher, &transit_nonce(seq), &a, ct)?;
        if seq >= self.top {
            let next = seq.checked_add(1).ok_or(Error::Counter)?;
            self.shift(next - self.top);
            self.top = next;
            self.seen[0] |= 1;
        } else {
            let age = self.top - 1 - seq;
            self.seen[(age / 64) as usize] |= 1 << (age % 64);
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_rest_round_trip_and_binding() {
        let k = Secret32::random().unwrap();
        let b = seal_at_rest(
            &k,
            ObjectType::INDEX_ENTRY,
            &[b"item-1", b"\0\0\0\x05"],
            b"name",
        )
        .unwrap();
        assert_eq!(b.len(), BOX_OVERHEAD + 4);
        assert_eq!(
            &open_at_rest(&k, ObjectType::INDEX_ENTRY, &[b"item-1", b"\0\0\0\x05"], &b).unwrap()[..],
            b"name"
        );
        // another item, another type, another key, a flipped bit: all refused
        assert_eq!(
            open_at_rest(&k, ObjectType::INDEX_ENTRY, &[b"item-2", b"\0\0\0\x05"], &b).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            open_at_rest(&k, ObjectType::SETTINGS, &[b"item-1", b"\0\0\0\x05"], &b).unwrap_err(),
            Error::Encoding
        );
        let k2 = Secret32::random().unwrap();
        assert_eq!(
            open_at_rest(
                &k2,
                ObjectType::INDEX_ENTRY,
                &[b"item-1", b"\0\0\0\x05"],
                &b
            )
            .unwrap_err(),
            Error::Decrypt
        );
        for i in HEADER_LEN..b.len() {
            let mut c = b.clone();
            c[i] ^= 1;
            assert!(
                open_at_rest(&k, ObjectType::INDEX_ENTRY, &[b"item-1", b"\0\0\0\x05"], &c).is_err()
            );
        }
        assert!(open_at_rest(&k, ObjectType::INDEX_ENTRY, &[], &b[..BOX_OVERHEAD - 1]).is_err());
    }

    #[test]
    fn sealed_box() {
        let sk = KemSecretKey::generate().unwrap();
        let other = KemSecretKey::generate().unwrap();
        let b = seal_to(
            sk.public_key(),
            ObjectType::SHARE_UPLOAD,
            &[b"acct", b"doc"],
            b"secret!",
        )
        .unwrap();
        assert_eq!(b.len(), SEALED_OVERHEAD + 7);
        assert_eq!(
            &open_sealed(&sk, ObjectType::SHARE_UPLOAD, &[b"acct", b"doc"], &b).unwrap()[..],
            b"secret!"
        );
        assert_eq!(
            open_sealed(&other, ObjectType::SHARE_UPLOAD, &[b"acct", b"doc"], &b).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            open_sealed(&sk, ObjectType::SHARE_UPLOAD, &[b"acct", b"doc2"], &b).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            open_sealed(&sk, ObjectType::SHARE_RELEASE, &[b"acct", b"doc"], &b).unwrap_err(),
            Error::Encoding
        );
        // re-labelling the header to another type does not open either
        let mut c = b.clone();
        c[..HEADER_LEN].copy_from_slice(&header(ObjectType::SHARE_RELEASE));
        assert_eq!(
            open_sealed(&sk, ObjectType::SHARE_RELEASE, &[b"acct", b"doc"], &c).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn transit_counter_and_replay() {
        let k = Secret32::random().unwrap();
        let mut tx = TransitSealer::new(&k, b"session-1");
        let mut rx = TransitOpener::new(&k, b"session-1");
        let recs: Vec<_> = (0..300)
            .map(|i| tx.seal(b"hdr", format!("m{i}").as_bytes()).unwrap())
            .collect();
        // in order
        assert_eq!(&rx.open(recs[0].0, b"hdr", &recs[0].1).unwrap()[..], b"m0");
        assert_eq!(
            rx.open(recs[0].0, b"hdr", &recs[0].1).unwrap_err(),
            Error::Counter
        );
        // out of order within the window
        assert!(rx.open(recs[5].0, b"hdr", &recs[5].1).is_ok());
        assert!(rx.open(recs[3].0, b"hdr", &recs[3].1).is_ok());
        assert_eq!(
            rx.open(recs[3].0, b"hdr", &recs[3].1).unwrap_err(),
            Error::Counter
        );
        assert!(rx.open(recs[4].0, b"hdr", &recs[4].1).is_ok());
        // a jump; then the oldest falls out of the window
        assert!(rx.open(recs[299].0, b"hdr", &recs[299].1).is_ok());
        assert_eq!(
            rx.open(recs[1].0, b"hdr", &recs[1].1).unwrap_err(),
            Error::Counter
        );
        assert!(rx.open(recs[100].0, b"hdr", &recs[100].1).is_ok());
        assert_eq!(
            rx.open(recs[100].0, b"hdr", &recs[100].1).unwrap_err(),
            Error::Counter
        );
        // a record under the wrong seq, channel or aad fails, and doesn't burn the seq
        assert_eq!(
            rx.open(recs[200].0, b"hdr", &recs[201].1).unwrap_err(),
            Error::Decrypt
        );
        assert!(rx.open(recs[200].0, b"hdr", &recs[200].1).is_ok());
        let mut rx2 = TransitOpener::new(&k, b"session-2");
        assert_eq!(
            rx2.open(recs[0].0, b"hdr", &recs[0].1).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            rx2.open(recs[0].0, b"HDR", &recs[0].1).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn transit_window_shift_matches_a_model() {
        // Compare the bitmap window against a plain set, over a pseudo-random schedule.
        let k = Secret32::random().unwrap();
        let mut tx = TransitSealer::new(&k, b"c");
        let recs: Vec<_> = (0..1200).map(|_| tx.seal(b"", b"").unwrap()).collect();
        let mut rx = TransitOpener::new(&k, b"c");
        let mut accepted = std::collections::BTreeSet::new();
        let mut x: u64 = 12345;
        for _ in 0..4000 {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let s = (x >> 33) % 1200;
            let top = accepted.iter().next_back().map_or(0, |t| t + 1);
            let want = !accepted.contains(&s) && (s >= top || top - 1 - s < REPLAY_WINDOW);
            let got = rx.open(s, b"", &recs[s as usize].1).is_ok();
            assert_eq!(got, want, "seq {s}, top {top}");
            if got {
                accepted.insert(s);
            }
        }
    }
}
