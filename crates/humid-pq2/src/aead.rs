//! Symmetric encryption.
//!
//! * **At rest:** AES-256-GCM-SIV (RFC 8452), random 96-bit nonce. Nonce-misuse resistant,
//!   so a repeated nonce under a long-lived key leaks only equality of identical messages.
//!   Box: `header(type) ‖ nonce (12) ‖ ciphertext ‖ tag (16)`, AAD
//!   `header(type) ‖ lp(aad parts…)`.
//! * **In transit:** AES-256-GCM. [`transit_channel`] derives one key per (channel,
//!   direction) from a session secret it consumes; nonces are `u32 direction ‖ u64 seq`, each
//!   `seq` used once; the receiver keeps a 256-record replay window.
//!   AAD `header(0x0020) ‖ lp(channel, u32 direction, u64 seq, aad)`.
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
    // Borrowed as an Array: no by-value copy of the key on the stack.
    Aes256GcmSiv::new(<&Array<u8, _>>::from(key.expose()))
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

/// Which end of a channel this is. Each direction gets its own key and its own nonce
/// domain, so the two ends can never produce the same (key, nonce) pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The side that started the handshake (the phone).
    Initiator,
    /// The other side (the server).
    Responder,
}

/// Direction tags: the first 4 nonce bytes, and part of the key derivation.
const I2R: u32 = 0x4932_5201; // "I2R" 1
const R2I: u32 = 0x5232_4901; // "R2I" 1

impl Role {
    fn send_dir(self) -> u32 {
        match self {
            Role::Initiator => I2R,
            Role::Responder => R2I,
        }
    }

    fn recv_dir(self) -> u32 {
        match self {
            Role::Initiator => R2I,
            Role::Responder => I2R,
        }
    }
}

fn transit_nonce(dir: u32, seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&dir.to_be_bytes());
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn transit_aad(channel: &[u8], dir: u32, seq: u64, extra: &[u8]) -> Result<Vec<u8>> {
    aad(
        ObjectType::TRANSIT_RECORD,
        &[channel, &dir.to_be_bytes(), &seq.to_be_bytes(), extra],
    )
}

fn transit_key(secret: &Secret32, channel: &[u8], dir: u32) -> Result<Aes256Gcm> {
    let k = kdf::<32>(
        "HUMID-PQ2 transit",
        &[secret.expose()],
        &[channel, &dir.to_be_bytes()],
    )?;
    Ok(gcm_cipher(&k))
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
    // Borrowed as an Array: no by-value copy of the key on the stack.
    Aes256Gcm::new(<&Array<u8, _>>::from(key.expose()))
}

/// One end of a transit channel: its sealer and opener, from one session secret.
///
/// ```text
/// k_dir  = KDF("HUMID-PQ2 transit", [session_secret], [channel, u32 dir], 32)
/// nonce  = u32 dir ‖ u64 seq                    dir = I2R (0x49325201) or R2I (0x52324901)
/// A      = header(0x0020) ‖ lp(channel, u32 dir, u64 seq, extra_aad)
/// ```
///
/// Nonce reuse is impossible by construction: the channel and direction select the key,
/// the direction is also in the nonce, and `seq` only grows within a sealer. The secret is
/// consumed, so one call per end per session. Rebuilding a sealer (a reconnect, a restart)
/// needs a fresh session secret from a new handshake: never persist `seq` and reuse a secret.
///
/// # Errors
/// Never in practice (fixed label).
pub fn transit_channel(
    session_secret: Secret32,
    channel: &[u8],
    role: Role,
) -> Result<(TransitSealer, TransitOpener)> {
    let tx = TransitSealer {
        cipher: transit_key(&session_secret, channel, role.send_dir())?,
        channel: channel.to_vec(),
        dir: role.send_dir(),
        next: 0,
    };
    let rx = TransitOpener {
        cipher: transit_key(&session_secret, channel, role.recv_dir())?,
        channel: channel.to_vec(),
        dir: role.recv_dir(),
        top: 0,
        seen: [0; 4],
    };
    drop(session_secret);
    Ok((tx, rx))
}

/// The sending half of one direction of a channel. Never reuses a nonce: `seq` only grows.
pub struct TransitSealer {
    cipher: Aes256Gcm,
    channel: Vec<u8>,
    dir: u32,
    next: u64,
}

impl TransitSealer {
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
        let a = transit_aad(&self.channel, self.dir, seq, extra_aad)?;
        Ok((
            seq,
            gcm_seal(&self.cipher, &transit_nonce(self.dir, seq), &a, pt)?,
        ))
    }
}

/// The receiving half: accepts each `seq` at most once, within a 256-record window.
pub struct TransitOpener {
    cipher: Aes256Gcm,
    channel: Vec<u8>,
    dir: u32,
    /// One past the highest `seq` accepted (0 = none yet).
    top: u64,
    /// Bit i set = `top - 1 - i` was accepted.
    seen: [u64; 4],
}

impl TransitOpener {
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
        let a = transit_aad(&self.channel, self.dir, seq, extra_aad)?;
        let buf = gcm_open(&self.cipher, &transit_nonce(self.dir, seq), &a, ct)?;
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
        let (mut tx, _) = transit_channel(k.duplicate(), b"session-1", Role::Initiator).unwrap();
        let (_, mut rx) = transit_channel(k.duplicate(), b"session-1", Role::Responder).unwrap();
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
        let (_, mut rx2) = transit_channel(k.duplicate(), b"session-2", Role::Responder).unwrap();
        assert_eq!(
            rx2.open(recs[0].0, b"hdr", &recs[0].1).unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(
            rx2.open(recs[0].0, b"HDR", &recs[0].1).unwrap_err(),
            Error::Decrypt
        );
    }

    /// Review H3 (PROBE6): two sealers made from one secret, for the two directions or two
    /// channels, must never share a keystream.
    #[test]
    fn transit_never_reuses_a_keystream() {
        let k = Secret32::random().unwrap();
        let (mut a, mut a_rx) = transit_channel(k.duplicate(), b"chan", Role::Initiator).unwrap();
        let (mut b, mut b_rx) = transit_channel(k.duplicate(), b"chan", Role::Responder).unwrap();
        let (mut c, _) = transit_channel(k.duplicate(), b"other", Role::Initiator).unwrap();
        let p1 = [0x41u8; 32];
        let zero = [0u8; 32];
        let (s1, c1) = a.seal(b"", &p1).unwrap();
        let (s2, c2) = b.seal(b"", &zero).unwrap();
        let (_, c3) = c.seal(b"", &zero).unwrap();
        assert_eq!(s1, s2);
        let x12: Vec<u8> = c1[..32].iter().zip(&c2[..32]).map(|(x, y)| x ^ y).collect();
        let x13: Vec<u8> = c1[..32].iter().zip(&c3[..32]).map(|(x, y)| x ^ y).collect();
        assert_ne!(x12, p1.to_vec(), "directions share a keystream");
        assert_ne!(x13, p1.to_vec(), "channels share a keystream");
        // each direction opens only the other end's records
        assert_eq!(&b_rx.open(s1, b"", &c1).unwrap()[..], &p1[..]);
        assert_eq!(&a_rx.open(s2, b"", &c2).unwrap()[..], &zero[..]);
        let (_, mut wrong) = transit_channel(k, b"chan", Role::Initiator).unwrap();
        assert_eq!(
            wrong.open(s1, b"", &c1).unwrap_err(),
            Error::Decrypt,
            "own records reflected back"
        );
        // the nonce carries the direction
        assert_ne!(
            transit_nonce(Role::Initiator.send_dir(), 0),
            transit_nonce(Role::Responder.send_dir(), 0)
        );
    }

    #[test]
    fn transit_window_shift_matches_a_model() {
        // Compare the bitmap window against a plain set, over a pseudo-random schedule.
        let k = Secret32::random().unwrap();
        let (mut tx, _) = transit_channel(k.duplicate(), b"c", Role::Initiator).unwrap();
        let recs: Vec<_> = (0..1200).map(|_| tx.seal(b"", b"").unwrap()).collect();
        let (_, mut rx) = transit_channel(k, b"c", Role::Responder).unwrap();
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
