//! The device wrap `W_n` and its per-unlock ratchet (CORE.md §4).
//!
//! ```text
//! K_wrap = KDF("HUMID-PQ2 device-wrap", [HW_n, ss_soft], [account_id, device_id, u64 n, hw_input], 32)
//! W_n    = header(0x0100) ‖ u64 n ‖ account_id (32) ‖ device_id (32) ‖ lp(hw_input)
//!          ‖ nonce (12) ‖ AES-256-GCM-SIV(K_wrap, nonce, A, account seed ‖ device seed) ‖ tag
//! A      = header(0x0100) ‖ lp(account_id, device_id, u64 n, hw_input)
//! ```
//!
//! `ss_soft` is the optional software ML-KEM-1024 + X25519 leg (V5.md); HUMID-PQ2/1 cores pass
//! the empty string. Two slots (`wrap-0`, `wrap-1`; `W_n` lives in slot `n mod 2`) and the
//! store's rollback floor make the ratchet crash-safe: see [`plan`].

use humid_pq2::encoding::{Reader, aad, header, lp_push};
use humid_pq2::{NONCE_LEN, ObjectType, Secret32, kdf, random_bytes, siv_open, siv_seal};

use crate::error::{CoreError, Result};
use crate::gate::MAX_INPUT;
use crate::keys::{SEEDS_LEN, Seeds};

/// The two wrap slot file names.
pub const SLOTS: [&str; 2] = ["wrap-0", "wrap-1"];

/// A decoded (still sealed) device wrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    /// The counter.
    pub n: u64,
    /// The account this wrap belongs to.
    pub account_id: [u8; 32],
    /// The device.
    pub device_id: [u8; 32],
    /// The hardware input that makes `HW_n`.
    pub hw_input: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

fn wrap_key(
    hw: &Secret32,
    account: &[u8; 32],
    device: &[u8; 32],
    n: u64,
    input: &[u8],
) -> Result<Secret32> {
    Ok(kdf::<32>(
        "HUMID-PQ2 device-wrap",
        &[hw.expose(), b""],
        &[account, device, &n.to_be_bytes(), input],
    )?)
}

fn wrap_aad(account: &[u8; 32], device: &[u8; 32], n: u64, input: &[u8]) -> Result<Vec<u8>> {
    Ok(aad(
        ObjectType::DEVICE_WRAP,
        &[account, device, &n.to_be_bytes(), input],
    )?)
}

impl Wrap {
    /// Seal `seeds` as `W_n` under `HW_n`.
    pub(crate) fn seal(
        hw: &Secret32,
        n: u64,
        account_id: [u8; 32],
        device_id: [u8; 32],
        hw_input: Vec<u8>,
        seeds: &Seeds,
    ) -> Result<Self> {
        if hw_input.len() > MAX_INPUT {
            return Err(CoreError::Format);
        }
        let k = wrap_key(hw, &account_id, &device_id, n, &hw_input)?;
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let a = wrap_aad(&account_id, &device_id, n, &hw_input)?;
        let ct = siv_seal(&k, &nonce, &a, seeds.0.expose())?;
        Ok(Self {
            n,
            account_id,
            device_id,
            hw_input,
            nonce,
            ct,
        })
    }

    /// Open with `HW_n`.
    pub(crate) fn open(&self, hw: &Secret32) -> Result<Seeds> {
        let k = wrap_key(
            hw,
            &self.account_id,
            &self.device_id,
            self.n,
            &self.hw_input,
        )?;
        let a = wrap_aad(&self.account_id, &self.device_id, self.n, &self.hw_input)?;
        let pt = siv_open(&k, &self.nonce, &a, &self.ct).map_err(|_| CoreError::WrapUnusable)?;
        Ok(Seeds(
            humid_pq2::Secret::<SEEDS_LEN>::from_slice(&pt).map_err(|_| CoreError::WrapUnusable)?,
        ))
    }

    /// The slot file this wrap lives in.
    #[must_use]
    pub fn slot(&self) -> &'static str {
        SLOTS[(self.n % 2) as usize]
    }

    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = header(ObjectType::DEVICE_WRAP).to_vec();
        v.extend_from_slice(&self.n.to_be_bytes());
        v.extend_from_slice(&self.account_id);
        v.extend_from_slice(&self.device_id);
        // hw_input ≤ MAX_INPUT, so the length prefix can't fail.
        let _ = lp_push(&mut v, &self.hw_input);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }

    /// Decode; never panics.
    ///
    /// # Errors
    /// [`CoreError::Format`] for anything malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::DEVICE_WRAP)?;
        let n = r.u64()?;
        let account_id = r.array()?;
        let device_id = r.array()?;
        let hw_input = r.lp(MAX_INPUT)?.to_vec();
        let nonce = r.array()?;
        let ct = r.rest().to_vec();
        if ct.len() != SEEDS_LEN + humid_pq2::TAG_LEN {
            return Err(CoreError::Format);
        }
        Ok(Self {
            n,
            account_id,
            device_id,
            hw_input,
            nonce,
            ct,
        })
    }
}

/// The wraps to try, in order, given what the slots hold and the rollback floor.
///
/// * Only wraps with `n ≥ floor` count: an older one (a restored backup or image) is a
///   rollback and is refused. The floor is the counter of the last wrap that opened.
/// * Highest `n` first. Two candidates exist after every unlock (the wrap that opened and
///   its successor), and after a crash or a write whose outcome was unknown; the core falls
///   back to the lower one if the higher one doesn't open (CORE.md §4).
///
/// # Errors
/// [`CoreError::NotEnrolled`] with no wrap; [`CoreError::Rollback`] if every wrap is below
/// the floor.
pub fn plan(slots: &[Option<Wrap>], floor: u64) -> Result<Vec<Wrap>> {
    let any = slots.iter().any(Option::is_some);
    let mut c: Vec<Wrap> = slots
        .iter()
        .flatten()
        .filter(|w| w.n >= floor)
        .cloned()
        .collect();
    c.sort_by_key(|w| core::cmp::Reverse(w.n));
    c.dedup_by_key(|w| w.n);
    if c.is_empty() {
        Err(if any {
            CoreError::Rollback
        } else {
            CoreError::NotEnrolled
        })
    } else {
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use humid_pq2::encoding::HEADER_LEN;

    fn seeds() -> Seeds {
        Seeds::new().unwrap()
    }

    #[test]
    fn seal_open_and_binding() {
        let hw = Secret32::random().unwrap();
        let s = seeds();
        let w = Wrap::seal(&hw, 7, [1; 32], [2; 32], b"input".to_vec(), &s).unwrap();
        let back = Wrap::decode(&w.encode()).unwrap();
        assert_eq!(back, w);
        assert!(back.open(&hw).unwrap().0.ct_eq(&s.0));
        assert_eq!(back.slot(), "wrap-1");
        // wrong HW, or any field changed: unusable
        assert!(matches!(
            back.open(&Secret32::random().unwrap()),
            Err(CoreError::WrapUnusable)
        ));
        let enc = w.encode();
        for i in HEADER_LEN..enc.len() {
            let mut e = enc.clone();
            e[i] ^= 0x10;
            if let Ok(x) = Wrap::decode(&e) {
                assert!(x.open(&hw).is_err(), "byte {i}");
            }
        }
    }

    #[test]
    fn plan_prefers_highest_above_floor() {
        let hw = Secret32::random().unwrap();
        let s = seeds();
        let w = |n| Some(Wrap::seal(&hw, n, [1; 32], [2; 32], vec![], &s).unwrap());
        let ns = |r: Result<Vec<Wrap>>| r.map(|v| v.iter().map(|w| w.n).collect::<Vec<_>>());
        assert_eq!(ns(plan(&[None, None], 0)), Err(CoreError::NotEnrolled));
        assert_eq!(ns(plan(&[w(4), w(5)], 4)), Ok(vec![5, 4]));
        assert_eq!(ns(plan(&[w(4), w(5)], 5)), Ok(vec![5]));
        assert_eq!(ns(plan(&[w(4), None], 4)), Ok(vec![4]));
        assert_eq!(ns(plan(&[w(4), w(3)], 5)), Err(CoreError::Rollback));
    }

    #[test]
    fn decode_never_panics() {
        for len in 0..200 {
            let _ = Wrap::decode(&vec![0xAB; len]);
        }
        let mut v = header(ObjectType::DEVICE_WRAP).to_vec();
        v.extend_from_slice(&[0xff; 100]);
        assert!(Wrap::decode(&v).is_err());
    }
}
