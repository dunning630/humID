//! Signatures: ML-DSA-87 (FIPS 204, hedged) for everyday use; SLH-DSA-SHA2-256s
//! (FIPS 205) and the dual ML-DSA-87 + SLH-DSA signature for long-lived roots.
//!
//! Every signature is the FIPS 204 / FIPS 205 *pure* external interface with a context
//! string that carries the suite, the signature's own type and a label:
//!
//! ```text
//! ctx = SUITE ‖ u16 signature-type ‖ label            (≤ 71 bytes; FIPS allows 255)
//! ```
//!
//! So a signature made for one purpose never verifies for another, and the ML-DSA half of
//! a dual signature (type 0x0008) never verifies as a stand-alone ML-DSA signature (0x0004).

use ml_dsa::{MlDsa87, Signature as DsaSig};
use slh_dsa::Sha2_256s;
use zeroize::Zeroizing;

use crate::encoding::{HEADER_LEN, ObjectType, Reader, SUITE, header};
use crate::hash::key_id;
use crate::kdf::check_label;
use crate::kem::hex_prefix;
use crate::rng::{FixedRng, OsRng};
use crate::secret::{Secret, Secret32};
use crate::{Error, Result, rng};

/// ML-DSA-87 verifying key bytes.
pub const MLDSA_VK_LEN: usize = 2592;
/// ML-DSA-87 signature bytes.
pub const MLDSA_SIG_LEN: usize = 4627;
/// SLH-DSA-SHA2-256s verifying key bytes.
pub const SLH_VK_LEN: usize = 64;
/// SLH-DSA-SHA2-256s signature bytes.
pub const SLH_SIG_LEN: usize = 29792;
/// SLH-DSA seed: `SK.seed ‖ SK.prf ‖ PK.seed`.
pub const SLH_SEED_LEN: usize = 96;

pub(crate) fn context(sig_type: ObjectType, label: &str) -> Result<Vec<u8>> {
    check_label(label)?;
    let mut c = Vec::with_capacity(SUITE.len() + 2 + label.len());
    c.extend_from_slice(&SUITE);
    c.extend_from_slice(&sig_type.to_be_bytes());
    c.extend_from_slice(label.as_bytes());
    Ok(c)
}

fn encoded<const N: usize>(t: ObjectType, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + N);
    v.extend_from_slice(&header(t));
    v.extend_from_slice(body);
    v
}

/* ------------------------------- ML-DSA-87 ------------------------------- */

/// An ML-DSA-87 signing key, from a 32-byte seed ξ. Wiped on drop; no `Debug`, no `Clone`.
pub struct MlDsaSigningKey {
    pub(crate) sk: ml_dsa::SigningKey<MlDsa87>,
    public: MlDsaVerifyingKey,
}

impl MlDsaSigningKey {
    /// A fresh key from the platform CSPRNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&Secret32::random()?))
    }

    /// `ML-DSA.KeyGen_internal(ξ = seed)`.
    #[must_use]
    pub fn from_seed(seed: &Secret32) -> Self {
        let xi = Zeroizing::new(ml_dsa::B32::from(*seed.expose()));
        let sk = ml_dsa::SigningKey::<MlDsa87>::from_seed(&xi);
        let public = MlDsaVerifyingKey::from_inner(sk.expanded_key().verifying_key());
        Self { sk, public }
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &MlDsaVerifyingKey {
        &self.public
    }

    /// The 32-byte seed. Key material.
    #[must_use]
    pub fn seed(&self) -> Secret32 {
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(self.sk.as_seed());
        Secret32::new(&mut s)
    }

    /// Hedged ML-DSA-87 signature (32 bytes of `rnd` from the platform CSPRNG) over `msg`
    /// for `label`.
    ///
    /// # Errors
    /// [`Error::Label`] for a malformed label; [`Error::Rng`] if the generator fails.
    pub fn sign(&self, label: &str, msg: &[u8]) -> Result<MlDsaSignature> {
        self.sign_typed(ObjectType::MLDSA_SIGNATURE, label, msg)
    }

    /// As [`MlDsaSigningKey::sign`], with the context naming the statement's own type
    /// (`SUITE ‖ u16 type ‖ label`, PQ2.md §6): for structured statements such as a
    /// document (`ObjectType::DOC_SIGNED`).
    ///
    /// # Errors
    /// As [`MlDsaSigningKey::sign`].
    pub fn sign_typed(&self, t: ObjectType, label: &str, msg: &[u8]) -> Result<MlDsaSignature> {
        let ctx = context(t, label)?;
        self.sign_ctx(msg, &ctx, None).map(MlDsaSignature)
    }

    pub(crate) fn sign_ctx(
        &self,
        msg: &[u8],
        ctx: &[u8],
        rnd: Option<&[u8; 32]>,
    ) -> Result<Box<[u8; MLDSA_SIG_LEN]>> {
        mldsa_sign_expanded(self.sk.expanded_key(), msg, ctx, rnd)
    }
}

/// ML-DSA.Sign with an explicit `rnd` (KATs, cross-checks), or hedged from the CSPRNG.
pub(crate) fn mldsa_sign_expanded(
    esk: &ml_dsa::ExpandedSigningKey<MlDsa87>,
    msg: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; 32]>,
) -> Result<Box<[u8; MLDSA_SIG_LEN]>> {
    let sig = match rnd {
        Some(r) => esk.sign_randomized(msg, ctx, &mut FixedRng(r)),
        None => esk.sign_randomized(msg, ctx, &mut OsRng),
    }
    .map_err(|_| Error::Rng)?;
    let mut out = Box::new([0u8; MLDSA_SIG_LEN]);
    out.copy_from_slice(&sig.encode());
    Ok(out)
}

/// An ML-DSA-87 verifying key.
#[derive(Clone)]
pub struct MlDsaVerifyingKey {
    vk: ml_dsa::VerifyingKey<MlDsa87>,
    raw: Box<[u8; MLDSA_VK_LEN]>,
}

impl core::fmt::Debug for MlDsaVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsaVerifyingKey({})", hex_prefix(&self.key_id()))
    }
}

impl PartialEq for MlDsaVerifyingKey {
    fn eq(&self, o: &Self) -> bool {
        self.raw[..] == o.raw[..]
    }
}
impl Eq for MlDsaVerifyingKey {}

impl MlDsaVerifyingKey {
    fn from_inner(vk: ml_dsa::VerifyingKey<MlDsa87>) -> Self {
        let mut raw = Box::new([0u8; MLDSA_VK_LEN]);
        raw.copy_from_slice(&vk.encode());
        Self { vk, raw }
    }

    pub(crate) fn from_raw(raw: &[u8]) -> Result<Self> {
        let arr =
            ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(raw).map_err(|_| Error::Encoding)?;
        Ok(Self::from_inner(ml_dsa::VerifyingKey::decode(&arr)))
    }

    /// Decode `header ‖ pk` (2605 bytes).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::MLDSA_VERIFYING_KEY)?;
        let raw = r.take(MLDSA_VK_LEN)?;
        r.finish()?;
        Self::from_raw(raw)
    }

    /// `header ‖ pk`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encoded::<MLDSA_VK_LEN>(ObjectType::MLDSA_VERIFYING_KEY, &self.raw[..])
    }

    /// The raw FIPS 204 public key.
    #[must_use]
    pub fn raw(&self) -> &[u8; MLDSA_VK_LEN] {
        &self.raw
    }

    /// `key_id(to_bytes())`: what a document names as its signer.
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        key_id(&self.to_bytes())
    }

    /// Verify `sig` over `msg` for `label`.
    ///
    /// # Errors
    /// [`Error::Verify`] if it does not verify; [`Error::Label`] for a malformed label.
    pub fn verify(&self, label: &str, msg: &[u8], sig: &MlDsaSignature) -> Result<()> {
        self.verify_typed(ObjectType::MLDSA_SIGNATURE, label, msg, sig)
    }

    /// Verify a signature made with [`MlDsaSigningKey::sign_typed`].
    ///
    /// # Errors
    /// As [`MlDsaVerifyingKey::verify`].
    pub fn verify_typed(
        &self,
        t: ObjectType,
        label: &str,
        msg: &[u8],
        sig: &MlDsaSignature,
    ) -> Result<()> {
        let ctx = context(t, label)?;
        self.verify_ctx(msg, &ctx, &sig.0[..])
    }

    pub(crate) fn verify_ctx(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        let s = DsaSig::<MlDsa87>::try_from(sig).map_err(|_| Error::Verify)?;
        if self.vk.verify_with_context(msg, ctx, &s) {
            Ok(())
        } else {
            Err(Error::Verify)
        }
    }
}

/// An ML-DSA-87 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaSignature(Box<[u8; MLDSA_SIG_LEN]>);

impl core::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsaSignature({}…)", hex_prefix(&self.0[..]))
    }
}

impl MlDsaSignature {
    /// Decode `header ‖ sig` (4640 bytes). The signature's inner structure is checked when
    /// it is verified.
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::MLDSA_SIGNATURE)?;
        let s: [u8; MLDSA_SIG_LEN] = r.array()?;
        r.finish()?;
        Ok(Self(Box::new(s)))
    }

    /// `header ‖ sig`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encoded::<MLDSA_SIG_LEN>(ObjectType::MLDSA_SIGNATURE, &self.0[..])
    }

    /// The raw FIPS 204 signature.
    #[must_use]
    pub fn raw(&self) -> &[u8; MLDSA_SIG_LEN] {
        &self.0
    }

    /// From raw FIPS 204 bytes (inside a larger structure).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong length.
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        let s: [u8; MLDSA_SIG_LEN] = raw.try_into().map_err(|_| Error::Encoding)?;
        Ok(Self(Box::new(s)))
    }
}

/* --------------------------- SLH-DSA-SHA2-256s --------------------------- */

/// An SLH-DSA-SHA2-256s signing key. Wiped on drop; no `Debug`, no `Clone`.
pub struct SlhSigningKey {
    pub(crate) sk: slh_dsa::SigningKey<Sha2_256s>,
    public: SlhVerifyingKey,
}

impl SlhSigningKey {
    /// A fresh key from the platform CSPRNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&Secret::<SLH_SEED_LEN>::random()?))
    }

    /// `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` from the 96-byte seed.
    #[must_use]
    pub fn from_seed(seed: &Secret<SLH_SEED_LEN>) -> Self {
        let s = seed.expose();
        let sk =
            slh_dsa::SigningKey::<Sha2_256s>::slh_keygen_internal(&s[..32], &s[32..64], &s[64..]);
        let public = SlhVerifyingKey::from_inner(sk.as_ref().clone());
        Self { sk, public }
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &SlhVerifyingKey {
        &self.public
    }

    /// Hedged SLH-DSA signature (`opt_rand` from the platform CSPRNG) over `msg` for `label`.
    /// Slow (about a second): for long-lived roots only.
    ///
    /// # Errors
    /// [`Error::Label`] for a malformed label; [`Error::Rng`] if the generator fails.
    pub fn sign(&self, label: &str, msg: &[u8]) -> Result<SlhSignature> {
        let ctx = context(ObjectType::SLH_SIGNATURE, label)?;
        self.sign_ctx(msg, &ctx).map(SlhSignature)
    }

    pub(crate) fn sign_ctx(&self, msg: &[u8], ctx: &[u8]) -> Result<Box<[u8]>> {
        let mut rnd = Zeroizing::new([0u8; 32]);
        rng::fill(&mut rnd[..])?;
        slh_sign(&self.sk, msg, ctx, Some(&rnd))
    }
}

pub(crate) fn slh_sign(
    sk: &slh_dsa::SigningKey<Sha2_256s>,
    msg: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; 32]>,
) -> Result<Box<[u8]>> {
    let sig = sk
        .try_sign_with_context(msg, ctx, rnd.map(|r| &r[..]))
        .map_err(|_| Error::Label)?;
    let out: Box<[u8]> = sig.to_bytes().as_slice().into();
    debug_assert_eq!(out.len(), SLH_SIG_LEN);
    Ok(out)
}

/// An SLH-DSA-SHA2-256s verifying key (`PK.seed ‖ PK.root`).
#[derive(Clone)]
pub struct SlhVerifyingKey {
    vk: slh_dsa::VerifyingKey<Sha2_256s>,
    raw: [u8; SLH_VK_LEN],
}

impl core::fmt::Debug for SlhVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SlhVerifyingKey({})", hex_prefix(&self.raw))
    }
}

impl PartialEq for SlhVerifyingKey {
    fn eq(&self, o: &Self) -> bool {
        self.raw == o.raw
    }
}
impl Eq for SlhVerifyingKey {}

impl SlhVerifyingKey {
    fn from_inner(vk: slh_dsa::VerifyingKey<Sha2_256s>) -> Self {
        let mut raw = [0u8; SLH_VK_LEN];
        raw.copy_from_slice(&vk.to_bytes());
        Self { vk, raw }
    }

    pub(crate) fn from_raw(raw: &[u8]) -> Result<Self> {
        let vk = slh_dsa::VerifyingKey::<Sha2_256s>::try_from(raw).map_err(|_| Error::Encoding)?;
        Ok(Self::from_inner(vk))
    }

    /// Decode `header ‖ pk` (77 bytes).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::SLH_VERIFYING_KEY)?;
        let raw = r.take(SLH_VK_LEN)?;
        r.finish()?;
        Self::from_raw(raw)
    }

    /// `header ‖ pk`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encoded::<SLH_VK_LEN>(ObjectType::SLH_VERIFYING_KEY, &self.raw)
    }

    /// The raw FIPS 205 public key.
    #[must_use]
    pub fn raw(&self) -> &[u8; SLH_VK_LEN] {
        &self.raw
    }

    /// Verify `sig` over `msg` for `label`.
    ///
    /// # Errors
    /// [`Error::Verify`] if it does not verify; [`Error::Label`] for a malformed label.
    pub fn verify(&self, label: &str, msg: &[u8], sig: &SlhSignature) -> Result<()> {
        let ctx = context(ObjectType::SLH_SIGNATURE, label)?;
        self.verify_ctx(msg, &ctx, &sig.0[..])
    }

    pub(crate) fn verify_ctx(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        let s = slh_dsa::Signature::<Sha2_256s>::try_from(sig).map_err(|_| Error::Verify)?;
        self.vk
            .try_verify_with_context(msg, ctx, &s)
            .map_err(|_| Error::Verify)
    }
}

/// An SLH-DSA-SHA2-256s signature (always [`SLH_SIG_LEN`] bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct SlhSignature(Box<[u8]>);

impl core::fmt::Debug for SlhSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SlhSignature({}…)", hex_prefix(&self.0[..]))
    }
}

impl SlhSignature {
    /// Decode `header ‖ sig` (29805 bytes).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::SLH_SIGNATURE)?;
        let s = r.take(SLH_SIG_LEN)?;
        r.finish()?;
        Self::from_raw(s)
    }

    fn from_raw(raw: &[u8]) -> Result<Self> {
        if raw.len() != SLH_SIG_LEN {
            return Err(Error::Encoding);
        }
        Ok(Self(raw.into()))
    }

    /// `header ‖ sig`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encoded::<SLH_SIG_LEN>(ObjectType::SLH_SIGNATURE, &self.0[..])
    }
}

/* ------------------------- Dual (long-lived roots) ------------------------ */

/// A dual signing key for long-lived roots: ML-DSA-87 and SLH-DSA-SHA2-256s.
pub struct DualSigningKey {
    mldsa: MlDsaSigningKey,
    slh: SlhSigningKey,
    public: DualVerifyingKey,
}

impl DualSigningKey {
    /// Fresh keys from the platform CSPRNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_parts(
            MlDsaSigningKey::generate()?,
            SlhSigningKey::generate()?,
        ))
    }

    /// Pair two keys.
    #[must_use]
    pub fn from_parts(mldsa: MlDsaSigningKey, slh: SlhSigningKey) -> Self {
        let public = DualVerifyingKey {
            mldsa: mldsa.verifying_key().clone(),
            slh: slh.verifying_key().clone(),
        };
        Self { mldsa, slh, public }
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &DualVerifyingKey {
        &self.public
    }

    /// Both signatures over the same message, each under `ctx = SUITE ‖ 0x0008 ‖ label`.
    ///
    /// # Errors
    /// [`Error::Label`] for a malformed label; [`Error::Rng`] if the generator fails.
    pub fn sign(&self, label: &str, msg: &[u8]) -> Result<DualSignature> {
        let ctx = context(ObjectType::DUAL_SIGNATURE, label)?;
        let a = self.mldsa.sign_ctx(msg, &ctx, None)?;
        let b = self.slh.sign_ctx(msg, &ctx)?;
        Ok(DualSignature {
            mldsa: MlDsaSignature(a),
            slh: SlhSignature(b),
        })
    }
}

/// `header ‖ ML-DSA-87 pk (2592) ‖ SLH-DSA pk (64)`: 2669 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualVerifyingKey {
    mldsa: MlDsaVerifyingKey,
    slh: SlhVerifyingKey,
}

impl DualVerifyingKey {
    /// Decode.
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::DUAL_VERIFYING_KEY)?;
        let a = r.take(MLDSA_VK_LEN)?;
        let b = r.take(SLH_VK_LEN)?;
        r.finish()?;
        Ok(Self {
            mldsa: MlDsaVerifyingKey::from_raw(a)?,
            slh: SlhVerifyingKey::from_raw(b)?,
        })
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = header(ObjectType::DUAL_VERIFYING_KEY).to_vec();
        v.extend_from_slice(&self.mldsa.raw[..]);
        v.extend_from_slice(&self.slh.raw);
        v
    }

    /// `key_id(to_bytes())`.
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        key_id(&self.to_bytes())
    }

    /// Verify both halves; succeeds only if both do.
    ///
    /// # Errors
    /// [`Error::Verify`] unless both verify; [`Error::Label`] for a malformed label.
    pub fn verify(&self, label: &str, msg: &[u8], sig: &DualSignature) -> Result<()> {
        let ctx = context(ObjectType::DUAL_SIGNATURE, label)?;
        let a = self.mldsa.verify_ctx(msg, &ctx, &sig.mldsa.0[..]);
        let b = self.slh.verify_ctx(msg, &ctx, &sig.slh.0[..]);
        a.and(b)
    }
}

/// `header ‖ ML-DSA-87 sig (4627) ‖ SLH-DSA sig (29792)`: 34432 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualSignature {
    mldsa: MlDsaSignature,
    slh: SlhSignature,
}

impl DualSignature {
    /// Decode.
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::DUAL_SIGNATURE)?;
        let a = r.take(MLDSA_SIG_LEN)?;
        let b = r.take(SLH_SIG_LEN)?;
        r.finish()?;
        Ok(Self {
            mldsa: MlDsaSignature::from_raw(a)?,
            slh: SlhSignature::from_raw(b)?,
        })
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = header(ObjectType::DUAL_SIGNATURE).to_vec();
        v.extend_from_slice(&self.mldsa.0[..]);
        v.extend_from_slice(&self.slh.0[..]);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_round_trip_and_domain_separation() {
        let k = MlDsaSigningKey::generate().unwrap();
        let vk = k.verifying_key();
        let s = k.sign("HUMID-PQ2 test", b"hello").unwrap();
        vk.verify("HUMID-PQ2 test", b"hello", &s).unwrap();
        assert_eq!(
            vk.verify("HUMID-PQ2 test", b"hellO", &s),
            Err(Error::Verify)
        );
        assert_eq!(
            vk.verify("HUMID-PQ2 other", b"hello", &s),
            Err(Error::Verify)
        );
        // hedged: two signatures of the same message differ
        assert_ne!(s, k.sign("HUMID-PQ2 test", b"hello").unwrap());
        // encodings
        let s2 = MlDsaSignature::from_bytes(&s.to_bytes()).unwrap();
        assert_eq!(s, s2);
        let vk2 = MlDsaVerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
        assert_eq!(&vk2, vk);
        assert_eq!(MlDsaSigningKey::from_seed(&k.seed()).verifying_key(), vk);
        // a garbage signature of the right length is refused, not a panic
        let junk = MlDsaSignature::from_raw(&[0xffu8; MLDSA_SIG_LEN]).unwrap();
        assert_eq!(
            vk.verify("HUMID-PQ2 test", b"hello", &junk),
            Err(Error::Verify)
        );
    }

    #[test]
    fn slh_and_dual() {
        let d = DualSigningKey::generate().unwrap();
        let vk = d.verifying_key();
        let s = d.sign("HUMID-PQ2 checkpoint", b"root").unwrap();
        vk.verify("HUMID-PQ2 checkpoint", b"root", &s).unwrap();
        assert_eq!(
            vk.verify("HUMID-PQ2 checkpoint", b"r00t", &s),
            Err(Error::Verify)
        );
        let enc = s.to_bytes();
        assert_eq!(enc.len(), HEADER_LEN + MLDSA_SIG_LEN + SLH_SIG_LEN);
        assert_eq!(DualSignature::from_bytes(&enc).unwrap(), s);
        assert_eq!(&DualVerifyingKey::from_bytes(&vk.to_bytes()).unwrap(), vk);
        // Either half broken: refused.
        for pos in [HEADER_LEN + 100, HEADER_LEN + MLDSA_SIG_LEN + 100] {
            let mut e = enc.clone();
            e[pos] ^= 0x40;
            let bad = DualSignature::from_bytes(&e).unwrap();
            assert_eq!(
                vk.verify("HUMID-PQ2 checkpoint", b"root", &bad),
                Err(Error::Verify)
            );
        }
        // The ML-DSA half alone is not a valid stand-alone ML-DSA signature (stripping).
        let half = MlDsaSignature::from_raw(&enc[HEADER_LEN..HEADER_LEN + MLDSA_SIG_LEN]).unwrap();
        assert_eq!(
            vk.mldsa.verify("HUMID-PQ2 checkpoint", b"root", &half),
            Err(Error::Verify)
        );
        // SLH alone
        let slh = SlhSigningKey::from_seed(&Secret::<SLH_SEED_LEN>::random().unwrap());
        let ss = slh.sign("HUMID-PQ2 release", b"x").unwrap();
        slh.verifying_key()
            .verify("HUMID-PQ2 release", b"x", &ss)
            .unwrap();
        assert_eq!(SlhSignature::from_bytes(&ss.to_bytes()).unwrap(), ss);
    }
}
