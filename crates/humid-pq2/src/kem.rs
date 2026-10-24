//! The hybrid KEM: ML-KEM-1024 (FIPS 203) + X25519 (RFC 7748), one combiner.
//!
//! ```text
//! ss = KDF("HUMID-PQ2 hybrid-kem",
//!          key     = [ss_mlkem, ss_x25519],
//!          context = [ct_mlkem, eph_x25519, ek_mlkem, pk_x25519], 32)
//! ```
//!
//! Both shared secrets, both ciphertexts (the X25519 "ciphertext" is the ephemeral public
//! key) and both halves of the recipient's public key go into the one KMAC256 call, so the
//! result is secure if either ML-KEM-1024 or X25519 is, and a ciphertext cannot be moved to
//! another key or mixed with half of another ciphertext.

use ml_kem::array::Array;
use ml_kem::{Decapsulate, KeyExport, MlKem1024};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{HEADER_LEN, ObjectType, Reader, header};
use crate::hash::key_id;
use crate::kdf::kdf;
use crate::secret::{Secret, Secret32};
use crate::{Error, Result, rng};

type MlKemEk = ml_kem::EncapsulationKey<MlKem1024>;
type MlKemDk = ml_kem::DecapsulationKey<MlKem1024>;

/// ML-KEM-1024 encapsulation key bytes.
pub const MLKEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext bytes.
pub const MLKEM_CT_LEN: usize = 1568;
/// X25519 public key / ephemeral bytes.
pub const X25519_LEN: usize = 32;
/// Encoded [`KemPublicKey`]: header ‖ ek ‖ X25519 public key = 1613 bytes.
pub const KEM_PUBLIC_KEY_LEN: usize = HEADER_LEN + MLKEM_EK_LEN + X25519_LEN;
/// Encoded [`KemCiphertext`]: header ‖ ct ‖ X25519 ephemeral = 1613 bytes.
pub const KEM_CIPHERTEXT_LEN: usize = HEADER_LEN + MLKEM_CT_LEN + X25519_LEN;
/// A hybrid secret key's seed: ML-KEM `d ‖ z` (64) ‖ X25519 scalar (32).
pub const KEM_SEED_LEN: usize = 96;

/// A recipient's hybrid public key.
#[derive(Clone)]
pub struct KemPublicKey {
    ek: MlKemEk,
    x: XPublic,
    encoded: Box<[u8; KEM_PUBLIC_KEY_LEN]>,
}

impl core::fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KemPublicKey({})", hex_prefix(&self.key_id()))
    }
}

pub(crate) fn hex_prefix(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().take(8).fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

impl PartialEq for KemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded[..] == other.encoded[..]
    }
}
impl Eq for KemPublicKey {}

impl KemPublicKey {
    fn from_parts(ek: MlKemEk, x: XPublic) -> Self {
        let mut encoded = Box::new([0u8; KEM_PUBLIC_KEY_LEN]);
        encoded[..HEADER_LEN].copy_from_slice(&header(ObjectType::KEM_PUBLIC_KEY));
        encoded[HEADER_LEN..HEADER_LEN + MLKEM_EK_LEN].copy_from_slice(&ek.to_bytes());
        encoded[HEADER_LEN + MLKEM_EK_LEN..].copy_from_slice(x.as_bytes());
        Self { ek, x, encoded }
    }

    /// Decode, running FIPS 203's encapsulation key check (every coefficient < q).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length, or an ML-KEM key that fails the check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::KEM_PUBLIC_KEY)?;
        let ek_bytes = r.take(MLKEM_EK_LEN)?;
        let x: [u8; 32] = r.array()?;
        r.finish()?;
        let ek_arr = Array::try_from(ek_bytes).map_err(|_| Error::Encoding)?;
        let ek = MlKemEk::new(&ek_arr).map_err(|_| Error::Encoding)?;
        Ok(Self::from_parts(ek, XPublic::from(x)))
    }

    /// The 1613-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8; KEM_PUBLIC_KEY_LEN] {
        &self.encoded
    }

    /// `key_id(encoding)`.
    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        key_id(&self.encoded[..])
    }

    fn mlkem_bytes(&self) -> &[u8] {
        &self.encoded[HEADER_LEN..HEADER_LEN + MLKEM_EK_LEN]
    }

    /// Encapsulate a fresh shared secret to this key.
    ///
    /// # Errors
    /// [`Error::Rng`] if the platform generator fails; [`Error::KeyAgreement`] if this
    /// key's X25519 half is a low-order point.
    pub fn encapsulate(&self) -> Result<(KemCiphertext, Secret32)> {
        let mut m = Zeroizing::new([0u8; 32]);
        rng::fill(&mut m[..])?;
        let mut eph = Zeroizing::new([0u8; 32]);
        rng::fill(&mut eph[..])?;
        self.encapsulate_derand(&m, &eph)
    }

    /// Encapsulation with given randomness (`m` for ML-KEM, `eph` for the X25519 scalar).
    /// Known-answer tests and cross-checks only.
    pub(crate) fn encapsulate_derand(
        &self,
        m: &[u8; 32],
        eph: &[u8; 32],
    ) -> Result<(KemCiphertext, Secret32)> {
        let m_arr = Zeroizing::new(Array::from(*m));
        let (ct, mut ss_k) = self.ek.encapsulate_deterministic(&m_arr);
        let e = StaticSecret::from(*eph);
        let eph_pub = XPublic::from(&e);
        let ss_x = e.diffie_hellman(&self.x);
        if !ss_x.was_contributory() {
            ss_k.zeroize();
            return Err(Error::KeyAgreement);
        }
        let ct = KemCiphertext::from_parts(ct.as_slice(), eph_pub.as_bytes());
        let ss = combine(&ss_k, ss_x.as_bytes(), &ct, self);
        ss_k.zeroize();
        Ok((ct, ss?))
    }
}

/// A hybrid KEM ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct KemCiphertext {
    encoded: Box<[u8; KEM_CIPHERTEXT_LEN]>,
}

impl core::fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "KemCiphertext({}…)",
            hex_prefix(&self.encoded[HEADER_LEN..])
        )
    }
}

impl KemCiphertext {
    fn from_parts(ct: &[u8], eph: &[u8; 32]) -> Self {
        let mut encoded = Box::new([0u8; KEM_CIPHERTEXT_LEN]);
        encoded[..HEADER_LEN].copy_from_slice(&header(ObjectType::KEM_CIPHERTEXT));
        encoded[HEADER_LEN..HEADER_LEN + MLKEM_CT_LEN].copy_from_slice(ct);
        encoded[HEADER_LEN + MLKEM_CT_LEN..].copy_from_slice(eph);
        Self { encoded }
    }

    /// Decode. Any 1568 + 32 bytes after the header are a well-formed ciphertext (ML-KEM
    /// rejects bad ones implicitly at decapsulation).
    ///
    /// # Errors
    /// [`Error::Encoding`] for a wrong header or length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEM_CIPHERTEXT_LEN
            || bytes[..HEADER_LEN] != header(ObjectType::KEM_CIPHERTEXT)
        {
            return Err(Error::Encoding);
        }
        let mut encoded = Box::new([0u8; KEM_CIPHERTEXT_LEN]);
        encoded.copy_from_slice(bytes);
        Ok(Self { encoded })
    }

    /// The 1613-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8; KEM_CIPHERTEXT_LEN] {
        &self.encoded
    }

    fn mlkem(&self) -> &[u8] {
        &self.encoded[HEADER_LEN..HEADER_LEN + MLKEM_CT_LEN]
    }

    fn eph(&self) -> [u8; 32] {
        let mut e = [0u8; 32];
        e.copy_from_slice(&self.encoded[HEADER_LEN + MLKEM_CT_LEN..]);
        e
    }
}

fn combine(
    ss_k: &[u8],
    ss_x: &[u8; 32],
    ct: &KemCiphertext,
    pk: &KemPublicKey,
) -> Result<Secret32> {
    kdf::<32>(
        "HUMID-PQ2 hybrid-kem",
        &[ss_k, ss_x],
        &[ct.mlkem(), &ct.eph(), pk.mlkem_bytes(), pk.x.as_bytes()],
    )
}

/// A hybrid secret (decapsulation) key. Wiped on drop; no `Debug`, no `Clone`.
pub struct KemSecretKey {
    pub(crate) dk: MlKemDk,
    x: StaticSecret,
    public: KemPublicKey,
    seed: Secret<KEM_SEED_LEN>,
}

impl KemSecretKey {
    /// A new key pair from the platform CSPRNG.
    ///
    /// # Errors
    /// [`Error::Rng`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&Secret::<KEM_SEED_LEN>::random()?))
    }

    /// The key pair for a 96-byte seed: ML-KEM-1024.KeyGen_internal(d = seed[0..32],
    /// z = seed[32..64]) and the X25519 scalar seed[64..96] (clamped per RFC 7748).
    #[must_use]
    pub fn from_seed(seed: &Secret<KEM_SEED_LEN>) -> Self {
        let s = seed.expose();
        let mut ml_seed = Zeroizing::new(ml_kem::Seed::default());
        ml_seed.copy_from_slice(&s[..64]);
        let dk = MlKemDk::from_seed(*ml_seed);
        let mut xs = Zeroizing::new([0u8; 32]);
        xs.copy_from_slice(&s[64..]);
        let x = StaticSecret::from(*xs);
        let public = KemPublicKey::from_parts(dk.encapsulation_key().clone(), XPublic::from(&x));
        Self {
            dk,
            x,
            public,
            seed: seed.duplicate(),
        }
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &KemPublicKey {
        &self.public
    }

    /// The 96-byte seed. Key material: store it only sealed.
    #[must_use]
    pub fn seed(&self) -> &Secret<KEM_SEED_LEN> {
        &self.seed
    }

    /// Decapsulate. ML-KEM never fails (implicit rejection gives an unrelated secret, which
    /// the AEAD that follows then refuses).
    ///
    /// # Errors
    /// [`Error::KeyAgreement`] if the ephemeral X25519 key is a low-order point.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> Result<Secret32> {
        let ct_arr = Array::try_from(ct.mlkem()).map_err(|_| Error::Encoding)?;
        let mut ss_k = self.dk.decapsulate(&ct_arr);
        let ss_x = self.x.diffie_hellman(&XPublic::from(ct.eph()));
        if !ss_x.was_contributory() {
            ss_k.zeroize();
            return Err(Error::KeyAgreement);
        }
        let ss = combine(&ss_k, ss_x.as_bytes(), ct, &self.public);
        ss_k.zeroize();
        ss
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let a = KemSecretKey::generate().unwrap();
        let b = KemSecretKey::generate().unwrap();
        let (ct, ss) = a.public_key().encapsulate().unwrap();
        assert!(a.decapsulate(&ct).unwrap().ct_eq(&ss));
        assert!(!b.decapsulate(&ct).unwrap().ct_eq(&ss));
        // Flip one bit in either half of the ciphertext: a different secret.
        for pos in [HEADER_LEN, HEADER_LEN + MLKEM_CT_LEN + 3] {
            let mut bytes = ct.to_bytes().to_vec();
            bytes[pos] ^= 1;
            let ct2 = KemCiphertext::from_bytes(&bytes).unwrap();
            if let Ok(ss2) = a.decapsulate(&ct2) {
                assert!(!ss2.ct_eq(&ss));
            }
        }
        // Encodings round-trip.
        let pk = KemPublicKey::from_bytes(a.public_key().to_bytes()).unwrap();
        assert_eq!(&pk, a.public_key());
        let s2 = KemSecretKey::from_seed(a.seed());
        assert_eq!(s2.public_key(), a.public_key());
    }

    #[test]
    fn low_order_x25519_is_refused() {
        let a = KemSecretKey::generate().unwrap();
        let mut bytes = a.public_key().to_bytes().to_vec();
        bytes[HEADER_LEN + MLKEM_EK_LEN..].fill(0);
        let pk = KemPublicKey::from_bytes(&bytes).unwrap();
        assert!(matches!(pk.encapsulate(), Err(Error::KeyAgreement)));
        let (ct, _) = a.public_key().encapsulate().unwrap();
        let mut c = ct.to_bytes().to_vec();
        c[HEADER_LEN + MLKEM_CT_LEN..].fill(0);
        assert!(matches!(
            a.decapsulate(&KemCiphertext::from_bytes(&c).unwrap()),
            Err(Error::KeyAgreement)
        ));
    }

    #[test]
    fn bad_encodings() {
        assert_eq!(KemPublicKey::from_bytes(&[]).unwrap_err(), Error::Encoding);
        let a = KemSecretKey::generate().unwrap();
        let mut b = a.public_key().to_bytes().to_vec();
        b.push(0);
        assert_eq!(KemPublicKey::from_bytes(&b).unwrap_err(), Error::Encoding);
        // An ML-KEM coefficient ≥ q fails FIPS 203's modulus check.
        let mut b = a.public_key().to_bytes().to_vec();
        b[HEADER_LEN] = 0xff;
        b[HEADER_LEN + 1] |= 0x0f;
        assert_eq!(KemPublicKey::from_bytes(&b).unwrap_err(), Error::Encoding);
        assert_eq!(
            KemCiphertext::from_bytes(&[0u8; KEM_CIPHERTEXT_LEN]).unwrap_err(),
            Error::Encoding
        );
    }
}
