//! The server's only door to cryptography.
//!
//! Everything goes through `humid-pq2` (the HUMID-PQ2 suite, docs/v5/PQ2.md), except the
//! one primitive an external standard fixes: ECDSA P-256 from a phone's secure chip
//! (verified with aws-lc-rs). No other module imports `humid_pq2` or a crypto crate, so a
//! suite change is a change here (a test in `lib.rs` checks this).

use humid_pq2 as pq2;
pub use pq2::{ObjectType, Secret, Secret32};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/* ------------------------------- labels ------------------------------- */

/// Labels this server signs, hashes or derives with ("HUMID-PQ2 " + a-z0-9-, PQ2.md §3).
pub mod label {
    /// The account key's certificate for one device.
    pub const DEVICE_CERT: &str = "HUMID-PQ2 device-cert";
    /// The account key's proof of possession at registration.
    pub const REGISTER: &str = "HUMID-PQ2 register";
    /// A device key's proof of possession at enrolment.
    pub const DEVICE_POP: &str = "HUMID-PQ2 device-pop";
    /// The device key's step-up signature.
    pub const STEP_UP: &str = "HUMID-PQ2 step-up";
    /// What the secure chip signs (hashed) for a step-up ticket.
    pub const LIVE: &str = "HUMID-PQ2 live";
    /// The device key's sign-in signature (carries the duress bit).
    pub const LOGIN: &str = "HUMID-PQ2 login";
    /// What the secure chip signs (hashed) for a sign-in.
    pub const LIVE_LOGIN: &str = "HUMID-PQ2 live-login";
    /// What the chip signs at enrolment.
    pub const LIVE_ENROL: &str = "HUMID-PQ2 live-enrol";
    /// The short hash of a proof, as the ledger records it.
    pub const PROOF_HASH: &str = "HUMID-PQ2 proof-hash";
    /// A statement from one unit to another.
    pub const UNIT_STATEMENT: &str = "HUMID-PQ2 unit-statement";
    /// The signed server policy.
    pub const POLICY: &str = "HUMID-PQ2 server-policy";
    /// One ledger entry in an account's hash chain.
    pub const LEDGER_ENTRY: &str = "HUMID-PQ2 ledger-entry";
    /// A public-log leaf.
    pub const TLOG_LEAF: &str = "HUMID-PQ2 tlog-leaf";
    /// A public-log interior node.
    pub const TLOG_NODE: &str = "HUMID-PQ2 tlog-node";
    /// A public-log checkpoint (dual-signed by the ledger key).
    pub const TLOG_CHECKPOINT: &str = "HUMID-PQ2 tlog-checkpoint";
    /// A cosigner's signature over a checkpoint.
    pub const TLOG_COSIGN: &str = "HUMID-PQ2 tlog-cosign";
    /// The account key's recovery-mode statement.
    pub const RECOVERY_MODE: &str = "HUMID-PQ2 recovery-mode";
    /// Server-keyed recovery-card lookup tag.
    pub const CARD_TAG: &str = "HUMID-PQ2 card-tag";
    /// Hash of a session token (the token itself is never stored).
    pub const SESSION_TOKEN: &str = "HUMID-PQ2 session-token";
    /// Hash of an access code.
    pub const ACCESS_CODE: &str = "HUMID-PQ2 access-code";
    /// Id of a spent pass or post token.
    pub const SPENT: &str = "HUMID-PQ2 spent";
    /// Hash of a relay ack or retract token.
    pub const RELAY_TOKEN: &str = "HUMID-PQ2 relay-token";
    /// Key derivation inside the software HSM.
    pub const SOFT_HSM: &str = "HUMID-PQ2 soft-hsm";
    /// Check-in fuse key.
    pub const FUSE: &str = "HUMID-PQ2 checkin-fuse";
    /// Link and recovery codes.
    pub const CODE: &str = "HUMID-PQ2 key-code";
}

/// Server object types (`0x02xx`, proposed for the PQ2.md registry: see SERVER.md §13).
pub mod object_type {
    use super::ObjectType;
    /// A key share at rest in the keys unit, wrapped by the share KEK.
    pub const SHARE_AT_REST: ObjectType = ObjectType(0x0200);
    /// A share also sealed under an account's Check-in fuse key.
    pub const SHARE_FUSED: ObjectType = ObjectType(0x0201);
    /// Anything a unit seals under its HSM `seal` key (key seeds, blind-RSA private keys).
    pub const UNIT_SEALED: ObjectType = ObjectType(0x0202);
}

/// Run the suite's known-answer self-test. Every unit calls this before it serves.
///
/// # Errors
/// If the suite fails its own test (the unit must not start).
pub fn self_test() -> Result<()> {
    pq2::self_test().map_err(|e| Error::internal(format!("HUMID-PQ2 self-test failed: {e}")))
}

/* ------------------------------- hashes ------------------------------- */

/// `H(label, parts)` = SHA3-512 over `SUITE ‖ lp(label, parts…)`.
///
/// # Errors
/// Only for a malformed label (a bug).
pub fn hash(label: &str, parts: &[&[u8]]) -> Result<[u8; 64]> {
    Ok(pq2::labelled_hash(label, parts)?)
}

/// SHA3-512.
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    pq2::sha3_512(data)
}

/// Streaming SHA3-512 (uploads are hashed chunk by chunk).
pub struct Sha3Stream(pq2::Sha3_512Stream);
impl Sha3Stream {
    /// A new stream.
    #[must_use]
    pub fn new() -> Self {
        Self(pq2::Sha3_512Stream::new())
    }
    /// Absorb bytes.
    pub fn update(&mut self, b: &[u8]) {
        self.0.update(b);
    }
    /// The digest.
    #[must_use]
    pub fn finish(self) -> [u8; 64] {
        self.0.finish()
    }
}
impl Default for Sha3Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// The PQ2 key id of an encoding (accounts and devices are named by it).
#[must_use]
pub fn key_id(encoding: &[u8]) -> [u8; 32] {
    pq2::key_id(encoding)
}

/// `lp(a, b, …)`.
///
/// # Errors
/// A part of 4 GiB or more.
pub fn lp(parts: &[&[u8]]) -> Result<Vec<u8>> {
    Ok(pq2::encoding::lp(parts)?)
}

/// Constant-time equality.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    pq2::ct_eq(a, b)
}

/// Random bytes from the platform CSPRNG.
///
/// # Errors
/// If the generator fails.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    pq2::random_bytes(&mut b)?;
    Ok(b)
}

/// KMAC256 KDF.
///
/// # Errors
/// A malformed label or length.
pub fn kdf32(label: &str, key: &[&[u8]], context: &[&[u8]]) -> Result<Secret32> {
    Ok(pq2::kdf::<32>(label, key, context)?)
}

/// KMAC256 KDF, any fixed length.
///
/// # Errors
/// A malformed label or length.
pub fn kdf<const N: usize>(label: &str, key: &[&[u8]], context: &[&[u8]]) -> Result<Secret<N>> {
    Ok(pq2::kdf::<N>(label, key, context)?)
}

/* ------------------------------ signatures ----------------------------- */

/// An ML-DSA-87 verifying key (account, device, unit statement keys).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaPublic(pq2::MlDsaVerifyingKey);

impl MlDsaPublic {
    /// Parse a PQ2 verifying-key encoding (2605 bytes).
    ///
    /// # Errors
    /// Not a verifying key.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        pq2::MlDsaVerifyingKey::from_bytes(b)
            .map(Self)
            .map_err(|_| Error::bad("bad_key", "That isn't an ML-DSA-87 public key."))
    }
    /// The encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    /// Its key id (what account and device ids are).
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.0.key_id()
    }
    /// True when `sig` (a PQ2 signature encoding) is this key's over `msg` for `label`.
    #[must_use]
    pub fn verifies(&self, label: &str, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(s) = pq2::MlDsaSignature::from_bytes(sig) else {
            return false;
        };
        self.0.verify(label, msg, &s).is_ok()
    }
}

/// A dual (ML-DSA-87 + SLH-DSA-SHA2-256s) verifying key (identity root, ledger).
#[derive(Clone, Debug)]
pub struct DualPublic(pq2::DualVerifyingKey);

impl DualPublic {
    /// Parse.
    ///
    /// # Errors
    /// Not a dual verifying key.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        pq2::DualVerifyingKey::from_bytes(b)
            .map(Self)
            .map_err(|_| Error::bad("bad_key", "That isn't a dual verifying key."))
    }
    /// The encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    /// Its key id.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.0.key_id()
    }
    /// Both halves verify.
    #[must_use]
    pub fn verifies(&self, label: &str, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(s) = pq2::DualSignature::from_bytes(sig) else {
            return false;
        };
        self.0.verify(label, msg, &s).is_ok()
    }
}

/// An ML-DSA-87 signing key held in software (the software HSM, tests).
pub struct MlDsaSecret(pq2::MlDsaSigningKey);
impl MlDsaSecret {
    /// A fresh key.
    ///
    /// # Errors
    /// The generator failed.
    pub fn generate() -> Result<Self> {
        Ok(Self(pq2::MlDsaSigningKey::generate()?))
    }
    /// From a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &Secret32) -> Self {
        Self(pq2::MlDsaSigningKey::from_seed(seed))
    }
    /// The public half.
    #[must_use]
    pub fn public(&self) -> MlDsaPublic {
        MlDsaPublic(self.0.verifying_key().clone())
    }
    /// Sign; returns the PQ2 signature encoding.
    ///
    /// # Errors
    /// A malformed label; the generator failed.
    pub fn sign(&self, label: &str, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(label, msg)?.to_bytes())
    }
}

/// A dual signing key held in software (the software HSM, the dev identity root).
pub struct DualSecret(pq2::DualSigningKey);
impl DualSecret {
    /// From an ML-DSA seed and an SLH-DSA seed.
    #[must_use]
    pub fn from_seeds(mldsa: &Secret32, slh: &Secret<96>) -> Self {
        Self(pq2::DualSigningKey::from_parts(
            pq2::MlDsaSigningKey::from_seed(mldsa),
            pq2::SlhSigningKey::from_seed(slh),
        ))
    }
    /// The public half.
    #[must_use]
    pub fn public(&self) -> DualPublic {
        DualPublic(self.0.verifying_key().clone())
    }
    /// Sign with both halves; returns the dual signature encoding (SLH-DSA-256s: ~0.5 s).
    ///
    /// # Errors
    /// A malformed label; the generator failed.
    pub fn sign(&self, label: &str, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(label, msg)?.to_bytes())
    }
}

/* ------------------------- the phone's secure chip ------------------------- */

/// Verify an ECDSA P-256 / SHA-256 (ASN.1 DER) signature from a secure chip, under its
/// SubjectPublicKeyInfo. Classical by necessity (it's what the chips sign with); the
/// ML-DSA device signature made in the same check carries the post-quantum weight.
#[must_use]
pub fn p256_verifies(spki: &[u8], msg: &[u8], sig_der: &[u8]) -> bool {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    // aws-lc-rs accepts both SPKI and a SEC1 point here; insist on SPKI (what the app sends).
    if spki.len() != 91 {
        return false;
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, spki)
        .verify(msg, sig_der)
        .is_ok()
}

/* ------------------------------- the KEM ------------------------------- */

/// A hybrid KEM public key (ML-KEM-1024 + X25519, 1613 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublic(pq2::KemPublicKey);
impl KemPublic {
    /// Parse.
    ///
    /// # Errors
    /// Not a KEM public key.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        pq2::KemPublicKey::from_bytes(b)
            .map(Self)
            .map_err(|_| Error::bad("bad_key", "That isn't a hybrid KEM public key."))
    }
    /// The encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A hybrid KEM secret key (the keys unit's share-upload key).
pub struct KemSecret(pq2::KemSecretKey);
impl KemSecret {
    /// From a 96-byte seed.
    #[must_use]
    pub fn from_seed(seed: &Secret<96>) -> Self {
        Self(pq2::KemSecretKey::from_seed(seed))
    }
    /// A fresh key.
    ///
    /// # Errors
    /// The generator failed.
    pub fn generate() -> Result<Self> {
        Ok(Self(pq2::KemSecretKey::generate()?))
    }
    /// Its seed (to be sealed at rest).
    #[must_use]
    pub fn seed(&self) -> &Secret<96> {
        self.0.seed()
    }
    /// The public half.
    #[must_use]
    pub fn public(&self) -> KemPublic {
        KemPublic(self.0.public_key().clone())
    }
}

/// Size of a sealed share (both directions).
pub const SEALED_SHARE_LEN: usize = pq2::SEALED_SHARE_LEN;

/// A phone's request for one document's share (CORE.md §6.3, type `0x0012`):
/// `header(0x0012) ‖ account_id (32) ‖ doc_id (32) ‖ manifest_hash (64) ‖ one_time (1613)`.
/// The share is released sealed to `one_time` under `binding = H("HUMID-PQ2 share-request",
/// [encoding])`, which is what the phone's live check for the open signed.
pub struct ShareRequest {
    /// The account.
    pub account: [u8; 32],
    /// The document.
    pub doc: [u8; 32],
    /// Its manifest hash (what the upload bound the share to).
    pub manifest_hash: [u8; 64],
    /// The one-time hybrid KEM key to seal the share to.
    pub one_time: KemPublic,
    /// `H("HUMID-PQ2 share-request", [encoding])`.
    pub binding: [u8; 64],
}

/// The share-request binding label (humid-core's).
pub const SHARE_REQUEST_LABEL: &str = "HUMID-PQ2 share-request";

impl ShareRequest {
    /// Parse and bind.
    ///
    /// # Errors
    /// `bad_share_request`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bad = || Error::bad("bad_share_request", "That isn't a share request.");
        let mut r = pq2::encoding::Reader::new(bytes);
        r.header(ObjectType::SHARE_REQUEST).map_err(|_| bad())?;
        let account = r.array::<32>().map_err(|_| bad())?;
        let doc = r.array::<32>().map_err(|_| bad())?;
        let manifest_hash = r.array::<64>().map_err(|_| bad())?;
        let one_time = KemPublic::from_bytes(r.take(pq2::KEM_PUBLIC_KEY_LEN).map_err(|_| bad())?)
            .map_err(|_| bad())?;
        r.finish().map_err(|_| bad())?;
        let binding = hash(SHARE_REQUEST_LABEL, &[bytes])?;
        Ok(Self {
            account,
            doc,
            manifest_hash,
            one_time,
            binding,
        })
    }

    /// Encode (what a phone sends; tests).
    #[must_use]
    pub fn encode(
        account: &[u8; 32],
        doc: &[u8; 32],
        manifest_hash: &[u8; 64],
        one_time: &KemPublic,
    ) -> Vec<u8> {
        let mut v = pq2::encoding::header(ObjectType::SHARE_REQUEST).to_vec();
        v.extend_from_slice(account);
        v.extend_from_slice(doc);
        v.extend_from_slice(manifest_hash);
        v.extend_from_slice(&one_time.to_bytes());
        v
    }
}

/// Open a share the phone sealed to the keys unit (H2: the upload direction). The binding is
/// the document's manifest hash (CORE.md §6.3).
///
/// # Errors
/// `bad_share` if it wasn't sealed to this key for this account, object and manifest.
pub fn open_upload_share(
    sk: &KemSecret,
    account: &[u8],
    object: &[u8],
    manifest_hash: &[u8],
    sealed: &[u8],
) -> Result<Secret32> {
    pq2::open_share(
        pq2::ShareDirection::Upload,
        &sk.0,
        account,
        object,
        manifest_hash,
        sealed,
    )
    .map_err(|_| {
        Error::bad(
            "bad_share",
            "The document key wasn't sealed to this key service for this document.",
        )
    })
}

/// Seal a share to the phone's one-time key (the release direction).
///
/// # Errors
/// Key agreement or the generator failed.
pub fn seal_release_share(
    to: &KemPublic,
    account: &[u8],
    object: &[u8],
    binding: &[u8],
    share: &Secret32,
) -> Result<Vec<u8>> {
    Ok(pq2::seal_share(
        pq2::ShareDirection::Release,
        &to.0,
        account,
        object,
        binding,
        share,
    )?)
}

/// Test support: what a phone does (seal for upload, open a release).
#[cfg(any(test, feature = "testkit"))]
pub mod phone {
    use super::{KemPublic, KemSecret, Result, Secret32, pq2};

    /// Seal a share for upload.
    ///
    /// # Errors
    /// Crypto failure.
    pub fn seal_upload(
        to: &KemPublic,
        account: &[u8],
        object: &[u8],
        envelope_hash: &[u8],
        share: &Secret32,
    ) -> Result<Vec<u8>> {
        Ok(pq2::seal_share(
            pq2::ShareDirection::Upload,
            &to.0,
            account,
            object,
            envelope_hash,
            share,
        )?)
    }
    /// Open a released share.
    ///
    /// # Errors
    /// Wrong key or binding.
    pub fn open_release(
        sk: &KemSecret,
        account: &[u8],
        object: &[u8],
        binding: &[u8],
        sealed: &[u8],
    ) -> Result<Secret32> {
        Ok(pq2::open_share(
            pq2::ShareDirection::Release,
            &sk.0,
            account,
            object,
            binding,
            sealed,
        )?)
    }
}

/* ------------------------- blind RSA (RFC 9474) ------------------------- */

/// RSABSSA-SHA384-PSS-Randomized for access passes and post tokens. Classical, as V5.md
/// accepts until a post-quantum blind scheme is standardised; anon never learns an account,
/// so a future break links tokens to nothing.
pub mod blind {
    use blind_rsa_signatures as brs;

    use crate::error::{Error, Result};

    type Pk = brs::PublicKeySha384PSSRandomized;
    type Sk = brs::SecretKeySha384PSSRandomized;

    /// A signing key.
    pub struct SigningKey(Sk);
    /// A public key.
    #[derive(Clone)]
    pub struct PublicKey(Pk);

    fn e(_: brs::Error) -> Error {
        Error::bad(
            "bad_token",
            "That blind signature request or token isn't valid.",
        )
    }

    impl SigningKey {
        /// A new key of `bits` (2048–4096).
        ///
        /// # Errors
        /// Bad size.
        pub fn generate(bits: usize) -> Result<Self> {
            let kp =
                brs::KeyPairSha384PSSRandomized::generate(&mut brs::DefaultRng, bits).map_err(e)?;
            Ok(Self(kp.sk))
        }
        /// From PKCS#1 DER (as sealed at rest).
        ///
        /// # Errors
        /// Not a key.
        pub fn from_der(der: &[u8]) -> Result<Self> {
            Sk::from_der(der).map(Self).map_err(e)
        }
        /// To DER (sealed by the caller before it touches the disk).
        ///
        /// # Errors
        /// Encoding failure.
        pub fn to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            self.0.to_der().map(zeroize::Zeroizing::new).map_err(e)
        }
        /// The public half.
        ///
        /// # Errors
        /// Encoding failure.
        pub fn public(&self) -> Result<PublicKey> {
            self.0.public_key().map(PublicKey).map_err(e)
        }
        /// Sign a blinded message.
        ///
        /// # Errors
        /// A malformed blinded message.
        pub fn blind_sign(&self, blinded: &[u8]) -> Result<Vec<u8>> {
            self.0.blind_sign(blinded).map(|s| s.0).map_err(e)
        }
    }

    impl PublicKey {
        /// From SubjectPublicKeyInfo DER.
        ///
        /// # Errors
        /// Not a key.
        pub fn from_spki(der: &[u8]) -> Result<Self> {
            Pk::from_spki(der).map(Self).map_err(e)
        }
        /// To SubjectPublicKeyInfo DER.
        ///
        /// # Errors
        /// Encoding failure.
        pub fn to_spki(&self) -> Result<Vec<u8>> {
            self.0.to_spki().map_err(e)
        }
        /// Verify a finalized token: `msg` with its 32-byte randomizer and signature.
        #[must_use]
        pub fn verifies(&self, msg: &[u8], randomizer: &[u8], sig: &[u8]) -> bool {
            let Ok(r) = <[u8; 32]>::try_from(randomizer) else {
                return false;
            };
            self.0
                .verify(
                    &brs::Signature(sig.to_vec()),
                    Some(brs::MessageRandomizer(r)),
                    msg,
                )
                .is_ok()
        }
        /// Test support: a client's blind → finalize, giving `(randomizer, sig)`.
        ///
        /// # Errors
        /// Crypto failure.
        #[cfg(any(test, feature = "testkit"))]
        pub fn client_token(
            &self,
            signer: impl Fn(&[u8]) -> Result<Vec<u8>>,
            msg: &[u8],
        ) -> Result<([u8; 32], Vec<u8>)> {
            let (blinded, state) = self.client_blind(msg)?;
            let sig = signer(&blinded)?;
            self.client_finalize(&state, &sig, msg)
        }
        /// Test support: blind `msg`.
        ///
        /// # Errors
        /// Crypto failure.
        #[cfg(any(test, feature = "testkit"))]
        pub fn client_blind(&self, msg: &[u8]) -> Result<(Vec<u8>, BlindState)> {
            let r = self.0.blind(&mut brs::DefaultRng, msg).map_err(e)?;
            Ok((r.blind_message.0.clone(), BlindState(r)))
        }
        /// Test support: finalize a blind signature.
        ///
        /// # Errors
        /// The signature doesn't verify.
        #[cfg(any(test, feature = "testkit"))]
        pub fn client_finalize(
            &self,
            st: &BlindState,
            blind_sig: &[u8],
            msg: &[u8],
        ) -> Result<([u8; 32], Vec<u8>)> {
            let sig = self
                .0
                .finalize(&brs::BlindSignature(blind_sig.to_vec()), &st.0, msg)
                .map_err(e)?;
            let r =
                st.0.msg_randomizer
                    .ok_or_else(|| Error::internal("no randomizer"))?;
            Ok((r.0, sig.0))
        }
    }

    /// Test support: a client's blinding state.
    #[cfg(any(test, feature = "testkit"))]
    pub struct BlindState(brs::BlindingResult);
}

/// Test support: a phone's secure-chip P-256 key.
#[cfg(any(test, feature = "testkit"))]
pub struct P256Key(aws_lc_rs::signature::EcdsaKeyPair);

#[cfg(any(test, feature = "testkit"))]
impl P256Key {
    /// A fresh key.
    ///
    /// # Panics
    /// If the generator fails (tests only).
    #[must_use]
    pub fn generate() -> Self {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        Self(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("p256 keygen"))
    }
    /// SubjectPublicKeyInfo DER.
    ///
    /// # Panics
    /// Encoding failure (tests only).
    #[must_use]
    pub fn spki(&self) -> Vec<u8> {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
        use aws_lc_rs::signature::KeyPair;
        let der: PublicKeyX509Der<'_> = self.0.public_key().as_der().expect("spki");
        der.as_ref().to_vec()
    }
    /// Sign (ASN.1 DER).
    ///
    /// # Panics
    /// Signing failure (tests only).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0
            .sign(&aws_lc_rs::rand::SystemRandom::new(), msg)
            .expect("p256 sign")
            .as_ref()
            .to_vec()
    }
}

/* -------------------------------- at rest -------------------------------- */

/// Seal at rest (AES-256-GCM-SIV) under `key`.
///
/// # Errors
/// Over the size cap; the generator failed.
pub fn seal_at_rest(key: &Secret32, t: ObjectType, aad: &[&[u8]], pt: &[u8]) -> Result<Vec<u8>> {
    Ok(pq2::seal_at_rest(key, t, aad, pt)?)
}

/// Open at rest.
///
/// # Errors
/// `Decrypt` (→ `bad_proof`-free internal error at the caller) when the box doesn't open.
pub fn open_at_rest(
    key: &Secret32,
    t: ObjectType,
    aad: &[&[u8]],
    boxed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    pq2::open_at_rest(key, t, aad, boxed).map_err(|_| Error::internal("an at-rest box didn't open"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn mldsa_roundtrip_and_label_separation() {
        let k = MlDsaSecret::generate().unwrap();
        let sig = k.sign(label::STEP_UP, b"m").unwrap();
        let pk = MlDsaPublic::from_bytes(&k.public().to_bytes()).unwrap();
        assert!(pk.verifies(label::STEP_UP, b"m", &sig));
        assert!(
            !pk.verifies(label::LOGIN, b"m", &sig),
            "a signature for one purpose never verifies for another"
        );
        assert!(!pk.verifies(label::STEP_UP, b"n", &sig));
        assert!(!pk.verifies(label::STEP_UP, b"m", &sig[..10]));
    }

    #[test]
    fn share_upload_and_release() {
        let ks = KemSecret::generate().unwrap();
        let share = Secret32::random().unwrap();
        let sealed = phone::seal_upload(&ks.public(), b"acct", b"obj", b"env", &share).unwrap();
        assert_eq!(sealed.len(), SEALED_SHARE_LEN);
        let got = open_upload_share(&ks, b"acct", b"obj", b"env", &sealed).unwrap();
        assert!(got.ct_eq(&share));
        assert!(open_upload_share(&ks, b"acct", b"other", b"env", &sealed).is_err());
        let once = KemSecret::generate().unwrap();
        let rel = seal_release_share(&once.public(), b"acct", b"obj", b"bind", &got).unwrap();
        assert!(
            phone::open_release(&once, b"acct", b"obj", b"bind", &rel)
                .unwrap()
                .ct_eq(&share)
        );
    }

    #[test]
    fn p256_rejects_garbage_and_non_spki() {
        assert!(!p256_verifies(&[0u8; 91], b"m", b"sig"));
        assert!(!p256_verifies(&[4u8; 65], b"m", b"sig"));
    }
}
