//! # HUMID-PQ2
//!
//! The one frozen crypto suite of HumID 5.0 (docs/V5.md, "One crypto suite: HUMID-PQ2";
//! byte-for-byte specification in docs/v5/PQ2.md).
//!
//! | Job | Here |
//! | --- | --- |
//! | Key exchange | [`KemSecretKey`] / [`KemPublicKey`]: ML-KEM-1024 + X25519, one KMAC256 combiner over both secrets, both ciphertexts and both public keys |
//! | Everyday signatures | [`MlDsaSigningKey`]: ML-DSA-87, hedged |
//! | Long-lived roots | [`DualSigningKey`]: ML-DSA-87 **and** SLH-DSA-SHA2-256s; [`SlhSigningKey`] alone |
//! | At rest | [`seal_at_rest`] / [`open_at_rest`]: AES-256-GCM-SIV; [`seal_to`] / [`open_sealed`] to a public key |
//! | In transit | [`transit_channel`] → [`TransitSealer`] / [`TransitOpener`]: AES-256-GCM, a key per channel and direction, direction-tagged counter nonces, replay window |
//! | Key derivation | [`kdf`]: KMAC256 over length-prefixed inputs |
//! | Hash | [`sha3_512`], [`shake256`], [`labelled_hash`], [`key_id`] |
//! | Shares | [`seal_share`] / [`open_share`]: phone ↔ key service, both directions |
//!
//! Every encoding starts with `"HUMID-PQ2" ‖ u16 version ‖ u16 type` ([`encoding`]), and the
//! same `{suite, v}` is in every KDF input, AAD and signature context.
//!
//! Rules this crate keeps: no `unsafe`; every secret is wiped on drop and has no `Debug`;
//! secret comparisons are constant time; decoders are bounds-checked and never panic on
//! input; randomness comes only from the platform CSPRNG.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::similar_names
)]

mod aead;
pub mod encoding;
mod error;
mod hash;
mod kdf;
mod kem;
mod rng;
mod secret;
mod selftest;
mod share;
mod sign;

#[cfg(test)]
mod kat;

pub use aead::{
    BOX_OVERHEAD, MAX_PLAINTEXT, NONCE_LEN, REPLAY_WINDOW, Role, SEALED_OVERHEAD, TAG_LEN,
    TransitOpener, TransitSealer, open_at_rest, open_sealed, seal_at_rest, seal_to, siv_open,
    siv_seal, transit_channel,
};
pub use encoding::{ObjectType, SUITE, VERSION};
pub use error::{Error, Result};
pub use hash::{Sha3_512Stream, key_id, labelled_hash, sha3_512, shake256};
pub use kdf::{kdf, kdf_into};
pub use kem::{
    KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN, KEM_SEED_LEN, KemCiphertext, KemPublicKey, KemSecretKey,
};
pub use secret::{Secret, Secret32, ct_eq};
pub use selftest::self_test;
pub use share::{SEALED_SHARE_LEN, ShareDirection, open_share, seal_share};
pub use sign::{
    DualSignature, DualSigningKey, DualVerifyingKey, MLDSA_SIG_LEN, MLDSA_VK_LEN, MlDsaSignature,
    MlDsaSigningKey, MlDsaVerifyingKey, SLH_SEED_LEN, SLH_SIG_LEN, SLH_VK_LEN, SlhSignature,
    SlhSigningKey, SlhVerifyingKey,
};

/// The suite's name and version, as text (`"HUMID-PQ2/1"`), for logs and UI.
pub const SUITE_ID: &str = "HUMID-PQ2/1";

/// Draw `buf.len()` bytes from the platform CSPRNG.
///
/// # Errors
/// [`Error::Rng`] if the platform generator fails.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    rng::fill(buf)
}
