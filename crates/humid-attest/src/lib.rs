//! # humid-attest
//!
//! Proof that a phone's keys live in genuine secure hardware, made by the genuine HumID app:
//! the Rust port of 4.x `packages/attest`, for the 5.0 server (docs/v5/SERVER.md §2.3,
//! V5.md "The live check").
//!
//! | Platform | What is checked | Module |
//! | --- | --- | --- |
//! | Android 17+ | Key attestation chain to a pinned Google root (the RSA root and the 2026 "Key Attestation CA1"), Google's revocation list, the KeyDescription: TEE or StrongBox, the challenge, verified boot, OS version and patch level, and that the key is HumID's live key (sign only, P-256, biometric only, per use, unlocked device, generated in hardware), app package and signing certificate | [`android`] |
//! | iOS 26+ | App Attest attestation to Apple's root: the nonce binding, App ID (team + bundle), counter 0, production vs development AAGUID, key id, OS version; then each live check's assertion with a strictly increasing counter | [`apple`] |
//! | Android | Google's attestation status list, kept as a cached copy with its fetch time; revocation is checked at enrolment, at every sign-in and on a schedule | [`status`] |
//!
//! Parsing is strict (DER and CBOR readers that refuse anything non-canonical), size-capped,
//! and never panics on hostile input: every refusal is a [`Refusal`] with a stable code.
//!
//! **Trust.** [`Trust::pinned`] holds only the vendors' roots, compiled in. A [`Verifier`] in
//! [`Mode::Production`] accepts **only** those roots, whatever [`Trust`] it was given: the
//! testkit's test root (feature `testkit`) can't be accepted there.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod android;
pub mod apple;
pub mod cbor;
pub mod der;
pub mod status;
pub mod x509;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use android::{AndroidAttested, AndroidPolicy, SecurityLevel};
pub use apple::{AppleAttested, ApplePolicy, Environment};
pub use status::StatusList;

/// A refused attestation: a stable code (what the app shows its own words for) and a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// Stable code (`bad_attestation`, `untrusted_root`, `wrong_challenge`, …).
    pub code: &'static str,
    /// Words for the person.
    pub message: &'static str,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Refusal {}

/// `Result` with [`Refusal`].
pub type Result<T> = std::result::Result<T, Refusal>;

pub(crate) const fn refuse(code: &'static str, message: &'static str) -> Refusal {
    Refusal { code, message }
}

pub(crate) const BAD: Refusal = refuse("bad_attestation", "The device's proof can't be read.");

impl From<der::Bad> for Refusal {
    fn from(_: der::Bad) -> Self {
        BAD
    }
}

/// SHA-256.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut c = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        c.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(c.finish().as_ref());
    out
}

/// Constant-time equality.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether a check runs for production or development.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Only the vendors' pinned roots; App Attest production environment only.
    Production,
    /// Test roots allowed (the testkit's).
    Development,
}

/* ------------------------------- roots ------------------------------- */

/// Google's hardware attestation root (RSA-4096, `SERIALNUMBER=f92009e853b6b045`, the 2022
/// re-issue of the key every factory-provisioned chain ends in).
pub const GOOGLE_RSA_ROOT: &[u8] = include_bytes!("../roots/google-rsa-root.der");
/// Google's "Key Attestation CA1" (ECDSA P-384, 2025-07-17 – 2035-07-15): the 2026 rotation;
/// remotely provisioned chains end here from 1 February 2026.
pub const GOOGLE_CA1_ROOT: &[u8] = include_bytes!("../roots/google-key-attestation-ca1.der");
/// Apple App Attestation Root CA (ECDSA P-384, to 2045).
pub const APPLE_APP_ATTEST_ROOT: &[u8] = include_bytes!("../roots/apple-app-attestation-root.der");

/// The compiled-in roots: what production mode accepts, and nothing else, whatever trust
/// store it is handed. A root is matched by its SubjectPublicKeyInfo, so a device that sends
/// an older certificate for the same Google key (the 2016 issue of the RSA root) still matches.
const PINNED: [&[u8]; 3] = [GOOGLE_RSA_ROOT, GOOGLE_CA1_ROOT, APPLE_APP_ATTEST_ROOT];

/// One trust anchor: a root certificate, matched by its public key.
#[derive(Clone, Debug)]
pub struct Anchor {
    der: Vec<u8>,
    spki: Vec<u8>,
    subject: Vec<u8>,
    key: x509::Key,
}

impl Anchor {
    /// From a DER certificate.
    ///
    /// # Errors
    /// `bad_root` when it can't be read or isn't a CA.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let bad = refuse("bad_root", "A trust anchor can't be read.");
        let c = x509::Cert::parse(der).map_err(|_| bad)?;
        if c.ca.is_none() || matches!(c.key, x509::Key::Other) {
            return Err(bad);
        }
        Ok(Self {
            der: der.to_vec(),
            spki: c.spki.to_vec(),
            subject: c.subject.to_vec(),
            key: c.key.clone(),
        })
    }

    /// The certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Whether this anchor's key is one of the vendors' compiled-in roots' keys. Only these
    /// count in production, however the anchor was made.
    #[must_use]
    pub fn is_pinned(&self) -> bool {
        PINNED
            .iter()
            .any(|d| x509::Cert::parse(d).is_ok_and(|c| ct_eq(c.spki, &self.spki)))
    }
}

/// The roots a verifier trusts, per platform.
#[derive(Clone, Debug)]
pub struct Trust {
    /// Android key attestation roots.
    pub android: Vec<Anchor>,
    /// App Attest roots.
    pub apple: Vec<Anchor>,
}

impl Trust {
    /// The vendors' roots, compiled in: Google's two and Apple's App Attest root.
    ///
    /// # Panics
    /// Never: the compiled-in roots are tested to parse.
    #[must_use]
    pub fn pinned() -> Self {
        let a = |d: &[u8]| Anchor::from_der(d).expect("compiled-in root parses");
        Self {
            android: vec![a(GOOGLE_RSA_ROOT), a(GOOGLE_CA1_ROOT)],
            apple: vec![a(APPLE_APP_ATTEST_ROOT)],
        }
    }

    /// The pinned roots plus other anchors (development only: a production [`Verifier`]
    /// refuses to be built with any anchor whose key isn't a vendor's, and would not accept a
    /// chain ending in one if it were).
    #[must_use]
    pub fn with_test_anchors(mut self, android: Vec<Anchor>, apple: Vec<Anchor>) -> Self {
        self.android.extend(android);
        self.apple.extend(apple);
        self
    }

    fn has_test_anchor(&self) -> bool {
        self.android
            .iter()
            .chain(&self.apple)
            .any(|a| !a.is_pinned())
    }
}

/// Checks attestations against a trust store, in a mode.
#[derive(Clone, Debug)]
pub struct Verifier {
    trust: Trust,
    mode: Mode,
}

impl Verifier {
    /// A verifier.
    ///
    /// # Errors
    /// `test_root_in_production`: a production verifier with any anchor that isn't one of the
    /// vendors' compiled-in roots.
    pub fn new(trust: Trust, mode: Mode) -> Result<Self> {
        if mode == Mode::Production && trust.has_test_anchor() {
            return Err(refuse(
                "test_root_in_production",
                "A production server trusts only Google's and Apple's own attestation roots.",
            ));
        }
        Ok(Self { trust, mode })
    }

    /// The mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether `a` may be used now. In production, only a pinned one (checked again on every
    /// use, so no path around [`Verifier::new`] can add a root).
    pub(crate) fn usable(&self, a: &Anchor) -> bool {
        self.mode != Mode::Production || a.is_pinned()
    }

    /// The usable anchor in `anchors` whose key is `key`.
    pub(crate) fn anchor<'a>(&self, anchors: &'a [Anchor], key: &x509::Key) -> Option<&'a Anchor> {
        anchors
            .iter()
            .find(|a| a.key == *key)
            .filter(|a| self.usable(a))
    }

    /// The usable anchor in `anchors` that signed `c`.
    pub(crate) fn issuer_of<'a>(
        &self,
        anchors: &'a [Anchor],
        c: &x509::Cert<'_>,
    ) -> Option<&'a Anchor> {
        anchors
            .iter()
            .filter(|a| self.usable(a))
            .find(|a| a.subject == c.issuer && c.signed_by(&a.key))
    }

    /// The Android anchors.
    pub(crate) fn android_anchors(&self) -> &[Anchor] {
        &self.trust.android
    }

    /// The App Attest anchors.
    pub(crate) fn apple_anchors(&self) -> &[Anchor] {
        &self.trust.apple
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_roots_are_the_vendors() {
        // certificate fingerprints, as 4.x roots.js and the vendors publish them
        let fp = |d: &[u8]| x509::hex(&sha256(&[d]));
        assert_eq!(
            fp(GOOGLE_RSA_ROOT),
            "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"
        );
        assert_eq!(
            fp(GOOGLE_CA1_ROOT),
            "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"
        );
        assert_eq!(
            fp(APPLE_APP_ATTEST_ROOT),
            "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
        );
        // the RSA root's key, as the sample chains in tests/fixtures carry it (2016 issue)
        assert_eq!(
            x509::hex(&sha256(&[x509::Cert::parse(GOOGLE_RSA_ROOT).unwrap().spki])),
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae"
        );
        let t = Trust::pinned();
        assert!(t.android.iter().chain(&t.apple).all(Anchor::is_pinned));
        assert!(matches!(t.android[0].key, x509::Key::Rsa(_)));
        assert!(matches!(t.android[1].key, x509::Key::P384(_)));
        assert!(matches!(t.apple[0].key, x509::Key::P384(_)));
        assert!(!t.has_test_anchor());
        Verifier::new(t, Mode::Production).unwrap();
    }
}
