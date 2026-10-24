//! A test PKI (feature `testkit`, never in a release build): Android key attestation chains
//! and App Attest objects shaped exactly like a phone's, under throwaway **test roots**.
//!
//! The roots' keys are made fresh for each [`TestPki`], so they are never one of the vendors'
//! pinned keys: a production [`crate::Verifier`] refuses to be built with them
//! (`test_root_in_production`), and a production verifier built from [`crate::Trust::pinned`]
//! answers `untrusted_root` to everything made here.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PublicKeyData, SerialNumber,
    SignatureAlgorithm,
};

use crate::apple::Environment;
use crate::{Anchor, Trust, sha256};

/// The package name the test chains carry.
pub const PACKAGE: &str = "app.humid.vault";
/// The signing-certificate digest the test chains carry.
pub const SIGNER: [u8; 32] = [1; 32];
/// The Apple team id the test App Attest objects carry.
pub const TEAM_ID: &str = "TEAM123456";
/// The App ID the test App Attest objects carry.
pub const APP_ID: &str = "TEAM123456.app.humid.vault";

/* ------------------------------- DER builder ------------------------------- */

fn len(n: usize) -> Vec<u8> {
    match n {
        0..=127 => vec![u8::try_from(n).unwrap_or(0)],
        128..=255 => vec![0x81, u8::try_from(n).unwrap_or(0)],
        _ => {
            let b = u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes();
            vec![0x82, b[0], b[1]]
        }
    }
}

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    [tag, &len(content.len()), content].concat()
}

/// SEQUENCE.
#[must_use]
pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &items.concat())
}

/// SET.
#[must_use]
pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &items.concat())
}

/// OCTET STRING.
#[must_use]
pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}

fn uint_bytes(n: u64) -> Vec<u8> {
    let mut b: Vec<u8> = n
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|x| *x == 0)
        .collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    b
}

/// INTEGER.
#[must_use]
pub fn int(n: u64) -> Vec<u8> {
    tlv(&[0x02], &uint_bytes(n))
}

/// ENUMERATED.
#[must_use]
pub fn enumerated(n: u64) -> Vec<u8> {
    tlv(&[0x0a], &uint_bytes(n))
}

/// BOOLEAN.
#[must_use]
pub fn boolean(v: bool) -> Vec<u8> {
    tlv(&[0x01], &[if v { 0xff } else { 0 }])
}

/// NULL.
#[must_use]
pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// `[n] EXPLICIT inner` (high-tag form above 30).
#[must_use]
pub fn explicit(n: u32, inner: &[u8]) -> Vec<u8> {
    if n < 31 {
        return tlv(&[0xa0 | u8::try_from(n).unwrap_or(0)], inner);
    }
    let mut groups = vec![];
    let mut v = n;
    loop {
        groups.insert(0, u8::try_from(v & 0x7f).unwrap_or(0));
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    let k = groups.len();
    for g in &mut groups[..k - 1] {
        *g |= 0x80;
    }
    let mut tag = vec![0xbf];
    tag.extend(groups);
    tlv(&tag, inner)
}

/* ------------------------------- Android ------------------------------- */

/// A KeyDescription like an Android 17 phone's for HumID's live key. Change any field to make
/// a bad one.
#[derive(Clone, Debug)]
pub struct KeyDesc {
    /// attestationVersion (KeyMint 4 = 400).
    pub attestation_version: u64,
    /// attestationSecurityLevel (1 TEE, 2 StrongBox).
    pub attestation_level: u64,
    /// keyMintSecurityLevel.
    pub keymint_level: u64,
    /// The attestation challenge.
    pub challenge: Vec<u8>,
    /// PURPOSE.
    pub purposes: Vec<u64>,
    /// ALGORITHM (3 = EC).
    pub algorithm: u64,
    /// EC_CURVE (1 = P-256), or absent.
    pub curve: Option<u64>,
    /// ORIGIN (0 = generated), or absent.
    pub origin: Option<u64>,
    /// NO_AUTH_REQUIRED.
    pub no_auth_required: bool,
    /// USER_AUTH_TYPE (2 = biometric), or absent.
    pub user_auth_type: Option<u64>,
    /// AUTH_TIMEOUT, or absent.
    pub auth_timeout: Option<u64>,
    /// ALLOW_WHILE_ON_BODY.
    pub allow_while_on_body: bool,
    /// UNLOCKED_DEVICE_REQUIRED.
    pub unlocked_device_required: bool,
    /// RootOfTrust deviceLocked.
    pub device_locked: bool,
    /// RootOfTrust verifiedBootState (0 = verified).
    pub boot_state: u64,
    /// OS_VERSION, or absent.
    pub os_version: Option<u64>,
    /// OS_PATCHLEVEL (YYYYMM), or absent.
    pub patch_level: Option<u64>,
    /// The package.
    pub package: String,
    /// The signing certificate digest.
    pub signer: [u8; 32],
}

impl KeyDesc {
    /// A perfect StrongBox key for `challenge`.
    #[must_use]
    pub fn strongbox(challenge: &[u8]) -> Self {
        Self {
            attestation_version: 400,
            attestation_level: 2,
            keymint_level: 2,
            challenge: challenge.to_vec(),
            purposes: vec![2],
            algorithm: 3,
            curve: Some(1),
            origin: Some(0),
            no_auth_required: false,
            user_auth_type: Some(2),
            auth_timeout: None,
            allow_while_on_body: false,
            unlocked_device_required: true,
            device_locked: true,
            boot_state: 0,
            os_version: Some(170_000),
            patch_level: Some(202_609),
            package: PACKAGE.into(),
            signer: SIGNER,
        }
    }

    /// A perfect TEE key for `challenge`.
    #[must_use]
    pub fn tee(challenge: &[u8]) -> Self {
        Self {
            attestation_level: 1,
            keymint_level: 1,
            ..Self::strongbox(challenge)
        }
    }

    /// The extension's DER.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut hw: Vec<(u32, Vec<u8>)> = vec![
            (
                1,
                set(&self.purposes.iter().map(|p| int(*p)).collect::<Vec<_>>()),
            ),
            (2, int(self.algorithm)),
            (3, int(256)),
            (5, set(&[int(4)])),
        ];
        if let Some(c) = self.curve {
            hw.push((10, int(c)));
        }
        if self.no_auth_required {
            hw.push((503, null()));
        }
        if let Some(u) = self.user_auth_type {
            hw.push((504, int(u)));
        }
        if let Some(t) = self.auth_timeout {
            hw.push((505, int(t)));
        }
        if self.allow_while_on_body {
            hw.push((506, null()));
        }
        if self.unlocked_device_required {
            hw.push((509, null()));
        }
        if let Some(o) = self.origin {
            hw.push((702, int(o)));
        }
        hw.push((
            704,
            seq(&[
                octets(&[7; 32]),
                boolean(self.device_locked),
                enumerated(self.boot_state),
                octets(&[9; 32]),
            ]),
        ));
        if let Some(v) = self.os_version {
            hw.push((705, int(v)));
        }
        if let Some(p) = self.patch_level {
            hw.push((706, int(p)));
        }
        let app = seq(&[
            set(&[seq(&[octets(self.package.as_bytes()), int(1)])]),
            set(&[octets(&self.signer)]),
        ]);
        let sw: Vec<(u32, Vec<u8>)> = vec![(701, int(1_790_000_000_000)), (709, octets(&app))];
        let list = |mut l: Vec<(u32, Vec<u8>)>| {
            l.sort_by_key(|(t, _)| *t);
            seq(&l.iter().map(|(t, v)| explicit(*t, v)).collect::<Vec<_>>())
        };
        seq(&[
            int(self.attestation_version),
            enumerated(self.attestation_level),
            int(self.attestation_version),
            enumerated(self.keymint_level),
            octets(&self.challenge),
            octets(&[]),
            list(sw),
            list(hw),
        ])
    }
}

/// Chain knobs.
#[derive(Clone, Debug, Default)]
pub struct ChainOpts {
    /// The intermediate's notAfter is this long before `now` (ms): an expired certificate.
    pub intermediate_expired_ms: Option<i64>,
    /// The intermediate isn't a CA.
    pub intermediate_not_ca: bool,
    /// A second certificate also carries a KeyDescription.
    pub description_on_intermediate: bool,
}

/* ------------------------------- the PKI ------------------------------- */

struct Ca {
    params: CertificateParams,
    key: rcgen::KeyPair,
    der: Vec<u8>,
}

impl Ca {
    fn root(cn: &str, alg: &'static SignatureAlgorithm, now: i64) -> Self {
        let key = rcgen::KeyPair::generate_for(alg).expect("test key");
        let mut params = ca_params(cn, now, 20 * 365);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let der = params.self_signed(&key).expect("test root").der().to_vec();
        Self { params, key, der }
    }

    fn sub(
        &self,
        cn: &str,
        alg: &'static SignatureAlgorithm,
        now: i64,
        ca: bool,
        expired_ms: Option<i64>,
    ) -> Self {
        let key = rcgen::KeyPair::generate_for(alg).expect("test key");
        let mut params = ca_params(cn, now, 5 * 365);
        if let Some(e) = expired_ms {
            params.not_before = ts(now - 10 * 86_400_000 - e);
            params.not_after = ts(now - e);
        }
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        } else {
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        let issuer = Issuer::from_params(&self.params, &self.key);
        let der = params
            .signed_by(&key, &issuer)
            .expect("test cert")
            .der()
            .to_vec();
        Self { params, key, der }
    }

    fn leaf(&self, point: &[u8], now: i64, ext: Vec<CustomExtension>) -> Vec<u8> {
        let mut params = ca_params("Android Keystore Key", now, 365);
        params.is_ca = IsCa::NoCa;
        params.custom_extensions = ext;
        let issuer = Issuer::from_params(&self.params, &self.key);
        params
            .signed_by(&RawP256(point.to_vec()), &issuer)
            .expect("test leaf")
            .der()
            .to_vec()
    }
}

fn ts(ms: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000)).expect("time")
}

fn ca_params(cn: &str, now: i64, days: i64) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.not_before = ts(now - 86_400_000);
    p.not_after = ts(now + days * 86_400_000);
    p.serial_number = Some(SerialNumber::from_slice(&random::<8>()));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).expect("random");
    b[0] |= 1; // a non-zero leading byte keeps serials N bytes long
    b[0] &= 0x7f;
    b
}

/// A P-256 public key given as its uncompressed point (what rcgen certifies for a leaf whose
/// private key it doesn't hold: the phone's chip key).
struct RawP256(Vec<u8>);

impl PublicKeyData for RawP256 {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

/// The P-256 point of a SubjectPublicKeyInfo.
///
/// # Panics
/// Not a P-256 SPKI (tests only).
#[must_use]
pub fn point_of(spki: &[u8]) -> Vec<u8> {
    assert_eq!(spki.len(), 91, "P-256 SPKI");
    spki[26..].to_vec()
}

/// Throwaway attestation roots and intermediates, made at `now` (ms).
pub struct TestPki {
    now: i64,
    android_root: Ca,
    apple_root: Ca,
    apple_inter: Ca,
}

impl TestPki {
    /// A fresh PKI whose certificates are valid around `now` (ms).
    ///
    /// # Panics
    /// Key generation failure (tests only).
    #[must_use]
    pub fn new(now: i64) -> Self {
        let android_root = Ca::root("HumID Test Attestation Root", &PKCS_ECDSA_P384_SHA384, now);
        let apple_root = Ca::root("HumID Test App Attest Root", &PKCS_ECDSA_P384_SHA384, now);
        let apple_inter = apple_root.sub(
            "Apple App Attestation CA 1",
            &PKCS_ECDSA_P384_SHA384,
            now,
            true,
            None,
        );
        Self {
            now,
            android_root,
            apple_root,
            apple_inter,
        }
    }

    /// The Android test root, as an anchor.
    ///
    /// # Panics
    /// Never.
    #[must_use]
    pub fn android_anchor(&self) -> Anchor {
        Anchor::from_der(&self.android_root.der).expect("test root")
    }

    /// The App Attest test root, as an anchor.
    ///
    /// # Panics
    /// Never.
    #[must_use]
    pub fn apple_anchor(&self) -> Anchor {
        Anchor::from_der(&self.apple_root.der).expect("test root")
    }

    /// The vendors' pinned roots plus this PKI's (development only).
    #[must_use]
    pub fn trust(&self) -> Trust {
        Trust::pinned().with_test_anchors(vec![self.android_anchor()], vec![self.apple_anchor()])
    }

    /// An Android chain (leaf, intermediate, root) attesting the P-256 key `live_spki`.
    #[must_use]
    pub fn android_chain(&self, kd: &KeyDesc, live_spki: &[u8], o: &ChainOpts) -> Vec<Vec<u8>> {
        let mut inter = self.android_root.sub(
            "HumID Test StrongBox CA",
            &PKCS_ECDSA_P256_SHA256,
            self.now,
            !o.intermediate_not_ca,
            o.intermediate_expired_ms,
        );
        if o.description_on_intermediate {
            let mut params = inter.params.clone();
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(KD_OID, kd.encode()));
            let issuer = Issuer::from_params(&self.android_root.params, &self.android_root.key);
            inter.der = params
                .signed_by(&inter.key, &issuer)
                .expect("cert")
                .der()
                .to_vec();
        }
        let leaf = inter.leaf(
            &point_of(live_spki),
            self.now,
            vec![CustomExtension::from_oid_content(KD_OID, kd.encode())],
        );
        vec![leaf, inter.der, self.android_root.der.clone()]
    }

    /// An App Attest attestation object for `client_data_hash`, as
    /// `DCAppAttestService.attestKey` returns it.
    #[must_use]
    pub fn app_attestation(
        &self,
        key: &AppAttestKey,
        client_data_hash: &[u8; 32],
        app_id: &str,
        env: Environment,
        os: &str,
    ) -> Vec<u8> {
        let point = key.point();
        let key_id = sha256(&[&point]);
        let aaguid: &[u8; 16] = match env {
            Environment::Production => b"appattest\0\0\0\0\0\0\0",
            Environment::Development => b"appattestdevelop",
        };
        let cose = cbor_map(&[
            (cbor_int(1), cbor_int(2)),
            (cbor_int(3), cbor_int(-7)),
            (cbor_int(-1), cbor_int(1)),
            (cbor_int(-2), cbor_bytes(&point[1..33])),
            (cbor_int(-3), cbor_bytes(&point[33..])),
        ]);
        let auth_data = [
            &sha256(&[app_id.as_bytes()])[..],
            &[0x40],
            &0u32.to_be_bytes(),
            aaguid,
            &32u16.to_be_bytes(),
            &key_id,
            &cose,
        ]
        .concat();
        let nonce = sha256(&[&auth_data, client_data_hash]);
        let nonce_ext = seq(&[explicit(1, &octets(&nonce))]);
        let os_ext = seq(&[explicit(1400, &octets(os.as_bytes()))]);
        let leaf = self.apple_inter.leaf(
            &point,
            self.now,
            vec![
                CustomExtension::from_oid_content(APPLE_NONCE_OID, nonce_ext),
                CustomExtension::from_oid_content(APPLE_OS_OID, os_ext),
            ],
        );
        cbor_map(&[
            (cbor_text("fmt"), cbor_text("apple-appattest")),
            (
                cbor_text("attStmt"),
                cbor_map(&[
                    (
                        cbor_text("x5c"),
                        cbor_array(&[cbor_bytes(&leaf), cbor_bytes(&self.apple_inter.der)]),
                    ),
                    (cbor_text("receipt"), cbor_bytes(b"receipt")),
                ]),
            ),
            (cbor_text("authData"), cbor_bytes(&auth_data)),
        ])
    }
}

const KD_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
const APPLE_NONCE_OID: &[u64] = &[1, 2, 840, 113_635, 100, 8, 2];
const APPLE_OS_OID: &[u64] = &[1, 2, 840, 113_635, 100, 8, 7];

/* ------------------------------- App Attest key ------------------------------- */

/// An App Attest key (software here; the Secure Enclave's on a phone).
pub struct AppAttestKey(EcdsaKeyPair);

impl std::fmt::Debug for AppAttestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppAttestKey")
    }
}

impl AppAttestKey {
    /// A fresh key.
    ///
    /// # Panics
    /// Key generation failure (tests only).
    #[must_use]
    pub fn generate() -> Self {
        Self(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("p256"))
    }

    /// The uncompressed point.
    #[must_use]
    pub fn point(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }

    /// An assertion for `client_data_hash` with `counter`, as
    /// `DCAppAttestService.generateAssertion` returns it.
    ///
    /// # Panics
    /// Signing failure (tests only).
    #[must_use]
    pub fn assertion(&self, app_id: &str, client_data_hash: &[u8; 32], counter: u32) -> Vec<u8> {
        // Apple sets the AT flag here too (no credential data follows)
        let ad = [
            &sha256(&[app_id.as_bytes()])[..],
            &[0x40],
            &counter.to_be_bytes(),
        ]
        .concat();
        let nonce = sha256(&[&ad, client_data_hash]);
        let sig = self.0.sign(&SystemRandom::new(), &nonce).expect("sign");
        cbor_map(&[
            (cbor_text("signature"), cbor_bytes(sig.as_ref())),
            (cbor_text("authenticatorData"), cbor_bytes(&ad)),
        ])
    }
}

/* ------------------------------- CBOR builder ------------------------------- */

fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | u8::try_from(n).unwrap_or(0)],
        24..=0xff => vec![m | 24, u8::try_from(n).unwrap_or(0)],
        0x100..=0xffff => [&[m | 25][..], &u16::try_from(n).unwrap_or(0).to_be_bytes()].concat(),
        _ => [&[m | 26][..], &u32::try_from(n).unwrap_or(0).to_be_bytes()].concat(),
    }
}

/// A CBOR integer.
#[must_use]
pub fn cbor_int(v: i64) -> Vec<u8> {
    if v >= 0 {
        cbor_head(0, v.unsigned_abs())
    } else {
        cbor_head(1, (-1 - v).unsigned_abs())
    }
}

/// A CBOR byte string.
#[must_use]
pub fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    [cbor_head(2, b.len() as u64), b.to_vec()].concat()
}

/// A CBOR text string.
#[must_use]
pub fn cbor_text(s: &str) -> Vec<u8> {
    [cbor_head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}

/// A CBOR array.
#[must_use]
pub fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
    [cbor_head(4, items.len() as u64), items.concat()].concat()
}

/// A CBOR map.
#[must_use]
pub fn cbor_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut o = cbor_head(5, entries.len() as u64);
    for (k, v) in entries {
        o.extend_from_slice(k);
        o.extend_from_slice(v);
    }
    o
}
