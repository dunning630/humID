//! Android key attestation (https://source.android.com/docs/security/features/keystore/attestation).
//!
//! The phone's KeyMint (TEE or StrongBox) signs a certificate for a key it generated,
//! describing exactly how that key may be used. HumID accepts a device's live key only if
//! that description says the key
//!
//! - lives in secure hardware: both security levels TEE or StrongBox (StrongBox only, when the
//!   policy says so: a TEE attestation is then a downgrade and refused);
//! - was **generated** there (origin GENERATED: an imported key's bytes existed outside);
//! - signs with ECDSA P-256, and does nothing but sign;
//! - can be used only after a strong biometric, every time: no PIN or password, no
//!   "valid for N seconds" window, not while on-body, never without authentication, and only
//!   while the phone is unlocked (CORE.md §3's gate key settings);
//! - belongs to the HumID app: its package name **and** its release signing certificate;
//! - is on a locked, verified-boot phone on at least the policy's Android version and
//!   security patch;
//! - was made for this enrolment (the attestation challenge).
//!
//! The chain must end in a trusted root (matched by key); every certificate above the leaf
//! must be in date, a CA, allowed to sign certificates and within its path length, and no
//! certificate may be on Google's status list. As Google's own verifier does, the leaf's
//! dates are not checked (devices don't set them reliably).

use crate::der::{self, Bad, Reader, Tlv, class, tag};
use crate::x509::{self, Cert, Key, oid};
use crate::{BAD, Refusal, Result, StatusList, Verifier, ct_eq, refuse};

/// Longest chain accepted (real ones are 3–5).
pub const MAX_CHAIN: usize = 10;
/// Most bytes in a chain.
pub const MAX_CHAIN_BYTES: usize = 64 << 10;
/// Largest attestation challenge KeyMint accepts.
pub const MAX_CHALLENGE: usize = 128;

/// Android's version as KeyMint reports it (`osVersion`, MMmmpp): 17.0.0.
pub const ANDROID_17: u32 = 170_000;

/// Signing certificates never accepted, whatever a policy says: b066cd45…928c is the test key
/// `tools/android-test.keystore` (password "android") that is public in this repository's
/// history (docs/INCIDENT-2026-10-android-test-key.md).
pub const REVOKED_SIGNERS: &[[u8; 32]] = &[[
    0xb0, 0x66, 0xcd, 0x45, 0x64, 0xac, 0x84, 0x46, 0xb0, 0x25, 0x67, 0xe2, 0x76, 0x99, 0x2a, 0xac,
    0xf6, 0x47, 0x83, 0x00, 0x4d, 0xe8, 0x1d, 0xa3, 0xd3, 0xf1, 0xe5, 0x1f, 0x34, 0x11, 0x92, 0x8c,
]];

/// SHA-256 of the certificate the official HumID Android app is signed with (the release key
/// made 2026-10-16, CN=HumID, O=Router and Router LLC). Public: it is in every copy of the app.
pub const HUMID_RELEASE_SIGNER: [u8; 32] = [
    0xbf, 0xd3, 0xdc, 0x42, 0xae, 0xd6, 0xa3, 0xcb, 0xf4, 0xe5, 0x18, 0xda, 0x39, 0x0e, 0x66, 0x68,
    0xeb, 0x3b, 0xc9, 0x03, 0xeb, 0x2e, 0x4c, 0x06, 0x39, 0x32, 0x05, 0xff, 0x49, 0x66, 0x57, 0x8e,
];

/// KeyMint authorisation tags (Tag.aidl, the numbers without their type bits).
pub mod t {
    /// PURPOSE (SET OF INTEGER).
    pub const PURPOSE: u32 = 1;
    /// ALGORITHM.
    pub const ALGORITHM: u32 = 2;
    /// KEY_SIZE.
    pub const KEY_SIZE: u32 = 3;
    /// EC_CURVE.
    pub const EC_CURVE: u32 = 10;
    /// NO_AUTH_REQUIRED.
    pub const NO_AUTH_REQUIRED: u32 = 503;
    /// USER_AUTH_TYPE.
    pub const USER_AUTH_TYPE: u32 = 504;
    /// AUTH_TIMEOUT.
    pub const AUTH_TIMEOUT: u32 = 505;
    /// ALLOW_WHILE_ON_BODY.
    pub const ALLOW_WHILE_ON_BODY: u32 = 506;
    /// TRUSTED_USER_PRESENCE_REQUIRED.
    pub const TRUSTED_USER_PRESENCE: u32 = 507;
    /// UNLOCKED_DEVICE_REQUIRED.
    pub const UNLOCKED_DEVICE_REQUIRED: u32 = 509;
    /// CREATION_DATETIME.
    pub const CREATION_DATETIME: u32 = 701;
    /// ORIGIN.
    pub const ORIGIN: u32 = 702;
    /// ROOT_OF_TRUST.
    pub const ROOT_OF_TRUST: u32 = 704;
    /// OS_VERSION.
    pub const OS_VERSION: u32 = 705;
    /// OS_PATCHLEVEL.
    pub const OS_PATCHLEVEL: u32 = 706;
    /// ATTESTATION_APPLICATION_ID.
    pub const ATTESTATION_APPLICATION_ID: u32 = 709;
    /// VENDOR_PATCHLEVEL.
    pub const VENDOR_PATCHLEVEL: u32 = 718;
    /// BOOT_PATCHLEVEL.
    pub const BOOT_PATCHLEVEL: u32 = 719;
}

const PURPOSE_SIGN: u64 = 2;
const ALGORITHM_EC: u64 = 3;
const CURVE_P256: u64 = 1;
const AUTH_PASSWORD: u64 = 1;
const AUTH_BIOMETRIC: u64 = 2;
const ORIGIN_GENERATED: u64 = 0;
const BOOT_VERIFIED: u64 = 0;

/// Where a key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// 0: software (never accepted).
    Software,
    /// 1: the trusted execution environment.
    Tee,
    /// 2: a StrongBox secure element.
    StrongBox,
    /// Anything else (KeyMint's 100 "keystore", unknown values): never accepted.
    Other,
}

impl SecurityLevel {
    fn from(v: u64) -> Self {
        match v {
            0 => Self::Software,
            1 => Self::Tee,
            2 => Self::StrongBox,
            _ => Self::Other,
        }
    }

    /// As stored and shown.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Tee => "tee",
            Self::StrongBox => "strongbox",
            Self::Other => "other",
        }
    }
}

/// One AuthorizationList: each tag at most once, its explicit inner TLV.
#[derive(Clone, Debug, Default)]
pub struct AuthList<'a>(Vec<(u32, Tlv<'a>)>);

impl<'a> AuthList<'a> {
    fn parse(t: &Tlv<'a>) -> Result<Self> {
        let mut r = t.inner(tag::SEQUENCE)?;
        let mut out: Vec<(u32, Tlv<'a>)> = vec![];
        while !r.is_empty() {
            let e = r.read()?;
            if e.class != class::CONTEXT || !e.constructed {
                return Err(BAD);
            }
            if out.iter().any(|(n, _)| *n == e.tag) {
                return Err(BAD); // a tag twice: which one would count?
            }
            out.push((e.tag, der::one(e.value)?));
        }
        Ok(Self(out))
    }

    /// The value of tag `n`.
    #[must_use]
    pub fn get(&self, n: u32) -> Option<&Tlv<'a>> {
        self.0.iter().find(|(k, _)| *k == n).map(|(_, v)| v)
    }

    /// Whether tag `n` is present.
    #[must_use]
    pub fn has(&self, n: u32) -> bool {
        self.get(n).is_some()
    }

    fn uint(&self, n: u32) -> Result<Option<u64>> {
        self.get(n)
            .map(|v| der::uint(v))
            .transpose()
            .map_err(Refusal::from)
    }

    fn flag(&self, n: u32) -> Result<bool> {
        match self.get(n) {
            Some(v) => der::null(v).map(|()| true).map_err(Refusal::from),
            None => Ok(false),
        }
    }
}

/// The verified boot state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootOfTrust {
    /// The bootloader is locked.
    pub device_locked: bool,
    /// 0 verified, 1 self-signed, 2 unverified, 3 failed.
    pub verified_boot_state: u64,
}

/// The app that asked for the key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppId {
    /// Package names (more than one only for a shared UID).
    pub packages: Vec<String>,
    /// SHA-256 of each signing certificate.
    pub signers: Vec<[u8; 32]>,
}

/// A parsed KeyDescription.
#[derive(Clone, Debug)]
pub struct KeyDescription<'a> {
    /// The attestation format version (3 = Keymaster 4, 100…500 = KeyMint 1…5).
    pub attestation_version: u64,
    /// Who made the attestation.
    pub attestation_level: SecurityLevel,
    /// The KeyMint version.
    pub keymint_version: u64,
    /// Where the key is.
    pub keymint_level: SecurityLevel,
    /// The challenge the app passed.
    pub challenge: &'a [u8],
    /// Software-enforced list.
    pub sw: AuthList<'a>,
    /// Hardware-enforced list.
    pub hw: AuthList<'a>,
}

impl<'a> KeyDescription<'a> {
    /// Parse the extension's value.
    ///
    /// # Errors
    /// `bad_attestation`.
    pub fn parse(v: &'a [u8]) -> Result<Self> {
        let mut r = der::one(v)?.inner(tag::SEQUENCE)?;
        let attestation_version = der::uint(&r.expect(tag::INTEGER)?)?;
        let attestation_level = SecurityLevel::from(der::uint(&r.expect(tag::ENUMERATED)?)?);
        let keymint_version = der::uint(&r.expect(tag::INTEGER)?)?;
        let keymint_level = SecurityLevel::from(der::uint(&r.expect(tag::ENUMERATED)?)?);
        let challenge = r.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?;
        let _unique_id = r.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?;
        let sw = AuthList::parse(&r.expect(tag::SEQUENCE)?)?;
        let hw = AuthList::parse(&r.expect(tag::SEQUENCE)?)?;
        // the schema has had exactly these eight fields from version 1 to 500
        r.finish()?;
        if challenge.len() > MAX_CHALLENGE {
            return Err(BAD);
        }
        Ok(Self {
            attestation_version,
            attestation_level,
            keymint_version,
            keymint_level,
            challenge,
            sw,
            hw,
        })
    }

    /// The verified boot state (hardware-enforced only).
    ///
    /// # Errors
    /// `bad_attestation` when present but malformed.
    pub fn root_of_trust(&self) -> Result<Option<RootOfTrust>> {
        let Some(v) = self.hw.get(t::ROOT_OF_TRUST) else {
            return Ok(None);
        };
        let mut r = v.inner(tag::SEQUENCE)?;
        r.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?;
        let device_locked = der::boolean(&r.read()?)?;
        let verified_boot_state = der::uint(&r.expect(tag::ENUMERATED)?)?;
        if !r.is_empty() {
            r.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?; // verifiedBootHash (v3+)
        }
        r.finish()?;
        Ok(Some(RootOfTrust {
            device_locked,
            verified_boot_state,
        }))
    }

    /// The attesting app (either list; KeyMint puts it in the software one).
    ///
    /// # Errors
    /// `bad_attestation` when present but malformed.
    pub fn app_id(&self) -> Result<AppId> {
        let Some(v) = self
            .sw
            .get(t::ATTESTATION_APPLICATION_ID)
            .or_else(|| self.hw.get(t::ATTESTATION_APPLICATION_ID))
        else {
            return Ok(AppId::default());
        };
        let inner = v.prim(tag::OCTET_STRING)?;
        let mut s = der::one(inner)?.inner(tag::SEQUENCE)?;
        let mut infos = s.expect(tag::SET)?.inner(tag::SET)?;
        let mut packages = vec![];
        while !infos.is_empty() {
            let mut p = infos.expect(tag::SEQUENCE)?.inner(tag::SEQUENCE)?;
            let name = p.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?;
            der::uint(&p.expect(tag::INTEGER)?)?;
            p.finish()?;
            packages.push(String::from_utf8(name.to_vec()).map_err(|_| BAD)?);
            if packages.len() > 32 {
                return Err(BAD);
            }
        }
        let mut signers = vec![];
        if !s.is_empty() {
            let mut d = s.expect(tag::SET)?.inner(tag::SET)?;
            while !d.is_empty() {
                let b = d.expect(tag::OCTET_STRING)?.prim(tag::OCTET_STRING)?;
                signers.push(<[u8; 32]>::try_from(b).map_err(|_| BAD)?);
                if signers.len() > 32 {
                    return Err(BAD);
                }
            }
        }
        s.finish()?;
        Ok(AppId { packages, signers })
    }
}

/// A chain that verified, and its KeyDescription (no HumID rules applied yet).
#[derive(Clone, Debug)]
pub struct Chain<'a> {
    /// The parsed certificates, leaf first.
    pub certs: Vec<Cert<'a>>,
    /// The leaf's KeyDescription.
    pub description: KeyDescription<'a>,
}

impl<'a> Chain<'a> {
    /// The leaf's public key (SubjectPublicKeyInfo DER).
    #[must_use]
    pub fn leaf_spki(&self) -> &'a [u8] {
        self.certs[0].spki
    }

    /// Every certificate's serial, as Google's status list keys them.
    #[must_use]
    pub fn serials(&self) -> Vec<String> {
        self.certs.iter().map(Cert::serial_key).collect()
    }
}

/// Verify a chain (leaf first) up to a trusted root at time `now` (ms), and read the leaf's
/// KeyDescription.
///
/// # Errors
/// `bad_attestation` (malformed, a signature that doesn't verify, out of date, not a CA, a
/// second KeyDescription), `untrusted_root`.
pub fn read_chain<'a>(v: &Verifier, chain: &'a [Vec<u8>], now: i64) -> Result<Chain<'a>> {
    if chain.len() < 2
        || chain.len() > MAX_CHAIN
        || chain.iter().map(Vec::len).sum::<usize>() > MAX_CHAIN_BYTES
    {
        return Err(BAD);
    }
    let certs = chain
        .iter()
        .map(|c| Cert::parse(c))
        .collect::<std::result::Result<Vec<_>, Bad>>()?;
    // Each certificate must be signed by the next one's key. Names are not chained: real
    // StrongBox chains name an issuer other than the certificate that signed them (Google's
    // StrongBox sample in tests/fixtures does), and the signature is the binding that counts.
    for i in 0..certs.len() - 1 {
        if !certs[i].signed_by(&certs[i + 1].key) {
            return Err(refuse(
                "bad_attestation",
                "The device's proof has a signature that doesn't verify.",
            ));
        }
    }
    let top = &certs[certs.len() - 1];
    let anchor = v.anchor(v.android_anchors(), &top.key).ok_or(refuse(
        "untrusted_root",
        "The device's secure chip isn't vouched for by Google.",
    ))?;
    // the chain's own copy of the root must be self-signed by the trusted key; its dates are
    // the pinned certificate's (Google's 2016 issue of the RSA root expired in 2026, and the
    // same key is reissued until 2042)
    if !top.signed_by(&anchor.key) {
        return Err(BAD);
    }
    let pinned = Cert::parse(anchor.der()).map_err(|_| BAD)?;
    if !pinned.valid_at(now) {
        return Err(refuse(
            "bad_attestation",
            "A certificate in the device's proof is out of date.",
        ));
    }
    for (i, c) in certs.iter().enumerate().skip(1) {
        let is_root = i == certs.len() - 1;
        if !is_root && !c.valid_at(now) {
            return Err(refuse(
                "bad_attestation",
                "A certificate in the device's proof is out of date.",
            ));
        }
        let Some(path_len) = c.ca else {
            return Err(refuse(
                "bad_attestation",
                "A certificate that signed the device's proof isn't a certificate authority.",
            ));
        };
        if c.key_usage.is_some_and(|k| k & x509::KU_KEY_CERT_SIGN == 0) {
            return Err(BAD);
        }
        // certificates below this one that are themselves CAs
        if path_len.is_some_and(|n| u64::try_from(i - 1).unwrap_or(u64::MAX) > n) {
            return Err(BAD);
        }
    }
    let with = certs
        .iter()
        .map(|c| c.extension(oid::KEY_DESCRIPTION))
        .collect::<Vec<_>>();
    let Some(kd) = with[0] else {
        return Err(refuse(
            "bad_attestation",
            "The device's proof doesn't describe its key.",
        ));
    };
    if with[1..].iter().any(Option::is_some) {
        return Err(BAD); // only the attested key may carry one
    }
    let description = KeyDescription::parse(kd)?;
    Ok(Chain { certs, description })
}

/// HumID's Android rules (from the signed server policy).
#[derive(Clone, Debug)]
pub struct AndroidPolicy {
    /// Package names of the HumID app.
    pub packages: Vec<String>,
    /// SHA-256 of the release signing certificate(s). Never empty in production.
    pub signers: Vec<[u8; 32]>,
    /// Oldest Android accepted (`osVersion`, e.g. 170000 for Android 17).
    pub min_os_version: u32,
    /// Oldest security patch accepted (YYYYMM).
    pub min_patch_level: u32,
    /// Only StrongBox keys (a TEE key is a downgrade).
    pub strongbox_required: bool,
}

/// What an accepted Android attestation proved (kept with the device).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AndroidAttested {
    /// `tee` or `strongbox`.
    pub level: String,
    /// The attestation format version.
    pub attestation_version: u64,
    /// `osVersion`.
    pub os_version: u32,
    /// `osPatchLevel` (YYYYMM).
    pub patch_level: u32,
    /// The package that asked.
    pub package: String,
    /// Serials of every certificate in the chain (checked against Google's list at every
    /// sign-in and on a schedule).
    pub serials: Vec<String>,
}

impl AndroidAttested {
    /// `android-tee` / `android-strongbox`.
    #[must_use]
    pub fn proven(&self) -> String {
        format!("android-{}", self.level)
    }
}

/// Verify an Android key attestation for a live key.
///
/// * `chain`: DER certificates, leaf first.
/// * `challenge`: what the attestation must be bound to (the enrolment's attestation challenge).
/// * `live_spki`: the live key the device presents (P-256 SubjectPublicKeyInfo): the attested
///   key must be exactly it.
/// * `status`: Google's status list as the server has it (a listed certificate refuses).
///
/// # Errors
/// A [`Refusal`]: `bad_attestation`, `untrusted_root`, `revoked`, `wrong_challenge`,
/// `wrong_key`, `software_key`, `not_strongbox`, `bad_key`, `imported_key`, `no_biometric`,
/// `pin_allowed`, `not_per_use`, `unlocked_use`, `unlocked_device`, `old_android`,
/// `old_patch`, `wrong_app`, `revoked_signer`, `not_configured`, or a status-list refusal.
pub fn verify(
    v: &Verifier,
    chain: &[Vec<u8>],
    challenge: &[u8],
    live_spki: &[u8],
    policy: &AndroidPolicy,
    status: &StatusList,
    now: i64,
) -> Result<AndroidAttested> {
    let c = read_chain(v, chain, now)?;
    let serials = c.serials();
    status.check(&serials, now)?;
    let attested = check_policy(&c, challenge, policy)?;
    if !ct_eq(c.leaf_spki(), live_spki) || !matches!(c.certs[0].key, Key::P256(_)) {
        return Err(refuse(
            "wrong_key",
            "The secure chip vouched for a different key than this device uses.",
        ));
    }
    Ok(AndroidAttested {
        serials,
        ..attested
    })
}

/// Re-check a stored chain (scheduled re-verification and every sign-in): it still ends in
/// a trusted root and no certificate in it is on Google's list now. The policy rules that
/// describe the phone as it was when the key was made (patch level, OS version) are not
/// re-applied: the certificate can't change when the phone updates.
///
/// # Errors
/// `untrusted_root`, `revoked`, a status-list refusal, `bad_attestation`.
pub fn recheck(v: &Verifier, chain: &[Vec<u8>], status: &StatusList, now: i64) -> Result<()> {
    // the chain verified at enrolment; dates are not re-checked (short-lived remotely
    // provisioned intermediates would otherwise remove every phone within weeks)
    let certs = chain
        .iter()
        .map(|c| Cert::parse(c))
        .collect::<std::result::Result<Vec<_>, Bad>>()?;
    let top = certs.last().ok_or(BAD)?;
    if v.anchor(v.android_anchors(), &top.key).is_none() {
        return Err(refuse(
            "untrusted_root",
            "The device's secure chip isn't vouched for by Google any more.",
        ));
    }
    let serials: Vec<String> = certs.iter().map(Cert::serial_key).collect();
    status.check(&serials, now)
}

/// HumID's rules over a verified chain.
///
/// # Errors
/// As [`verify`].
pub fn check_policy(c: &Chain<'_>, challenge: &[u8], p: &AndroidPolicy) -> Result<AndroidAttested> {
    let kd = &c.description;
    if !ct_eq(kd.challenge, challenge) {
        return Err(refuse(
            "wrong_challenge",
            "The device's proof was made for a different enrolment.",
        ));
    }
    let hw_level = |l: SecurityLevel| matches!(l, SecurityLevel::Tee | SecurityLevel::StrongBox);
    if !hw_level(kd.attestation_level) || !hw_level(kd.keymint_level) {
        return Err(refuse(
            "software_key",
            "The key isn't held in the phone's secure hardware.",
        ));
    }
    if p.strongbox_required
        && (kd.attestation_level != SecurityLevel::StrongBox
            || kd.keymint_level != SecurityLevel::StrongBox)
    {
        return Err(refuse(
            "not_strongbox",
            "This server needs the key in the phone's StrongBox secure element.",
        ));
    }
    let hw = &kd.hw;
    let either_flag = |n| -> Result<bool> { Ok(hw.flag(n)? || kd.sw.flag(n)?) };
    // purpose: SIGN, and nothing else
    let purposes = match hw.get(t::PURPOSE) {
        Some(s) => {
            let mut r: Reader<'_> = s.inner(tag::SET)?;
            let mut out = vec![];
            while !r.is_empty() {
                out.push(der::uint(&r.read()?)?);
                if out.len() > 16 {
                    return Err(BAD);
                }
            }
            out
        }
        None => vec![],
    };
    let bad_key = refuse(
        "bad_key",
        "The key isn't HumID's live key (ECDSA P-256, for signing only).",
    );
    if purposes.is_empty() || purposes.iter().any(|x| *x != PURPOSE_SIGN) {
        return Err(bad_key);
    }
    let curve = hw.uint(t::EC_CURVE)?;
    if hw.uint(t::ALGORITHM)? != Some(ALGORITHM_EC)
        || curve.is_some_and(|c| c != CURVE_P256)
        || hw.uint(t::KEY_SIZE)?.is_some_and(|s| s != 256)
        || !matches!(c.certs[0].key, Key::P256(_))
    {
        return Err(bad_key); // some StrongBox chips omit EC_CURVE; the leaf's key settles it
    }
    if hw.uint(t::ORIGIN)? != Some(ORIGIN_GENERATED) {
        return Err(refuse(
            "imported_key",
            "The key wasn't made inside the secure hardware.",
        ));
    }
    if either_flag(t::NO_AUTH_REQUIRED)? {
        return Err(refuse(
            "no_biometric",
            "The key can be used without any check.",
        ));
    }
    let Some(uat) = hw.uint(t::USER_AUTH_TYPE)? else {
        return Err(refuse(
            "no_biometric",
            "The secure hardware doesn't enforce the key's check.",
        ));
    };
    if uat & AUTH_PASSWORD != 0 {
        return Err(refuse(
            "pin_allowed",
            "The key also accepts a PIN or password. HumID needs a live biometric.",
        ));
    }
    if uat & AUTH_BIOMETRIC == 0 {
        return Err(refuse("no_biometric", "The key doesn't need a biometric."));
    }
    let timeout = match hw.uint(t::AUTH_TIMEOUT)? {
        Some(x) => Some(x),
        None => kd.sw.uint(t::AUTH_TIMEOUT)?,
    };
    if timeout.is_some_and(|x| x != 0) || either_flag(t::ALLOW_WHILE_ON_BODY)? {
        return Err(refuse(
            "not_per_use",
            "The key stays usable after one check. HumID needs a check for every use.",
        ));
    }
    if !either_flag(t::UNLOCKED_DEVICE_REQUIRED)? {
        return Err(refuse(
            "unlocked_use",
            "The key can be used while the phone is locked.",
        ));
    }
    match kd.root_of_trust()? {
        Some(r) if r.device_locked && r.verified_boot_state == BOOT_VERIFIED => {}
        _ => {
            return Err(refuse(
                "unlocked_device",
                "The phone's bootloader is unlocked or its software isn't verified.",
            ));
        }
    }
    let os = hw
        .uint(t::OS_VERSION)?
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(0);
    if os < p.min_os_version {
        return Err(refuse(
            "old_android",
            "HumID needs a newer version of Android on this phone.",
        ));
    }
    let patch = hw
        .uint(t::OS_PATCHLEVEL)?
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(0);
    if patch < p.min_patch_level {
        return Err(refuse(
            "old_patch",
            "The phone needs a newer security update before it can use HumID.",
        ));
    }
    let app = kd.app_id()?;
    if p.packages.is_empty() || p.signers.is_empty() {
        return Err(refuse(
            "not_configured",
            "The server doesn't know the HumID app's package and signing certificate.",
        ));
    }
    let Some(package) = app.packages.iter().find(|x| p.packages.contains(x)) else {
        return Err(refuse("wrong_app", "The key wasn't made by the HumID app."));
    };
    // a leaked signing key is refused before any policy setting is looked at
    if app.signers.iter().any(|s| REVOKED_SIGNERS.contains(s)) {
        return Err(refuse(
            "revoked_signer",
            "This copy of the app is signed with a leaked key HumID no longer accepts. Install the official HumID app.",
        ));
    }
    if !app.signers.iter().any(|s| p.signers.contains(s)) {
        return Err(refuse(
            "wrong_app",
            "The key wasn't made by a HumID build we signed.",
        ));
    }
    Ok(AndroidAttested {
        level: kd.keymint_level.as_str().into(),
        attestation_version: kd.attestation_version,
        os_version: os,
        patch_level: patch,
        package: package.clone(),
        serials: vec![],
    })
}
