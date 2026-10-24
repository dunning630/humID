//! Apple App Attest (https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
//!
//! iOS can't attest a Secure Enclave key's access policy to a third party, so HumID proves the
//! next best thing at enrolment: the genuine, signed HumID app on a genuine Apple device made
//! this device's live key in this enrolment. The app makes its live key in the Secure Enclave
//! (`.biometryCurrentSet`), then asks App Attest to vouch for
//! `clientDataHash = SHA-256(challenge ‖ live key SPKI)`.
//!
//! Then **every live check** carries an App Attest assertion over that check's digest, signed
//! by the attested App Attest key with a counter that must strictly increase: a copied live
//! key on another device, or a replayed check, fails.
//!
//! Attestation checks: the CBOR object (exactly `fmt`, `attStmt`, `authData`); `x5c` =
//! credential certificate + intermediate to Apple's root; every certificate in date; the
//! nonce `SHA-256(authData ‖ clientDataHash)` in the credential certificate; the RP id is
//! `SHA-256(<team id>.<bundle id>)` of an allowed app; counter 0; the AAGUID is production
//! (or development, only where allowed); the credential id is the key id and the COSE key the
//! certificate's key; the OS version is at least the policy's.

use crate::cbor::{self, Value};
use crate::der::{self, tag};
use crate::x509::{self, Cert, Key, oid};
use crate::{BAD, Mode, Result, Verifier, ct_eq, refuse, sha256};

/// Largest attestation object accepted (real ones are about 5 KiB with the receipt).
pub const MAX_ATTESTATION: usize = 32 << 10;
/// Largest assertion accepted (real ones are about 120 bytes).
pub const MAX_ASSERTION: usize = 1024;

const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// The App Attest environment a build was signed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// App Store and TestFlight builds.
    Production,
    /// Xcode builds.
    Development,
}

/// HumID's iOS rules (from the signed server policy).
#[derive(Clone, Debug)]
pub struct ApplePolicy {
    /// Allowed App IDs, `<team id>.<bundle id>`.
    pub app_ids: Vec<String>,
    /// The environment accepted.
    pub environment: Environment,
    /// Oldest iOS accepted (major version).
    pub min_os_major: u32,
}

/// What an accepted App Attest attestation proved (kept with the device).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppleAttested {
    /// The App Attest key id (SHA-256 of its point).
    pub key_id: Vec<u8>,
    /// The App Attest key: the uncompressed P-256 point (65 bytes). Assertions verify under it.
    pub public_key: Vec<u8>,
    /// The App ID it was made for.
    pub app_id: String,
    /// The environment.
    pub environment: Environment,
    /// The iOS version the certificate names.
    pub os_version: String,
}

/// `clientDataHash` for an enrolment: `SHA-256(challenge ‖ live key SPKI)`.
#[must_use]
pub fn enrolment_client_data_hash(challenge: &[u8], live_spki: &[u8]) -> [u8; 32] {
    sha256(&[challenge, live_spki])
}

/// The authenticator data's fixed head: RP id hash, flags, counter.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

fn auth_data(b: &[u8]) -> Result<AuthData<'_>> {
    if b.len() < 37 {
        return Err(BAD);
    }
    Ok(AuthData {
        rp_id_hash: &b[..32],
        flags: b[32],
        counter: u32::from_be_bytes([b[33], b[34], b[35], b[36]]),
        rest: &b[37..],
    })
}

/// Extensions (iOS 27+): a CBOR map that must use the rest exactly.
fn extensions(flags: u8, rest: &[u8]) -> Result<()> {
    if flags & FLAG_ED == 0 {
        return if rest.is_empty() { Ok(()) } else { Err(BAD) };
    }
    match cbor::decode(rest) {
        Ok(Value::Map(_)) => Ok(()),
        _ => Err(BAD),
    }
}

fn app_for<'p>(p: &'p ApplePolicy, rp_id_hash: &[u8]) -> Result<&'p String> {
    p.app_ids
        .iter()
        .find(|id| ct_eq(&sha256(&[id.as_bytes()]), rp_id_hash))
        .ok_or(refuse(
            "wrong_app",
            "The proof was made for a different app.",
        ))
}

fn environment(v: &Verifier, p: &ApplePolicy, aaguid: &[u8]) -> Result<Environment> {
    let env = if aaguid == AAGUID_PRODUCTION {
        Environment::Production
    } else if aaguid == AAGUID_DEVELOPMENT {
        Environment::Development
    } else {
        return Err(BAD);
    };
    // a production server takes production builds only, whatever its policy says
    if env != p.environment || (v.mode() == Mode::Production && env != Environment::Production) {
        return Err(refuse(
            "wrong_environment",
            "This server accepts only App Store builds of HumID.",
        ));
    }
    Ok(env)
}

/// `SEQUENCE { [tag] EXPLICIT OCTET STRING }`: Apple's extension shape.
fn tagged_octets(ext: &[u8], n: u32) -> Result<&[u8]> {
    let mut s = der::one(ext)?.inner(tag::SEQUENCE)?;
    while !s.is_empty() {
        let t = s.read()?;
        if t.class == der::class::CONTEXT && t.tag == n && t.constructed {
            return Ok(der::one(t.value)?.prim(tag::OCTET_STRING)?);
        }
    }
    Err(BAD)
}

fn os_major(v: &str) -> Option<u32> {
    let major = v.split('.').next()?;
    if major.is_empty() || major.len() > 3 || !major.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    major.parse().ok()
}

/// Verify an App Attest attestation object.
///
/// # Errors
/// `bad_attestation`, `untrusted_root`, `wrong_challenge`, `wrong_app`, `wrong_environment`,
/// `old_ios`, `not_configured`.
pub fn verify_attestation(
    v: &Verifier,
    object: &[u8],
    client_data_hash: &[u8; 32],
    p: &ApplePolicy,
    now: i64,
) -> Result<AppleAttested> {
    if p.app_ids.is_empty() {
        return Err(refuse(
            "not_configured",
            "The server isn't set up for iPhone (no App ID).",
        ));
    }
    if object.len() > MAX_ATTESTATION {
        return Err(BAD);
    }
    let o = cbor::decode(object).map_err(|_| BAD)?;
    let mut keys = o.text_keys().ok_or(BAD)?;
    keys.sort_unstable();
    if keys != ["attStmt", "authData", "fmt"]
        || o.get("fmt") != Some(&Value::Text("apple-appattest"))
    {
        return Err(BAD);
    }
    let stmt = o.get("attStmt").ok_or(BAD)?;
    let mut sk = stmt.text_keys().ok_or(BAD)?;
    sk.sort_unstable();
    if sk != ["receipt", "x5c"] {
        return Err(BAD);
    }
    let Some(Value::Array(x5c)) = stmt.get("x5c") else {
        return Err(BAD);
    };
    stmt.get("receipt").and_then(Value::bytes).ok_or(BAD)?;
    let ad = o.get("authData").and_then(Value::bytes).ok_or(BAD)?;
    let [leaf, inter] = x5c.as_slice() else {
        return Err(BAD);
    };
    let leaf = Cert::parse(leaf.bytes().ok_or(BAD)?)?;
    let inter = Cert::parse(inter.bytes().ok_or(BAD)?)?;
    if leaf.issuer != inter.subject || !leaf.signed_by(&inter.key) {
        return Err(BAD);
    }
    let Some(root) = v.issuer_of(v.apple_anchors(), &inter) else {
        return Err(refuse(
            "untrusted_root",
            "The proof isn't vouched for by Apple.",
        ));
    };
    let root_valid = Cert::parse(root.der()).is_ok_and(|r| r.valid_at(now));
    if inter.ca.is_none() || !leaf.valid_at(now) || !inter.valid_at(now) || !root_valid {
        return Err(refuse(
            "bad_attestation",
            "A certificate in the device's proof is out of date.",
        ));
    }
    // the nonce binds the authenticator data and this enrolment's client data
    let nonce = sha256(&[ad, client_data_hash]);
    let ext = leaf.extension(oid::APPLE_NONCE).ok_or(BAD)?;
    if !ct_eq(tagged_octets(ext, 1)?, &nonce) {
        return Err(refuse(
            "wrong_challenge",
            "The proof was made for a different enrolment or key.",
        ));
    }
    let Key::P256(point) = &leaf.key else {
        return Err(BAD);
    };
    let key_id = sha256(&[point]);
    let a = auth_data(ad)?;
    let app_id = app_for(p, a.rp_id_hash)?;
    if a.counter != 0 || a.flags & FLAG_AT == 0 {
        return Err(BAD);
    }
    let rest = a.rest;
    if rest.len() < 18 {
        return Err(BAD);
    }
    let env = environment(v, p, &rest[..16])?;
    let cred_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    let cred = rest.get(18..18 + cred_len).ok_or(BAD)?;
    if !ct_eq(cred, &key_id) {
        return Err(BAD);
    }
    let (cose, used) = cbor::decode_prefix(&rest[18 + cred_len..]).map_err(|_| BAD)?;
    // COSE_Key: kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), x, y = the certificate's key
    let x = cose.get_int(-2).and_then(Value::bytes).ok_or(BAD)?;
    let y = cose.get_int(-3).and_then(Value::bytes).ok_or(BAD)?;
    if cose.get_int(1).and_then(Value::as_int) != Some(2)
        || cose.get_int(-1).and_then(Value::as_int) != Some(1)
        || cose
            .get_int(3)
            .and_then(Value::as_int)
            .is_some_and(|alg| alg != -7)
        || x.len() != 32
        || y.len() != 32
        || !ct_eq(&point[1..33], x)
        || !ct_eq(&point[33..], y)
    {
        return Err(BAD);
    }
    extensions(a.flags, &rest[18 + cred_len + used..])?;
    let os = leaf
        .extension(oid::APPLE_OS_VERSION)
        .map(|e| tagged_octets(e, 1400))
        .transpose()?
        .map(|b| String::from_utf8(b.to_vec()).map_err(|_| BAD))
        .transpose()?
        .unwrap_or_default();
    if os_major(&os).is_none_or(|m| m < p.min_os_major) {
        return Err(refuse(
            "old_ios",
            "HumID needs a newer version of iOS on this iPhone.",
        ));
    }
    Ok(AppleAttested {
        key_id: key_id.to_vec(),
        public_key: point.clone(),
        app_id: app_id.clone(),
        environment: env,
        os_version: os,
    })
}

/// A verified assertion: the counter it carries (store it; the next must be higher).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asserted {
    /// The assertion's counter.
    pub counter: u32,
}

/// Verify one per-check assertion by the attested key `key`.
///
/// * `client_data_hash`: what the check bound (SERVER.md §2.3: SHA-256 of the live digest).
/// * `last_counter`: the highest counter accepted so far for this key (0 after attestation).
///
/// # Errors
/// `bad_assertion` (malformed, wrong app, a signature that doesn't verify),
/// `assertion_replayed` (the counter didn't increase).
pub fn verify_assertion(
    assertion: &[u8],
    attested: &AppleAttested,
    client_data_hash: &[u8; 32],
    last_counter: u32,
) -> Result<Asserted> {
    let bad = refuse(
        "bad_assertion",
        "This iPhone's App Attest proof for this check doesn't verify.",
    );
    if assertion.len() > MAX_ASSERTION {
        return Err(bad);
    }
    let o = cbor::decode(assertion).map_err(|_| bad)?;
    let mut keys = o.text_keys().ok_or(bad)?;
    keys.sort_unstable();
    if keys != ["authenticatorData", "signature"] {
        return Err(bad);
    }
    let sig = o.get("signature").and_then(Value::bytes).ok_or(bad)?;
    let ad = o
        .get("authenticatorData")
        .and_then(Value::bytes)
        .ok_or(bad)?;
    let a = auth_data(ad).map_err(|_| bad)?;
    // Apple sets the AT flag in assertions although no credential data follows: only ED counts
    extensions(a.flags & FLAG_ED, a.rest).map_err(|_| bad)?;
    if !ct_eq(&sha256(&[attested.app_id.as_bytes()]), a.rp_id_hash) {
        return Err(bad);
    }
    let nonce = sha256(&[ad, client_data_hash]);
    if attested.public_key.len() != 65
        || !x509::verify(
            &Key::P256(attested.public_key.clone()),
            oid::ECDSA_SHA256,
            &nonce,
            sig,
        )
    {
        return Err(bad);
    }
    if a.counter <= last_counter {
        return Err(refuse(
            "assertion_replayed",
            "That App Attest proof was already used. Try the check again.",
        ));
    }
    Ok(Asserted { counter: a.counter })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_versions() {
        assert_eq!(os_major("26.1"), Some(26));
        assert_eq!(os_major("14.4"), Some(14));
        assert_eq!(os_major(""), None);
        assert_eq!(os_major("x.1"), None);
        assert_eq!(os_major("99999"), None);
    }
}
