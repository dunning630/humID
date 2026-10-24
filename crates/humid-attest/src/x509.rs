//! X.509 certificates, as much as attestation chains need: the to-be-signed bytes, the
//! signature, validity, the public key, basic constraints, key usage and extensions.
//!
//! Strict: version 3 only, the inner and outer signature algorithms must be identical, an
//! extension appears at most once, and an unknown **critical** extension refuses the
//! certificate (RFC 5280 §4.2).

use aws_lc_rs::signature::{self as sig, UnparsedPublicKey};

use crate::der::{self, Bad, R, Tlv, tag};

/// Largest certificate accepted (real attestation certificates are 0.5–2 KiB).
pub const MAX_CERT: usize = 16 << 10;

/// OIDs (DER contents).
pub mod oid {
    /// ecPublicKey.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1.
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1.
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// rsaEncryption.
    pub const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// ecdsa-with-SHA256.
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384.
    pub const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    /// ecdsa-with-SHA512.
    pub const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    /// sha256WithRSAEncryption.
    pub const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// sha384WithRSAEncryption.
    pub const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// sha512WithRSAEncryption.
    pub const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// basicConstraints.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// keyUsage.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// extendedKeyUsage.
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// Android key attestation: KeyDescription (1.3.6.1.4.1.11129.2.1.17).
    pub const KEY_DESCRIPTION: &[u8] =
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
    /// Apple App Attest nonce (1.2.840.113635.100.8.2).
    pub const APPLE_NONCE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];
    /// Apple App Attest OS version (1.2.840.113635.100.8.7).
    pub const APPLE_OS_VERSION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x07];
}

/// A public key, as a signature check needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// NIST P-256: the uncompressed point (65 bytes).
    P256(Vec<u8>),
    /// NIST P-384: the uncompressed point (97 bytes).
    P384(Vec<u8>),
    /// RSA: the PKCS#1 RSAPublicKey DER.
    Rsa(Vec<u8>),
    /// Anything else (it can be a leaf's key, never an issuer's).
    Other,
}

/// One parsed certificate.
#[derive(Clone, Debug)]
pub struct Cert<'a> {
    /// The whole DER.
    pub raw: &'a [u8],
    /// The to-be-signed bytes.
    pub tbs: &'a [u8],
    /// Signature algorithm OID.
    pub sig_alg: &'a [u8],
    /// Signature bytes.
    pub signature: &'a [u8],
    /// The serial number's content bytes.
    pub serial: &'a [u8],
    /// Issuer Name, DER.
    pub issuer: &'a [u8],
    /// Subject Name, DER.
    pub subject: &'a [u8],
    /// notBefore (ms).
    pub not_before: i64,
    /// notAfter (ms).
    pub not_after: i64,
    /// The SubjectPublicKeyInfo, DER.
    pub spki: &'a [u8],
    /// The key.
    pub key: Key,
    /// basicConstraints: `Some(path_len)` for a CA (`None` inside = no limit); `None` = not a CA.
    pub ca: Option<Option<u64>>,
    /// keyUsage bits, if the extension is present (bit 0 = digitalSignature … bit 5 = keyCertSign).
    pub key_usage: Option<u16>,
    /// Every extension: (OID, critical, value).
    pub extensions: Vec<(&'a [u8], bool, &'a [u8])>,
}

impl<'a> Cert<'a> {
    /// Parse a DER certificate.
    ///
    /// # Errors
    /// Malformed, too large, not v3, or an unknown critical extension.
    pub fn parse(raw: &'a [u8]) -> R<Self> {
        if raw.len() > MAX_CERT {
            return Err(Bad);
        }
        let top = der::one(raw)?;
        let mut c = top.inner(tag::SEQUENCE)?;
        let tbs_t = c.expect(tag::SEQUENCE)?;
        let outer_alg = c.expect(tag::SEQUENCE)?;
        let sig_t = c.expect(tag::BIT_STRING)?;
        c.finish()?;
        let signature = der::bit_string_bytes(&sig_t)?;

        let mut t = tbs_t.inner(tag::SEQUENCE)?;
        let v = t.optional_context(0)?.ok_or(Bad)?;
        if !v.constructed || der::uint(&der::one(v.value)?)? != 2 {
            return Err(Bad); // v3 only
        }
        let serial_t = t.expect(tag::INTEGER)?;
        if serial_t.constructed || serial_t.value.is_empty() || serial_t.value.len() > 21 {
            return Err(Bad);
        }
        let inner_alg = t.expect(tag::SEQUENCE)?;
        if inner_alg.raw != outer_alg.raw {
            return Err(Bad);
        }
        let sig_alg = alg_oid(&outer_alg)?;
        let issuer = t.expect(tag::SEQUENCE)?;
        let mut validity = t.expect(tag::SEQUENCE)?.inner(tag::SEQUENCE)?;
        let not_before = der::time(&validity.read()?)?;
        let not_after = der::time(&validity.read()?)?;
        validity.finish()?;
        let subject = t.expect(tag::SEQUENCE)?;
        let spki = t.expect(tag::SEQUENCE)?;
        let key = parse_spki(&spki)?;
        let _issuer_uid = t.optional_context(1)?;
        let _subject_uid = t.optional_context(2)?;
        let mut extensions = vec![];
        if let Some(e) = t.optional_context(3)? {
            if !e.constructed {
                return Err(Bad);
            }
            let mut list = der::one(e.value)?.inner(tag::SEQUENCE)?;
            while !list.is_empty() {
                let mut x = list.expect(tag::SEQUENCE)?.inner(tag::SEQUENCE)?;
                let id = x.expect(tag::OID)?;
                let mut critical = false;
                if x.peek()?.is(tag::BOOLEAN) {
                    critical = der::boolean(&x.read()?)?;
                }
                let value = x.expect(tag::OCTET_STRING)?;
                x.finish()?;
                if id.constructed || value.constructed {
                    return Err(Bad);
                }
                if extensions.iter().any(|(o, _, _)| *o == id.value) {
                    return Err(Bad); // RFC 5280: at most once
                }
                extensions.push((id.value, critical, value.value));
            }
            if extensions.is_empty() {
                return Err(Bad);
            }
        }
        t.finish()?;
        let mut cert = Cert {
            raw,
            tbs: tbs_t.raw,
            sig_alg,
            signature,
            serial: serial_t.value,
            issuer: issuer.raw,
            subject: subject.raw,
            not_before,
            not_after,
            spki: spki.raw,
            key,
            ca: None,
            key_usage: None,
            extensions: vec![],
        };
        for (id, critical, value) in &extensions {
            match *id {
                oid::BASIC_CONSTRAINTS => cert.ca = basic_constraints(value)?,
                oid::KEY_USAGE => cert.key_usage = Some(key_usage(value)?),
                oid::EXT_KEY_USAGE => {}
                _ if *critical => return Err(Bad),
                _ => {}
            }
        }
        cert.extensions = extensions;
        Ok(cert)
    }

    /// The value of extension `id`, if present.
    #[must_use]
    pub fn extension(&self, id: &[u8]) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|(o, _, _)| *o == id)
            .map(|(_, _, v)| *v)
    }

    /// The serial number as Google's status list writes it: lower-case hex, no leading zeros.
    #[must_use]
    pub fn serial_key(&self) -> String {
        serial_key(&hex(self.serial))
    }

    /// True when `issuer`'s key signed this certificate.
    #[must_use]
    pub fn signed_by(&self, issuer: &Key) -> bool {
        verify(issuer, self.sig_alg, self.tbs, self.signature)
    }

    /// True when `at` (ms) is inside the validity period.
    #[must_use]
    pub fn valid_at(&self, at: i64) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}

/// Lower-case hex.
#[must_use]
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// Normalise a serial number as Google's list keys it: lower-case, no leading zeros.
#[must_use]
pub fn serial_key(hex_serial: &str) -> String {
    let s = hex_serial.to_ascii_lowercase();
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

fn alg_oid<'a>(alg: &Tlv<'a>) -> R<&'a [u8]> {
    let mut a = alg.inner(tag::SEQUENCE)?;
    let id = a.expect(tag::OID)?;
    if id.constructed {
        return Err(Bad);
    }
    if !a.is_empty() {
        // RSA PKCS#1 v1.5 carries NULL parameters. ECDSA should carry none (RFC 5758), but real
        // StrongBox chips write NULL (tests/fixtures/android-attestation, StrongBox leaf): a
        // NULL is accepted for both, anything else for neither.
        der::null(&a.read()?)?;
    }
    a.finish()?;
    Ok(id.value)
}

fn parse_spki(spki: &Tlv<'_>) -> R<Key> {
    let mut s = spki.inner(tag::SEQUENCE)?;
    let mut alg = s.expect(tag::SEQUENCE)?.inner(tag::SEQUENCE)?;
    let id = alg.expect(tag::OID)?;
    let key = der::bit_string_bytes(&s.expect(tag::BIT_STRING)?)?;
    s.finish()?;
    match id.value {
        oid::EC_PUBLIC_KEY => {
            let curve = alg.expect(tag::OID)?;
            alg.finish()?;
            match (curve.value, key.first(), key.len()) {
                (oid::P256, Some(4), 65) => Ok(Key::P256(key.to_vec())),
                (oid::P384, Some(4), 97) => Ok(Key::P384(key.to_vec())),
                _ => Ok(Key::Other),
            }
        }
        oid::RSA => {
            if !alg.is_empty() {
                der::null(&alg.read()?)?;
            }
            alg.finish()?;
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            let mut k = der::one(key)?.inner(tag::SEQUENCE)?;
            der::uint_bytes(&k.expect(tag::INTEGER)?)?;
            der::uint_bytes(&k.expect(tag::INTEGER)?)?;
            k.finish()?;
            Ok(Key::Rsa(key.to_vec()))
        }
        _ => Ok(Key::Other),
    }
}

fn basic_constraints(v: &[u8]) -> R<Option<Option<u64>>> {
    let mut s = der::one(v)?.inner(tag::SEQUENCE)?;
    let mut ca = false;
    let mut path = None;
    if !s.is_empty() && s.peek()?.is(tag::BOOLEAN) {
        ca = der::boolean(&s.read()?)?;
    }
    if !s.is_empty() {
        path = Some(der::uint(&s.expect(tag::INTEGER)?)?);
    }
    s.finish()?;
    if !ca && path.is_some() {
        return Err(Bad);
    }
    Ok(ca.then_some(path))
}

fn key_usage(v: &[u8]) -> R<u16> {
    let t = der::one(v)?;
    let b = t.prim(tag::BIT_STRING)?;
    match b {
        [unused, rest @ ..] if *unused < 8 && !rest.is_empty() && rest.len() <= 2 => {
            let mut bits = 0u16;
            for (i, byte) in rest.iter().enumerate() {
                for j in 0..8 {
                    if byte & (0x80 >> j) != 0 {
                        bits |= 1 << (i * 8 + j);
                    }
                }
            }
            Ok(bits)
        }
        _ => Err(Bad),
    }
}

/// keyUsage keyCertSign.
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;

/// Verify `signature` over `msg` by `key` under `alg` (an X.509 signature algorithm OID).
#[must_use]
pub fn verify(key: &Key, alg: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let (algorithm, k): (&'static dyn sig::VerificationAlgorithm, &[u8]) = match (key, alg) {
        (Key::P256(k), oid::ECDSA_SHA256) => (&sig::ECDSA_P256_SHA256_ASN1, k),
        (Key::P256(k), oid::ECDSA_SHA384) => (&sig::ECDSA_P256_SHA384_ASN1, k),
        (Key::P256(k), oid::ECDSA_SHA512) => (&sig::ECDSA_P256_SHA512_ASN1, k),
        (Key::P384(k), oid::ECDSA_SHA256) => (&sig::ECDSA_P384_SHA256_ASN1, k),
        (Key::P384(k), oid::ECDSA_SHA384) => (&sig::ECDSA_P384_SHA384_ASN1, k),
        (Key::P384(k), oid::ECDSA_SHA512) => (&sig::ECDSA_P384_SHA512_ASN1, k),
        (Key::Rsa(k), oid::RSA_SHA256) => (&sig::RSA_PKCS1_2048_8192_SHA256, k),
        (Key::Rsa(k), oid::RSA_SHA384) => (&sig::RSA_PKCS1_2048_8192_SHA384, k),
        (Key::Rsa(k), oid::RSA_SHA512) => (&sig::RSA_PKCS1_2048_8192_SHA512, k),
        _ => return false,
    };
    UnparsedPublicKey::new(algorithm, k)
        .verify(msg, signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_keys_match_googles_list() {
        assert_eq!(serial_key("00AB12"), "ab12");
        assert_eq!(serial_key("0"), "0");
        assert_eq!(serial_key("000"), "0");
    }

    #[test]
    fn key_usage_bits() {
        // keyCertSign | cRLSign: 03 02 01 06
        assert_eq!(key_usage(&[3, 2, 1, 6]).unwrap(), (1 << 5) | (1 << 6));
        // digitalSignature: 03 02 07 80
        assert_eq!(key_usage(&[3, 2, 7, 0x80]).unwrap(), 1);
        assert!(key_usage(&[3, 1, 0]).is_err());
    }
}
