//! JSON helpers for the internal APIs: bytes as unpadded base64url, ids as lower-case hex.
//! (HTP/2 will carry binary fields; until it lands, everything internal is JSON.)

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// Bytes that serialise as unpadded base64url.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl B64 {
    /// Encode to text.
    #[must_use]
    pub fn encode(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }
    /// Decode text.
    ///
    /// # Errors
    /// Not base64url.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| Error::bad("bad_base64", "Expected unpadded base64url."))
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        B64(v)
    }
}

impl std::ops::Deref for B64 {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

/// A 32-byte id (account, device, object…) as 64 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(pub [u8; 32]);

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // short form only: ids are not secrets, but logs keep them short
        write!(f, "Id({}…)", &hex::encode(self.0)[..8])
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Id {
    /// Parse 64 lower-case hex characters.
    ///
    /// # Errors
    /// Anything else.
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::bad(
                "bad_id",
                "An id is 64 lower-case hex characters.",
            ));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| Error::bad("bad_id", "Bad id."))?;
        Ok(Id(out))
    }
    /// From a database column.
    ///
    /// # Errors
    /// The column isn't 32 bytes (a bug).
    pub fn from_slice(b: &[u8]) -> Result<Self> {
        <[u8; 32]>::try_from(b)
            .map(Id)
            .map_err(|_| Error::internal("id column is not 32 bytes"))
    }
    /// A fresh random id.
    ///
    /// # Errors
    /// The generator failed.
    pub fn random() -> Result<Self> {
        Ok(Id(crate::crypto::random::<32>()?))
    }
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Id::parse(&s).map_err(|e| serde::de::Error::custom(e.message()))
    }
}

/// Parse a JSON body into `T`, refusing unknown fields where `T` says so.
///
/// # Errors
/// Malformed JSON.
pub fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(Error::from)
}

/// Split an `lp(a, b, …)` encoding of exactly `n` parts.
///
/// # Errors
/// Wrong part count, truncation or trailing bytes.
pub fn unlp(mut b: &[u8], n: usize) -> Result<Vec<&[u8]>> {
    let bad = || Error::bad("bad_encoding", "Malformed length-prefixed data.");
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if b.len() < 4 {
            return Err(bad());
        }
        let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        b = &b[4..];
        if b.len() < len {
            return Err(bad());
        }
        out.push(&b[..len]);
        b = &b[len..];
    }
    if !b.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

/// Crockford base32 (no padding), for codes people may read out or type.
#[must_use]
pub fn base32(bytes: &[u8], chars: usize) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::with_capacity(chars);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < chars {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// True when `s` is `n` Crockford base32 characters.
#[must_use]
pub fn is_code(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip() {
        let v: B64 = serde_json::from_str("\"AQID\"").unwrap();
        assert_eq!(v.0, vec![1, 2, 3]);
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"AQID\"");
        assert!(
            serde_json::from_str::<B64>("\"AQID==\"").is_err(),
            "padding is refused"
        );
    }

    #[test]
    fn ids_are_strict() {
        let s = "ab".repeat(32);
        assert_eq!(Id::parse(&s).unwrap().to_string(), s);
        assert!(
            Id::parse(&"AB".repeat(32)).is_err(),
            "upper case refused (one spelling)"
        );
        assert!(Id::parse("abcd").is_err());
    }

    #[test]
    fn codes() {
        let c = base32(&[0xff; 8], 12);
        assert_eq!(c.len(), 12);
        assert!(is_code(&c, 12));
        assert!(
            !is_code("O0000000000I", 12),
            "ambiguous letters are not in the alphabet"
        );
    }
}
