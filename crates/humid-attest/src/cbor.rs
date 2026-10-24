//! A strict CBOR reader for App Attest objects (RFC 8949, the subset Apple emits).
//!
//! Definite lengths only; unsigned and negative integers, byte and text strings, arrays, maps,
//! `false` / `true` / `null`. No tags, no floats, no indefinite lengths, map keys unique,
//! nesting at most [`MAX_DEPTH`], and a declared element count must fit the bytes left (so a
//! hostile header can't make it allocate). Any violation is [`Bad`].

use crate::der::Bad;

/// Deepest nesting accepted.
pub const MAX_DEPTH: usize = 8;

/// A decoded value, borrowing from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Neg(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3 (UTF-8 checked).
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Value<'a>>),
    /// Major type 5, in input order.
    Map(Vec<(Value<'a>, Value<'a>)>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl<'a> Value<'a> {
    /// The entry under text key `k` of a map.
    #[must_use]
    pub fn get(&self, k: &str) -> Option<&Value<'a>> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(key, _)| matches!(key, Value::Text(t) if *t == k))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The entry under integer key `k` of a map.
    #[must_use]
    pub fn get_int(&self, k: i64) -> Option<&Value<'a>> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(key, _)| key.as_int() == Some(k))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Bytes, if this is a byte string.
    #[must_use]
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// An integer that fits `i64`.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Uint(n) => i64::try_from(*n).ok(),
            Value::Neg(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The text keys of a map (`None` if any key isn't text).
    #[must_use]
    pub fn text_keys(&self) -> Option<Vec<&'a str>> {
        match self {
            Value::Map(m) => m
                .iter()
                .map(|(k, _)| match k {
                    Value::Text(t) => Some(*t),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }
}

/// Decode exactly one item covering all of `buf`.
///
/// # Errors
/// Malformed, unsupported, or trailing bytes.
pub fn decode(buf: &[u8]) -> Result<Value<'_>, Bad> {
    let mut d = Dec { buf, pos: 0 };
    let v = d.item(0)?;
    if d.pos != buf.len() {
        return Err(Bad);
    }
    Ok(v)
}

/// Decode one item at the start of `buf`; returns it and the bytes it used.
///
/// # Errors
/// Malformed or unsupported.
pub fn decode_prefix(buf: &[u8]) -> Result<(Value<'_>, usize), Bad> {
    let mut d = Dec { buf, pos: 0 };
    let v = d.item(0)?;
    Ok((v, d.pos))
}

struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Bad> {
        let end = self.pos.checked_add(n).ok_or(Bad)?;
        let s = self.buf.get(self.pos..end).ok_or(Bad)?;
        self.pos = end;
        Ok(s)
    }

    fn arg(&mut self, ai: u8) -> Result<u64, Bad> {
        Ok(match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| Bad)?,
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| Bad)?,
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Bad)?),
            _ => return Err(Bad), // 28–30 reserved, 31 indefinite
        })
    }

    fn left(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn count(&mut self, ai: u8, per_item: usize) -> Result<usize, Bad> {
        let n = usize::try_from(self.arg(ai)?).map_err(|_| Bad)?;
        // every element takes at least one byte (two for a map entry)
        if n.checked_mul(per_item)
            .is_none_or(|need| need > self.left())
        {
            return Err(Bad);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, Bad> {
        if depth > MAX_DEPTH {
            return Err(Bad);
        }
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        match major {
            0 => Ok(Value::Uint(self.arg(ai)?)),
            1 => Ok(Value::Neg(self.arg(ai)?)),
            2 => {
                let n = self.count(ai, 1)?;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.count(ai, 1)?;
                std::str::from_utf8(self.take(n)?)
                    .map(Value::Text)
                    .map_err(|_| Bad)
            }
            4 => {
                let n = self.count(ai, 1)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(v))
            }
            5 => {
                let n = self.count(ai, 2)?;
                let mut m: Vec<(Value<'a>, Value<'a>)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    if !matches!(k, Value::Uint(_) | Value::Neg(_) | Value::Text(_)) {
                        return Err(Bad);
                    }
                    if m.iter().any(|(q, _)| *q == k) {
                        return Err(Bad); // duplicate key
                    }
                    let v = self.item(depth + 1)?;
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Bad),
            },
            _ => Err(Bad), // 6: tags are not used by App Attest
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_refuses() {
        // {"a": h'01', 1: -7}
        let v = decode(&[0xa2, 0x61, b'a', 0x41, 0x01, 0x01, 0x26]).unwrap();
        assert_eq!(v.get("a").and_then(Value::bytes), Some(&[1u8][..]));
        assert_eq!(v.get_int(1).and_then(Value::as_int), Some(-7));
        assert!(decode(&[0x9f, 0xff]).is_err(), "indefinite");
        assert!(
            decode(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err(),
            "duplicate key"
        );
        assert!(
            decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err(),
            "count past the end"
        );
        assert!(decode(&[0xc0, 0x01]).is_err(), "tag");
        assert!(decode(&[0xf9, 0, 0]).is_err(), "float");
        assert!(decode(&[0x01, 0x01]).is_err(), "trailing");
        assert!(decode(&[0x62, 0xff, 0xfe]).is_err(), "bad utf-8");
        let deep: Vec<u8> = std::iter::repeat_n(0x81, 20).chain([0x00]).collect();
        assert!(decode(&deep).is_err(), "too deep");
        assert!(decode(&[0xa1, 0x80, 0x00]).is_err(), "array as a key");
    }
}
