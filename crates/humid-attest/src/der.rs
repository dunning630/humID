//! A strict DER reader: enough to walk X.509 certificates and Android's KeyDescription.
//!
//! Every length must be definite, minimally encoded and fit its parent; high tag numbers must
//! be minimally encoded; nothing recurses on its own (callers walk one level at a time), so
//! hostile nesting can't exhaust the stack. Any violation is [`Bad`].

/// Malformed DER (the caller maps it to `bad_attestation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bad;

/// `Result` for DER reads.
pub type R<T> = Result<T, Bad>;

/// Tag classes.
pub mod class {
    /// Universal.
    pub const UNIVERSAL: u8 = 0;
    /// Context-specific.
    pub const CONTEXT: u8 = 2;
}

/// Universal tag numbers used here.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u32 = 1;
    /// INTEGER.
    pub const INTEGER: u32 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u32 = 4;
    /// NULL.
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER.
    pub const OID: u32 = 6;
    /// ENUMERATED.
    pub const ENUMERATED: u32 = 10;
    /// SEQUENCE.
    pub const SEQUENCE: u32 = 16;
    /// SET.
    pub const SET: u32 = 17;
    /// UTCTime.
    pub const UTC_TIME: u32 = 23;
    /// GeneralizedTime.
    pub const GENERALIZED_TIME: u32 = 24;
}

/// One TLV.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    /// Class (0 universal, 1 application, 2 context, 3 private).
    pub class: u8,
    /// Constructed bit.
    pub constructed: bool,
    /// Tag number.
    pub tag: u32,
    /// The contents.
    pub value: &'a [u8],
    /// The whole TLV, header included.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// True for a universal tag `t`.
    #[must_use]
    pub fn is(&self, t: u32) -> bool {
        self.class == class::UNIVERSAL && self.tag == t
    }

    /// The contents of a universal constructed `t` (SEQUENCE, SET), as a reader.
    ///
    /// # Errors
    /// Another tag.
    pub fn inner(&self, t: u32) -> R<Reader<'a>> {
        if !self.is(t) || !self.constructed {
            return Err(Bad);
        }
        Ok(Reader::new(self.value))
    }

    /// A primitive universal `t`'s contents.
    ///
    /// # Errors
    /// Another tag, or constructed.
    pub fn prim(&self, t: u32) -> R<&'a [u8]> {
        if !self.is(t) || self.constructed {
            return Err(Bad);
        }
        Ok(self.value)
    }
}

/// Reads TLVs one after another from a buffer.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Nothing left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> R<u8> {
        let b = *self.buf.get(self.pos).ok_or(Bad)?;
        self.pos += 1;
        Ok(b)
    }

    /// The next TLV without consuming it.
    ///
    /// # Errors
    /// Malformed.
    pub fn peek(&self) -> R<Tlv<'a>> {
        self.clone().read()
    }

    /// The next TLV.
    ///
    /// # Errors
    /// Truncated, an indefinite or non-minimal length, a non-minimal high tag.
    pub fn read(&mut self) -> R<Tlv<'a>> {
        let start = self.pos;
        let b = self.byte()?;
        let class = b >> 6;
        let constructed = b & 0x20 != 0;
        let mut tag = u32::from(b & 0x1f);
        if tag == 0x1f {
            tag = 0;
            let mut n = 0;
            loop {
                let c = self.byte()?;
                if n == 0 && c == 0x80 {
                    return Err(Bad); // leading zero group
                }
                n += 1;
                if n > 4 {
                    return Err(Bad);
                }
                tag = (tag << 7) | u32::from(c & 0x7f);
                if c & 0x80 == 0 {
                    break;
                }
            }
            if tag < 0x1f {
                return Err(Bad); // must have used the short form
            }
        }
        let l = self.byte()?;
        let len = if l < 0x80 {
            usize::from(l)
        } else {
            let n = usize::from(l & 0x7f);
            if n == 0 || n > 4 {
                return Err(Bad); // indefinite (BER only), or absurd
            }
            let mut v: usize = 0;
            for i in 0..n {
                let c = self.byte()?;
                if i == 0 && c == 0 {
                    return Err(Bad); // leading zero byte
                }
                v = (v << 8) | usize::from(c);
            }
            if v < 0x80 {
                return Err(Bad); // must have used the short form
            }
            v
        };
        let end = self.pos.checked_add(len).ok_or(Bad)?;
        if end > self.buf.len() {
            return Err(Bad);
        }
        let value = &self.buf[self.pos..end];
        self.pos = end;
        Ok(Tlv {
            class,
            constructed,
            tag,
            value,
            raw: &self.buf[start..end],
        })
    }

    /// The next TLV, which must be universal `t`.
    ///
    /// # Errors
    /// Malformed or another tag.
    pub fn expect(&mut self, t: u32) -> R<Tlv<'a>> {
        let x = self.read()?;
        if !x.is(t) {
            return Err(Bad);
        }
        Ok(x)
    }

    /// The next TLV if it is context-specific `[n]`.
    ///
    /// # Errors
    /// Malformed.
    pub fn optional_context(&mut self, n: u32) -> R<Option<Tlv<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }
        let p = self.peek()?;
        if p.class == class::CONTEXT && p.tag == n {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Everything must have been read.
    ///
    /// # Errors
    /// Trailing bytes.
    pub fn finish(&self) -> R<()> {
        if self.is_empty() { Ok(()) } else { Err(Bad) }
    }
}

/// Parse exactly one TLV covering all of `buf`.
///
/// # Errors
/// Malformed or trailing bytes.
pub fn one(buf: &[u8]) -> R<Tlv<'_>> {
    let mut r = Reader::new(buf);
    let t = r.read()?;
    r.finish()?;
    Ok(t)
}

/// The magnitude bytes of a minimally encoded INTEGER (or ENUMERATED) that is non-negative.
///
/// # Errors
/// Not an integer, negative, empty or not minimal.
pub fn uint_bytes<'a>(t: &Tlv<'a>) -> R<&'a [u8]> {
    if t.constructed
        || t.class != class::UNIVERSAL
        || (t.tag != tag::INTEGER && t.tag != tag::ENUMERATED)
    {
        return Err(Bad);
    }
    let v = t.value;
    match v {
        [] => Err(Bad),
        [b, ..] if b & 0x80 != 0 => Err(Bad),
        [0, b, ..] if b & 0x80 == 0 => Err(Bad), // a needless leading zero
        [0, rest @ ..] => Ok(rest),
        _ => Ok(v),
    }
}

/// A non-negative INTEGER or ENUMERATED that fits in 64 bits.
///
/// # Errors
/// Malformed, negative, or too large.
pub fn uint(t: &Tlv<'_>) -> R<u64> {
    let m = uint_bytes(t)?;
    if m.len() > 8 {
        return Err(Bad);
    }
    Ok(m.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

/// A DER BOOLEAN (`0x00` or `0xff` only).
///
/// # Errors
/// Anything else.
pub fn boolean(t: &Tlv<'_>) -> R<bool> {
    match t.prim(tag::BOOLEAN)? {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Bad),
    }
}

/// A BIT STRING with no unused bits, as bytes.
///
/// # Errors
/// Malformed or unused bits.
pub fn bit_string_bytes<'a>(t: &Tlv<'a>) -> R<&'a [u8]> {
    match t.prim(tag::BIT_STRING)? {
        [0, rest @ ..] => Ok(rest),
        _ => Err(Bad),
    }
}

/// An empty NULL.
///
/// # Errors
/// Anything else.
pub fn null(t: &Tlv<'_>) -> R<()> {
    if t.prim(tag::NULL)?.is_empty() {
        Ok(())
    } else {
        Err(Bad)
    }
}

/// Unix milliseconds of a UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
///
/// # Errors
/// Any other form (fractions, offsets, missing seconds) or an invalid date.
pub fn time(t: &Tlv<'_>) -> R<i64> {
    let (year, rest) = if t.is(tag::UTC_TIME) && !t.constructed {
        let v = t.value;
        if v.len() != 13 {
            return Err(Bad);
        }
        let yy = digits(&v[0..2])?;
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, &v[2..])
    } else if t.is(tag::GENERALIZED_TIME) && !t.constructed {
        let v = t.value;
        if v.len() != 15 {
            return Err(Bad);
        }
        (digits(&v[0..4])?, &v[4..])
    } else {
        return Err(Bad);
    };
    if rest.last() != Some(&b'Z') {
        return Err(Bad);
    }
    let mo = digits(&rest[0..2])?;
    let d = digits(&rest[2..4])?;
    let h = digits(&rest[4..6])?;
    let mi = digits(&rest[6..8])?;
    let s = digits(&rest[8..10])?;
    if !(1..=12).contains(&mo) || d == 0 || d > days_in(year, mo) || h > 23 || mi > 59 || s > 59 {
        return Err(Bad);
    }
    let days = days_from_civil(year, mo, d);
    Ok((((days * 24 + h) * 60 + mi) * 60 + s) * 1000)
}

fn digits(b: &[u8]) -> R<i64> {
    let mut v = 0i64;
    for c in b {
        if !c.is_ascii_digit() {
            return Err(Bad);
        }
        v = v * 10 + i64::from(c - b'0');
    }
    Ok(v)
}

fn days_in(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
#[must_use]
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_must_be_minimal_and_definite() {
        assert!(one(&[0x04, 0x01, 0xaa]).is_ok());
        assert_eq!(
            one(&[0x04, 0x81, 0x01, 0xaa]).unwrap_err(),
            Bad,
            "long form for 1"
        );
        assert_eq!(
            one(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
            Bad,
            "indefinite"
        );
        assert_eq!(
            one(&[0x04, 0x82, 0x00, 0x80]).unwrap_err(),
            Bad,
            "leading zero"
        );
        assert_eq!(one(&[0x04, 0x02, 0xaa]).unwrap_err(), Bad, "past the end");
        assert_eq!(one(&[0x04, 0x01, 0xaa, 0x00]).unwrap_err(), Bad, "trailing");
        assert_eq!(
            one(&[0x04, 0x85, 1, 1, 1, 1, 1]).unwrap_err(),
            Bad,
            "5 length bytes"
        );
    }

    #[test]
    fn high_tags() {
        // [709] constructed context: bf 85 45
        let t = one(&[0xbf, 0x85, 0x45, 0x00]).unwrap();
        assert_eq!((t.class, t.tag, t.constructed), (2, 709, true));
        assert!(
            one(&[0xbf, 0x80, 0x85, 0x45, 0x00]).is_err(),
            "leading 0x80 group"
        );
        assert!(
            one(&[0xbf, 0x1e, 0x00]).is_err(),
            "30 must use the short form"
        );
        assert!(one(&[0xbf, 0x85]).is_err(), "truncated tag");
    }

    #[test]
    fn integers_and_booleans() {
        let i = |b: &[u8]| uint(&one(b).unwrap());
        assert_eq!(i(&[2, 1, 0]).unwrap(), 0);
        assert_eq!(i(&[2, 2, 0, 0x80]).unwrap(), 128);
        assert!(i(&[2, 2, 0, 0x7f]).is_err(), "not minimal");
        assert!(i(&[2, 1, 0x80]).is_err(), "negative");
        assert!(i(&[2, 0]).is_err(), "empty");
        assert!(i(&[2, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8]).is_err(), "too large");
        assert!(boolean(&one(&[1, 1, 0xff]).unwrap()).unwrap());
        assert!(!boolean(&one(&[1, 1, 0x00]).unwrap()).unwrap());
        assert!(
            boolean(&one(&[1, 1, 0x01]).unwrap()).is_err(),
            "DER: 0x00 or 0xff only"
        );
    }

    #[test]
    fn times() {
        let t = |b: &[u8], tag: u8| {
            let mut v = vec![tag, u8::try_from(b.len()).unwrap()];
            v.extend_from_slice(b);
            time(&one(&v).unwrap())
        };
        assert_eq!(t(b"700101000000Z", 23).unwrap(), 0);
        assert_eq!(t(b"20270101000000Z", 24).unwrap(), 1_798_761_600_000);
        assert_eq!(
            t(b"490101000000Z", 23).unwrap(),
            t(b"20490101000000Z", 24).unwrap()
        );
        assert!(t(b"700101000000+0100", 23).is_err());
        assert!(t(b"20270230000000Z", 24).is_err(), "30 February");
        assert!(t(b"20270101000000.5Z", 24).is_err());
    }
}
