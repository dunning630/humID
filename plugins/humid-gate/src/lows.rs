//! ECDSA P-256 signatures in low-S form (servers accept only low-S; the secure chips may
//! return either). DER in, DER out; anything that isn't a plain P-256 DER signature is
//! returned unchanged (the server refuses it then).

/// The P-256 group order n, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// n / 2, big-endian.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// A DER INTEGER's value as 32 big-endian bytes, and the rest of the input.
fn integer(b: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = usize::from(len);
    if tag != 0x02 || len == 0 || len > 33 || rest.len() < len {
        return None;
    }
    let (v, rest) = rest.split_at(len);
    let v = if len == 33 {
        if v[0] != 0 {
            return None;
        }
        &v[1..]
    } else {
        v
    };
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Some((out, rest))
}

fn der_integer(v: &[u8; 32], out: &mut Vec<u8>) {
    let start = v.iter().position(|&b| b != 0).unwrap_or(31);
    let body = &v[start..];
    let pad = body[0] & 0x80 != 0;
    out.push(0x02);
    // at most 33 bytes: always fits in one length byte
    out.push(u8::try_from(body.len() + usize::from(pad)).unwrap_or(33));
    if pad {
        out.push(0);
    }
    out.extend_from_slice(body);
}

/// `a > b`, big-endian, same length.
fn gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a > b
}

/// `n - s`.
fn neg(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(N[i]) - i16::from(s[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = u8::try_from(d).unwrap_or(0);
    }
    out
}

/// The low-S form of a DER ECDSA P-256 signature.
#[must_use]
pub fn low_s(der: &[u8]) -> Vec<u8> {
    let parse = || -> Option<([u8; 32], [u8; 32])> {
        let (&tag, rest) = der.split_first()?;
        let (&len, rest) = rest.split_first()?;
        if tag != 0x30 || usize::from(len) != rest.len() {
            return None;
        }
        let (r, rest) = integer(rest)?;
        let (s, rest) = integer(rest)?;
        rest.is_empty().then_some((r, s))
    };
    let Some((r, s)) = parse() else {
        return der.to_vec();
    };
    if !gt(&s, &HALF_N) {
        return der.to_vec();
    }
    let s = neg(&s);
    let mut body = Vec::with_capacity(70);
    der_integer(&r, &mut body);
    der_integer(&s, &mut body);
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap_or(0)];
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        der_integer(r, &mut body);
        der_integer(s, &mut body);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn high_s_becomes_n_minus_s_and_low_s_is_unchanged() {
        let r = [0x11u8; 32];
        let mut high = N;
        high[31] -= 5; // n - 5
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(low_s(&sig(&r, &high)), sig(&r, &five));
        let low = sig(&r, &five);
        assert_eq!(low_s(&low), low);
        // exactly n/2 is already low
        assert_eq!(low_s(&sig(&r, &HALF_N)), sig(&r, &HALF_N));
        // n/2 + 1 is high: n - (n/2 + 1) = n/2 (n is odd)
        let mut h1 = HALF_N;
        h1[31] += 1;
        assert_eq!(low_s(&sig(&r, &h1)), sig(&r, &HALF_N));
    }

    #[test]
    fn leading_zero_rules_hold() {
        // r with its top bit set needs a 0x00 pad; a small s has no leading zeros
        let r = [0x80u8; 32];
        let mut s = [0u8; 32];
        s[31] = 1;
        let d = sig(&r, &s);
        assert_eq!(&d[2..5], &[0x02, 33, 0x00]);
        assert_eq!(&d[d.len() - 3..], &[0x02, 1, 1]);
        assert_eq!(integer(&d[2..]).unwrap().0, r);
    }

    #[test]
    fn junk_passes_through() {
        for j in [&[][..], &[0x30, 0][..], &[0x31, 2, 2, 0][..], &[1, 2, 3][..]] {
            assert_eq!(low_s(j), j.to_vec());
        }
    }
}
