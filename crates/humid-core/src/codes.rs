//! Comparison codes a person reads on one screen and types on another (CORE.md §5.3).
//!
//! ```text
//! code = Crockford-base32(first 100 bits of H(label, [bytes…]))     20 characters, shown XXXX-XXXX-…
//! ```
//!
//! 100 bits, so a relay can't grind a substitute key whose code matches. Typed input is
//! normalised (case, spaces and dashes ignored; `I`/`L` → `1`, `O` → `0`) and compared in
//! constant time.

use humid_pq2::{ct_eq, labelled_hash};

use crate::error::Result;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a code.
pub const CODE_LEN: usize = 20;

/// The code of `parts` under `label`, grouped `XXXX-XXXX-XXXX-XXXX-XXXX`.
pub(crate) fn code(label: &str, parts: &[&[u8]]) -> Result<String> {
    let h = labelled_hash(label, parts)?;
    let mut acc: u128 = 0;
    for &b in &h[..13] {
        acc = (acc << 8) | u128::from(b);
    }
    // 104 bits read; keep the top 100.
    acc >>= 4;
    let mut out = String::with_capacity(CODE_LEN + 4);
    for i in (0..CODE_LEN).rev() {
        let c = ALPHABET[((acc >> (5 * i)) & 31) as usize] as char;
        out.push(c);
        if i % 4 == 0 && i != 0 {
            out.push('-');
        }
    }
    Ok(out)
}

/// The canonical characters of a typed code: `None` if it isn't one.
fn normalise(typed: &str) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(CODE_LEN);
    for c in typed.chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        v.push(c as u8);
    }
    (v.len() == CODE_LEN).then_some(v)
}

/// Whether `typed` is `expected`, in constant time over the characters.
pub(crate) fn matches(typed: &str, expected: &str) -> bool {
    match (normalise(typed), normalise(expected)) {
        (Some(a), Some(b)) => ct_eq(&a, &b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_grouped_and_forgiving() {
        let c = code("HUMID-PQ2 join-code", &[b"x"]).unwrap();
        assert_eq!(c.len(), CODE_LEN + 4);
        assert_eq!(c.matches('-').count(), 4);
        assert_eq!(c, code("HUMID-PQ2 join-code", &[b"x"]).unwrap());
        assert_ne!(c, code("HUMID-PQ2 join-code", &[b"y"]).unwrap());
        assert!(matches(&c.to_lowercase().replace('-', " "), &c));
        let flipped: String = c.replace('0', "O");
        assert!(matches(&flipped, &c));
        assert!(!matches(&c[..c.len() - 1], &c));
        assert!(!matches("", &c));
        assert!(!matches("ü", &c));
        let mut wrong = c.clone().into_bytes();
        wrong[0] = if wrong[0] == b'Z' { b'Y' } else { b'Z' };
        assert!(!matches(std::str::from_utf8(&wrong).unwrap(), &c));
    }
}
