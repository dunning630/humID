//! The opaque hardware inputs this adapter hands humid-core (CORE.md §3): stored by the core
//! next to the wrap or slot they protect, given back in `Derive` and `retire`.
//!
//! ```text
//! input = "HG" ‖ u8 3 ‖ u8 design ‖ fields
//!   ios      lp(id) ‖ lp(ML-KEM-1024 ciphertext) ‖ lp(P-256 ephemeral, X9.63)
//!   a, b, c  lp(alias) ‖ lp(message, 32)
//!   d        lp(alias) ‖ lp(message, 32)
//! ```
//!
//! `id` and `alias` name a hardware key in this namespace: `[a-z0-9]{1,40}`. The input
//! carries its design, so wraps made under one gate mode still open after the mode changes.

use crate::design::Design;
use crate::wire::{Malformed, R, W};

const MAGIC: &[u8; 2] = b"HG";
const VERSION: u8 = 3;

/// A decoded input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// iOS: the Secure Enclave key pair `id`, and the encapsulation and ephemeral to it.
    Ios {
        /// Keychain id of the Secure Enclave key blobs.
        id: String,
        /// ML-KEM-1024 ciphertext.
        ct: Vec<u8>,
        /// P-256 ephemeral public key (65 bytes, X9.63).
        eph: Vec<u8>,
    },
    /// Android A/B/C: the imported HMAC key `alias` and the message it MACs.
    Hmac {
        /// Which of A, B, C made it (C keys are time-bound).
        design: Design,
        /// Keystore alias in this namespace.
        alias: String,
        /// 32 random bytes.
        msg: Vec<u8>,
    },
    /// Android D: the ML-DSA-87 factor key and the message it signs.
    Factor {
        /// Keystore alias in this namespace.
        alias: String,
        /// 32 random bytes.
        msg: Vec<u8>,
    },
}

/// Whether `s` is a valid key name.
#[must_use]
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

impl Input {
    /// The design that made this input.
    #[must_use]
    pub fn design(&self) -> Design {
        match self {
            Input::Ios { .. } => Design::Ios,
            Input::Hmac { design, .. } => *design,
            Input::Factor { .. } => Design::D,
        }
    }

    /// The bytes the core stores.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        w.u8(MAGIC[0]).u8(MAGIC[1]).u8(VERSION).u8(self.design().wire());
        match self {
            Input::Ios { id, ct, eph } => {
                w.lp(id.as_bytes()).lp(ct).lp(eph);
            }
            Input::Hmac { alias, msg, .. } | Input::Factor { alias, msg } => {
                w.lp(alias.as_bytes()).lp(msg);
            }
        }
        w.bytes().to_vec()
    }

    /// Decode; anything that isn't a v3 input of a known design is refused.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, Malformed> {
        let mut r = R::new(b);
        if r.u8()? != MAGIC[0] || r.u8()? != MAGIC[1] || r.u8()? != VERSION {
            return Err(Malformed);
        }
        let design = Design::ALL
            .into_iter()
            .find(|d| d.wire() == r_peek(&mut r))
            .ok_or(Malformed)?;
        let name = |r: &mut R| -> Result<String, Malformed> {
            let s = std::str::from_utf8(r.lp()?).map_err(|_| Malformed)?;
            if valid_name(s) {
                Ok(s.to_owned())
            } else {
                Err(Malformed)
            }
        };
        let out = match design {
            Design::Ios => {
                let id = name(&mut r)?;
                let ct = r.lp()?.to_vec();
                let eph = r.lp()?.to_vec();
                if ct.len() != 1568 || eph.len() != 65 {
                    return Err(Malformed);
                }
                Input::Ios { id, ct, eph }
            }
            Design::A | Design::B | Design::C | Design::D => {
                let alias = name(&mut r)?;
                let msg = r.lp()?.to_vec();
                if msg.len() != 32 {
                    return Err(Malformed);
                }
                if design == Design::D {
                    Input::Factor { alias, msg }
                } else {
                    Input::Hmac { design, alias, msg }
                }
            }
        };
        r.done()?;
        Ok(out)
    }
}

/// Read the design byte (a helper so `decode` reads in order).
fn r_peek(r: &mut R) -> u8 {
    r.u8().unwrap_or(0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Input> {
        vec![
            Input::Ios {
                id: "k0123abcd".into(),
                ct: vec![7; 1568],
                eph: vec![4; 65],
            },
            Input::Hmac {
                design: Design::A,
                alias: "w9f".into(),
                msg: vec![1; 32],
            },
            Input::Hmac {
                design: Design::C,
                alias: "d1".into(),
                msg: vec![2; 32],
            },
            Input::Factor {
                alias: "factor".into(),
                msg: vec![3; 32],
            },
        ]
    }

    #[test]
    fn round_trip_and_design() {
        for i in samples() {
            let b = i.encode();
            assert_eq!(&b[..3], b"HG\x03");
            assert_eq!(Input::decode(&b).unwrap(), i);
        }
    }

    #[test]
    fn refuses_other_versions_names_lengths_and_trailing_bytes() {
        let good = samples()[1].encode();
        let mut v2 = good.clone();
        v2[2] = 2;
        assert!(Input::decode(&v2).is_err());
        let mut extra = good.clone();
        extra.push(0);
        assert!(Input::decode(&extra).is_err());
        assert!(Input::decode(&good[..good.len() - 1]).is_err());
        let bad_name = Input::Hmac {
            design: Design::A,
            alias: "../x".into(),
            msg: vec![0; 32],
        }
        .encode();
        assert!(Input::decode(&bad_name).is_err());
        let short = Input::Factor {
            alias: "f".into(),
            msg: vec![0; 31],
        }
        .encode();
        assert!(Input::decode(&short).is_err());
        // the software gate's inputs are not ours
        assert!(Input::decode(b"K0123456789abcdef").is_err());
        assert!(Input::decode(&[]).is_err());
    }

    #[test]
    fn names() {
        assert!(valid_name("abc019"));
        for bad in ["", "A", "a-b", "a.b", &"a".repeat(41)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
