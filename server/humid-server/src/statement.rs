//! Statements from one unit to another (SERVER.md §2.4).
//!
//! `statement = lp(body, sig)`, `sig = ML-DSA-87.sign("HUMID-PQ2 unit-statement", body)` with
//! the sending unit's statement key in its HSM. The body is JSON `{kind, exp, facts}`; the
//! verifier checks the exact signed bytes before it parses anything, then the kind and the
//! expiry. A statement says only what the signer checked; the receiver still checks the
//! holder's own proof wherever the holder could have signed (keys does, for every share).

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crypto::{self, MlDsaPublic, label};
use crate::error::{Error, Result};
use crate::hsm::{Hsm, KeyRef};
use crate::wire::{B64, unlp};

/// How long a statement is good for.
pub const MAX_AGE_MS: i64 = 120_000;

#[derive(Serialize, serde::Deserialize)]
struct Body<T> {
    kind: String,
    exp: i64,
    facts: T,
}

/// Sign `facts` as a statement of `kind`, valid until `now + MAX_AGE_MS`.
///
/// # Errors
/// HSM failure.
pub fn sign<T: Serialize>(
    hsm: &dyn Hsm,
    key: KeyRef,
    kind: &str,
    now: i64,
    facts: &T,
) -> Result<B64> {
    let body = serde_json::to_vec(&Body {
        kind: kind.to_string(),
        exp: now + MAX_AGE_MS,
        facts,
    })
    .map_err(|e| Error::internal(e.to_string()))?;
    let sig = hsm.mldsa_sign(key, label::UNIT_STATEMENT, &body)?;
    Ok(B64(crypto::lp(&[&body, &sig])?))
}

/// Verify a statement of `kind` from the unit whose key is `pk`, and return its facts.
///
/// # Errors
/// `not_vouched`: a bad signature, another kind, expired, or malformed.
pub fn verify<T: DeserializeOwned>(
    pk: &MlDsaPublic,
    statement: &[u8],
    kind: &str,
    now: i64,
) -> Result<T> {
    let refuse = || {
        Error::forbidden(
            "not_vouched",
            "That isn't a valid statement from the unit it names.",
        )
    };
    let parts = unlp(statement, 2).map_err(|_| refuse())?;
    let (body, sig) = (parts[0], parts[1]);
    if !pk.verifies(label::UNIT_STATEMENT, body, sig) {
        return Err(refuse());
    }
    let b: Body<T> = serde_json::from_slice(body).map_err(|_| refuse())?;
    if b.kind != kind || b.exp < now || b.exp > now + MAX_AGE_MS + 5_000 {
        return Err(refuse());
    }
    Ok(b.facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::SoftHsm;

    #[derive(Serialize, serde::Deserialize, Debug, PartialEq)]
    struct F {
        a: u32,
    }

    #[test]
    fn statements() {
        let h = SoftHsm::ephemeral().unwrap();
        let pk = h.mldsa_public(KeyRef::CoreStatement).unwrap();
        let s = sign(&h, KeyRef::CoreStatement, "release", 1000, &F { a: 7 }).unwrap();
        assert_eq!(verify::<F>(&pk, &s, "release", 1000).unwrap(), F { a: 7 });
        assert!(
            verify::<F>(&pk, &s, "delete", 1000).is_err(),
            "kind is checked"
        );
        assert!(
            verify::<F>(&pk, &s, "release", 1000 + MAX_AGE_MS + 1).is_err(),
            "expiry is checked"
        );
        let other = h.mldsa_public(KeyRef::KeysStatement).unwrap();
        assert!(
            verify::<F>(&other, &s, "release", 1000).is_err(),
            "another unit's key doesn't verify it"
        );
        let mut t = s.0.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert!(verify::<F>(&pk, &t, "release", 1000).is_err());
    }
}
