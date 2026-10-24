//! Server KEM certificates and the key bundle (HTP2.md §2).
//!
//! ```text
//! cert    = header(0x0300) ‖ u8 unit ‖ u64 not_before ‖ u64 not_after ‖ kem_pk (1613) ‖ sig (4640)
//! sig     = ML-DSA-87(unit statement key, "HUMID-PQ2 htp2-kem-cert", every byte before sig)
//! kid     = key_id(kem_pk)
//! bundle  = header(0x0301) ‖ lp(policy.json) ‖ lp(policy.json.sig) ‖ u8 n ‖ lp(cert)×n
//! ```
//!
//! Trust runs: the identity root the app pins → the policy (dual signature over the exact file
//! bytes) → the unit's statement key named in the policy → this certificate → the KEM key the
//! hello encapsulates to.

use humid_pq2::encoding::{Reader, header};
use humid_pq2::{
    DualSignature, DualVerifyingKey, KEM_PUBLIC_KEY_LEN, KemPublicKey, MLDSA_SIG_LEN,
    MlDsaSignature, MlDsaVerifyingKey,
};

use crate::{Code, Result, Unit, label, types};

/// Encoded certificate bytes.
pub const CERT_LEN: usize = 13 + 1 + 8 + 8 + KEM_PUBLIC_KEY_LEN + 13 + MLDSA_SIG_LEN;
/// Longest a certificate may be valid.
pub const MAX_VALIDITY_MS: u64 = 3 * 24 * 3_600_000;
/// Largest policy file in a bundle.
pub const MAX_POLICY: usize = 256 << 10;
/// Largest policy signature (a dual signature is 34,432 bytes).
pub const MAX_POLICY_SIG: usize = 40_000;
/// Clock slack the client allows on a certificate's dates.
pub const CERT_SKEW_MS: u64 = 10 * 60_000;

/// A unit's KEM certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    /// The unit whose sessions it terminates.
    pub unit: Unit,
    /// Valid from (ms).
    pub not_before: u64,
    /// Valid until (ms).
    pub not_after: u64,
    /// The hybrid KEM public key.
    pub kem_pk: KemPublicKey,
    sig: Vec<u8>,
}

impl Cert {
    /// The bytes the statement key signs.
    #[must_use]
    pub fn to_be_signed(
        unit: Unit,
        not_before: u64,
        not_after: u64,
        kem_pk: &KemPublicKey,
    ) -> Vec<u8> {
        [
            &header(types::KEM_CERT)[..],
            &[unit.to_u8()],
            &not_before.to_be_bytes(),
            &not_after.to_be_bytes(),
            kem_pk.to_bytes(),
        ]
        .concat()
    }

    /// Assemble a certificate from its signed bytes and the signature encoding.
    ///
    /// # Errors
    /// `bad_cert` for a malformed signature.
    pub fn assemble(
        unit: Unit,
        not_before: u64,
        not_after: u64,
        kem_pk: &KemPublicKey,
        sig: &[u8],
    ) -> Result<Vec<u8>> {
        MlDsaSignature::from_bytes(sig).map_err(|_| Code::BadCert)?;
        Ok([
            Self::to_be_signed(unit, not_before, not_after, kem_pk),
            sig.to_vec(),
        ]
        .concat())
    }

    /// Parse (doesn't verify).
    ///
    /// # Errors
    /// `bad_cert`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let e = |_| Code::BadCert;
        let mut r = Reader::new(b);
        r.header(types::KEM_CERT).map_err(e)?;
        let unit = Unit::from_u8(r.array::<1>().map_err(e)?[0]).ok_or(Code::BadCert)?;
        let not_before = r.u64().map_err(e)?;
        let not_after = r.u64().map_err(e)?;
        let kem_pk = KemPublicKey::from_bytes(r.take(KEM_PUBLIC_KEY_LEN).map_err(e)?).map_err(e)?;
        let sig = r.take(13 + MLDSA_SIG_LEN).map_err(e)?.to_vec();
        r.finish().map_err(e)?;
        if not_after <= not_before || not_after - not_before > MAX_VALIDITY_MS {
            return Err(Code::BadCert);
        }
        Ok(Self {
            unit,
            not_before,
            not_after,
            kem_pk,
            sig,
        })
    }

    /// Check the statement key's signature and the dates against `now` (± [`CERT_SKEW_MS`]).
    ///
    /// # Errors
    /// `bad_cert`.
    pub fn verify(&self, statement_key: &MlDsaVerifyingKey, now: u64) -> Result<()> {
        let sig = MlDsaSignature::from_bytes(&self.sig).map_err(|_| Code::BadCert)?;
        let m = Self::to_be_signed(self.unit, self.not_before, self.not_after, &self.kem_pk);
        statement_key
            .verify(label::KEM_CERT, &m, &sig)
            .map_err(|_| Code::BadCert)?;
        if now + CERT_SKEW_MS < self.not_before || now > self.not_after + CERT_SKEW_MS {
            return Err(Code::BadCert);
        }
        Ok(())
    }

    /// The key id hellos name.
    #[must_use]
    pub fn kid(&self) -> [u8; 32] {
        self.kem_pk.key_id()
    }
}

/// The key bundle `GET /htp/v2/keys` serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The policy file, exactly as the identity root signed it.
    pub policy: Vec<u8>,
    /// Its dual signature.
    pub policy_sig: Vec<u8>,
    /// One certificate per unit (core, anon).
    pub certs: Vec<Vec<u8>>,
}

impl Bundle {
    /// Encode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut o = header(types::KEY_BUNDLE).to_vec();
        for p in [&self.policy, &self.policy_sig] {
            o.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
            o.extend_from_slice(p);
        }
        o.push(u8::try_from(self.certs.len()).unwrap_or(0));
        for c in &self.certs {
            o.extend_from_slice(&u32::try_from(c.len()).unwrap_or(u32::MAX).to_be_bytes());
            o.extend_from_slice(c);
        }
        o
    }

    /// Decode.
    ///
    /// # Errors
    /// `bad_cert`.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let e = |_| Code::BadCert;
        let mut r = Reader::new(b);
        r.header(types::KEY_BUNDLE).map_err(e)?;
        let policy = r.lp(MAX_POLICY).map_err(e)?.to_vec();
        let policy_sig = r.lp(MAX_POLICY_SIG).map_err(e)?.to_vec();
        let n = r.array::<1>().map_err(e)?[0];
        if n == 0 || n > 4 {
            return Err(Code::BadCert);
        }
        let certs = (0..n)
            .map(|_| r.lp(CERT_LEN).map(<[u8]>::to_vec).map_err(e))
            .collect::<Result<Vec<_>>>()?;
        r.finish().map_err(e)?;
        Ok(Self {
            policy,
            policy_sig,
            certs,
        })
    }

    /// Check the policy's signature under the pinned identity root; returns the policy bytes.
    ///
    /// # Errors
    /// `bad_cert`.
    pub fn verify_policy(&self, root: &DualVerifyingKey) -> Result<&[u8]> {
        let sig = DualSignature::from_bytes(&self.policy_sig).map_err(|_| Code::BadCert)?;
        let m = humid_pq2::encoding::lp(&[&self.policy]).map_err(|_| Code::BadCert)?;
        root.verify(label::POLICY, &m, &sig)
            .map_err(|_| Code::BadCert)?;
        Ok(&self.policy)
    }

    /// The verified certificate for `unit`: policy under `root`, then the certificate under
    /// the statement key `statement_key(policy, unit)` names, then its dates.
    ///
    /// # Errors
    /// `bad_cert`.
    pub fn verified(
        &self,
        root: &DualVerifyingKey,
        unit: Unit,
        now: u64,
        statement_key: impl Fn(&[u8], Unit) -> Option<Vec<u8>>,
    ) -> Result<Cert> {
        let policy = self.verify_policy(root)?;
        let vk = statement_key(policy, unit).ok_or(Code::BadCert)?;
        let vk = MlDsaVerifyingKey::from_bytes(&vk).map_err(|_| Code::BadCert)?;
        for c in &self.certs {
            let c = Cert::decode(c)?;
            if c.unit == unit {
                c.verify(&vk, now)?;
                return Ok(c);
            }
        }
        Err(Code::BadCert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use humid_pq2::{DualSigningKey, KemSecretKey, MlDsaSigningKey};

    #[test]
    fn chain_verifies_and_every_break_is_refused() {
        let root = DualSigningKey::generate().unwrap();
        let st = MlDsaSigningKey::generate().unwrap();
        let kem = KemSecretKey::generate().unwrap();
        let policy = b"{\"core\":1}".to_vec();
        let psig = root
            .sign(label::POLICY, &humid_pq2::encoding::lp(&[&policy]).unwrap())
            .unwrap()
            .to_bytes();
        let tbs = Cert::to_be_signed(Unit::Core, 1000, 2000, kem.public_key());
        let sig = st.sign(label::KEM_CERT, &tbs).unwrap().to_bytes();
        let cert = Cert::assemble(Unit::Core, 1000, 2000, kem.public_key(), &sig).unwrap();
        assert_eq!(cert.len(), CERT_LEN);
        let vk = st.verifying_key().to_bytes();
        let b = Bundle {
            policy,
            policy_sig: psig,
            certs: vec![cert.clone()],
        };
        let enc = b.encode();
        let b2 = Bundle::decode(&enc).unwrap();
        assert_eq!(b2, b);
        let key = |_: &[u8], u: Unit| (u == Unit::Core).then(|| vk.clone());
        let c = b2
            .verified(root.verifying_key(), Unit::Core, 1500, key)
            .unwrap();
        assert_eq!(c.kid(), kem.public_key().key_id());
        // another unit, expired, a forged policy, another root, a flipped certificate byte
        assert!(
            b2.verified(root.verifying_key(), Unit::Anon, 1500, key)
                .is_err()
        );
        assert!(
            b2.verified(
                root.verifying_key(),
                Unit::Core,
                2000 + CERT_SKEW_MS + 1,
                key
            )
            .is_err()
        );
        let mut forged = b2.clone();
        forged.policy[2] ^= 1;
        assert!(
            forged
                .verified(root.verifying_key(), Unit::Core, 1500, key)
                .is_err()
        );
        let other = DualSigningKey::generate().unwrap();
        assert!(
            b2.verified(other.verifying_key(), Unit::Core, 1500, key)
                .is_err()
        );
        for i in [14, 20, 40, 2000, CERT_LEN - 5] {
            let mut bad = b2.clone();
            bad.certs[0][i] ^= 1;
            assert!(
                bad.verified(root.verifying_key(), Unit::Core, 1500, key)
                    .is_err(),
                "byte {i}"
            );
        }
        assert!(Bundle::decode(&enc[..enc.len() - 1]).is_err());
        assert!(Cert::decode(&cert[1..]).is_err());
    }
}
