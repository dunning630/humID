//! Adding a device (CORE.md §5.3): a self-signed join request, the comparison code that
//! binds it to the person's approval, and the per-join key the pending slots are sealed to.
//!
//! ```text
//! body     = header(0x0108) ‖ account_id (32) ‖ device ML-DSA-87 pk (2592) ‖ join KEM pk (1613) ‖ nonce (32)
//! request  = body ‖ ML-DSA-87(device key, ctx = SUITE ‖ u16 0x0108 ‖ "HUMID-PQ2 join-request", body)
//! code     = Crockford-base32(first 100 bits of H("HUMID-PQ2 join-code", [body]))
//! binding  = H("HUMID-PQ2 join-binding", [body])
//! ```
//!
//! The new device shows `code`; the person types it on the approving device, which refuses
//! unless the request's signature verifies, it names this account, and the typed code is the
//! request's. A relay that swaps the join KEM key must re-sign the body with a device key of
//! its own, which changes the code: it would need a second preimage of a 100-bit code. The
//! approving device's live proof names `binding`, so the server can tell which request the
//! person approved.

use humid_pq2::encoding::{HEADER_LEN, Reader, header};
use humid_pq2::{
    KEM_PUBLIC_KEY_LEN, KemPublicKey, KemSecretKey, MLDSA_SIG_LEN, MLDSA_VK_LEN, MlDsaSignature,
    MlDsaSigningKey, MlDsaVerifyingKey, ObjectType, labelled_hash,
};

use crate::codes::code;
use crate::error::{CoreError, Result};

/// Encoded join request bytes.
pub const JOIN_REQUEST_LEN: usize =
    HEADER_LEN + 32 + MLDSA_VK_LEN + KEM_PUBLIC_KEY_LEN + 32 + MLDSA_SIG_LEN;
const BODY_LEN: usize = JOIN_REQUEST_LEN - MLDSA_SIG_LEN;
/// Most documents one grant carries.
pub const MAX_GRANT_DOCS: usize = 1 << 20;

/// A joining device's request. Decoding verifies its signature, so a value of this type is
/// always self-consistent; whether it is the right device is what the code decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    /// The account the device asks to join.
    pub account_id: [u8; 32],
    /// The device's ML-DSA-87 key (its id is this key's id).
    pub device_dsa: MlDsaVerifyingKey,
    /// The one-time KEM key the account seed and pending slots are sealed to.
    pub join_kem: KemPublicKey,
    /// Fresh per request.
    pub nonce: [u8; 32],
    sig: MlDsaSignature,
}

fn body(
    account_id: &[u8; 32],
    dsa: &MlDsaVerifyingKey,
    kem: &KemPublicKey,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(BODY_LEN);
    v.extend_from_slice(&header(ObjectType::JOIN_REQUEST));
    v.extend_from_slice(account_id);
    v.extend_from_slice(dsa.raw());
    v.extend_from_slice(kem.to_bytes());
    v.extend_from_slice(nonce);
    v
}

impl JoinRequest {
    pub(crate) fn sign(
        account_id: [u8; 32],
        device: &MlDsaSigningKey,
        join_kem: &KemPublicKey,
    ) -> Result<Self> {
        let mut nonce = [0u8; 32];
        humid_pq2::random_bytes(&mut nonce)?;
        let b = body(&account_id, device.verifying_key(), join_kem, &nonce);
        let sig = device.sign_typed(ObjectType::JOIN_REQUEST, "HUMID-PQ2 join-request", &b)?;
        Ok(Self {
            account_id,
            device_dsa: device.verifying_key().clone(),
            join_kem: join_kem.clone(),
            nonce,
            sig,
        })
    }

    fn body(&self) -> Vec<u8> {
        body(
            &self.account_id,
            &self.device_dsa,
            &self.join_kem,
            &self.nonce,
        )
    }

    /// Encode (body ‖ signature).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.body();
        v.extend_from_slice(self.sig.raw());
        v
    }

    /// Decode and verify the device's signature.
    ///
    /// # Errors
    /// [`CoreError::Format`] for malformed bytes; [`CoreError::WrongSigner`] if the
    /// signature doesn't verify under the device key it names.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.header(ObjectType::JOIN_REQUEST)?;
        let account_id = r.array()?;
        let device_dsa = MlDsaVerifyingKey::from_bytes(&{
            let mut v = header(ObjectType::MLDSA_VERIFYING_KEY).to_vec();
            v.extend_from_slice(r.take(MLDSA_VK_LEN)?);
            v
        })?;
        let join_kem = KemPublicKey::from_bytes(r.take(KEM_PUBLIC_KEY_LEN)?)?;
        let nonce = r.array()?;
        let sig = MlDsaSignature::from_raw(r.take(MLDSA_SIG_LEN)?)?;
        r.finish()?;
        let req = Self {
            account_id,
            device_dsa,
            join_kem,
            nonce,
            sig,
        };
        req.device_dsa
            .verify_typed(
                ObjectType::JOIN_REQUEST,
                "HUMID-PQ2 join-request",
                &req.body(),
                &req.sig,
            )
            .map_err(|_| CoreError::WrongSigner)?;
        Ok(req)
    }

    /// The joining device's id.
    #[must_use]
    pub fn device_id(&self) -> [u8; 32] {
        self.device_dsa.key_id()
    }

    /// The code the new device shows and the person types on the approving device.
    ///
    /// # Errors
    /// Never in practice (fixed label).
    pub fn code(&self) -> Result<String> {
        code("HUMID-PQ2 join-code", &[&self.body()])
    }

    /// What the grant and the approving live proof are bound to.
    ///
    /// # Errors
    /// Never in practice (fixed label).
    pub fn binding(&self) -> Result<[u8; 64]> {
        Ok(labelled_hash("HUMID-PQ2 join-binding", &[&self.body()])?)
    }
}

/// The account seed and the list of granted documents, sealed to the join key:
/// `account seed (32) ‖ u32 n ‖ n × doc_id (32)`, AAD `[account_id, device_id, binding]`.
pub(crate) struct JoinGrantBody {
    pub account_seed: humid_pq2::Secret32,
    pub doc_ids: Vec<[u8; 32]>,
}

impl JoinGrantBody {
    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let n = u32::try_from(self.doc_ids.len()).map_err(|_| CoreError::Format)?;
        let mut v = zeroize::Zeroizing::new(Vec::with_capacity(36 + 32 * self.doc_ids.len()));
        v.extend_from_slice(self.account_seed.expose());
        v.extend_from_slice(&n.to_be_bytes());
        for d in &self.doc_ids {
            v.extend_from_slice(d);
        }
        Ok(v)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_seed = humid_pq2::Secret32::from_slice(r.take(32)?)?;
        let n = r.u32()? as usize;
        if n > MAX_GRANT_DOCS {
            return Err(CoreError::Format);
        }
        let mut doc_ids = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            doc_ids.push(r.array()?);
        }
        r.finish()?;
        Ok(Self {
            account_seed,
            doc_ids,
        })
    }
}

/// The per-join KEM key on the new device, kept (sealed under the device-records key) only
/// until every granted document has been adopted into a hardware slot (review L5):
/// `seed (96) ‖ u32 n ‖ n × doc_id still pending`.
pub(crate) struct JoinKey {
    pub seed: humid_pq2::Secret<96>,
    pub pending: Vec<[u8; 32]>,
}

impl JoinKey {
    pub(crate) fn kem(&self) -> KemSecretKey {
        KemSecretKey::from_seed(&self.seed)
    }

    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let n = u32::try_from(self.pending.len()).map_err(|_| CoreError::Format)?;
        let mut v = zeroize::Zeroizing::new(Vec::with_capacity(100 + 32 * self.pending.len()));
        v.extend_from_slice(self.seed.expose());
        v.extend_from_slice(&n.to_be_bytes());
        for d in &self.pending {
            v.extend_from_slice(d);
        }
        Ok(v)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let seed = humid_pq2::Secret::<96>::from_slice(r.take(96)?)?;
        let n = r.u32()? as usize;
        if n > MAX_GRANT_DOCS {
            return Err(CoreError::Format);
        }
        let mut pending = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            pending.push(r.array()?);
        }
        r.finish()?;
        Ok(Self { seed, pending })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_and_signature() {
        let dev = MlDsaSigningKey::generate().unwrap();
        let kem = KemSecretKey::generate().unwrap();
        let r = JoinRequest::sign([7; 32], &dev, kem.public_key()).unwrap();
        let enc = r.encode();
        assert_eq!(enc.len(), JOIN_REQUEST_LEN);
        assert_eq!(JoinRequest::decode(&enc).unwrap(), r);
        // a swapped KEM key (review H1) breaks the signature
        let other = KemSecretKey::generate().unwrap();
        let mut forged = enc.clone();
        let at = HEADER_LEN + 32 + MLDSA_VK_LEN;
        forged[at..at + KEM_PUBLIC_KEY_LEN].copy_from_slice(other.public_key().to_bytes());
        assert_eq!(
            JoinRequest::decode(&forged).unwrap_err(),
            CoreError::WrongSigner
        );
        // any other changed byte too
        for i in [HEADER_LEN, HEADER_LEN + 40, enc.len() - 33] {
            let mut e = enc.clone();
            e[i] ^= 1;
            assert!(JoinRequest::decode(&e).is_err(), "{i}");
        }
        for n in [0, 10, JOIN_REQUEST_LEN - 1, JOIN_REQUEST_LEN + 1] {
            assert!(JoinRequest::decode(&vec![0u8; n]).is_err());
        }
    }

    #[test]
    fn re_signing_changes_the_code() {
        let dev = MlDsaSigningKey::generate().unwrap();
        let kem = KemSecretKey::generate().unwrap();
        let r = JoinRequest::sign([7; 32], &dev, kem.public_key()).unwrap();
        let attacker_dev = MlDsaSigningKey::generate().unwrap();
        let attacker_kem = KemSecretKey::generate().unwrap();
        let f = JoinRequest::sign([7; 32], &attacker_dev, attacker_kem.public_key()).unwrap();
        assert_ne!(r.code().unwrap(), f.code().unwrap());
        assert_ne!(r.binding().unwrap(), f.binding().unwrap());
    }

    #[test]
    fn grant_and_join_key_bodies() {
        let g = JoinGrantBody {
            account_seed: humid_pq2::Secret32::random().unwrap(),
            doc_ids: vec![[1; 32], [2; 32]],
        };
        let b = JoinGrantBody::decode(&g.encode().unwrap()).unwrap();
        assert!(b.account_seed.ct_eq(&g.account_seed));
        assert_eq!(b.doc_ids, g.doc_ids);
        assert!(JoinGrantBody::decode(&g.encode().unwrap()[..40]).is_err());
        let k = JoinKey {
            seed: humid_pq2::Secret::<96>::random().unwrap(),
            pending: vec![[3; 32]],
        };
        let back = JoinKey::decode(&k.encode().unwrap()).unwrap();
        assert_eq!(back.pending, k.pending);
        assert_eq!(back.kem().public_key(), k.kem().public_key());
    }
}
