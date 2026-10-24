//! The two seeds a device wrap holds, and every key derived from them (CORE.md §2).

use humid_pq2::{
    KemPublicKey, KemSecretKey, MlDsaSigningKey, MlDsaVerifyingKey, Secret, Secret32, kdf,
};

use crate::error::Result;

/// Length of the wrap payload: account seed ‖ device seed.
pub const SEEDS_LEN: usize = 64;

/// The account seed (shared by every device of the account) and this device's seed.
pub struct Seeds(pub(crate) Secret<SEEDS_LEN>);

impl Seeds {
    /// Fresh seeds; `account` reuses an existing account seed (a joining device).
    pub(crate) fn new(account: Option<&Secret32>) -> Result<Self> {
        let mut s = Secret::<SEEDS_LEN>::random()?;
        if let Some(a) = account {
            let mut both = [0u8; SEEDS_LEN];
            both[..32].copy_from_slice(a.expose());
            both[32..].copy_from_slice(&s.expose()[32..]);
            s = Secret::new(&mut both);
        }
        Ok(Self(s))
    }

    pub(crate) fn account(&self) -> &[u8] {
        &self.0.expose()[..32]
    }

    pub(crate) fn device(&self) -> &[u8] {
        &self.0.expose()[32..]
    }

    pub(crate) fn account_seed(&self) -> Result<Secret32> {
        Ok(Secret32::from_slice(self.account())?)
    }
}

/// Every secret a session holds. All wipe on drop.
pub(crate) struct SessionKeys {
    pub account_kem: KemSecretKey,
    pub account_dsa: MlDsaSigningKey,
    pub device_dsa: MlDsaSigningKey,
    pub device_kem: KemSecretKey,
    /// Index entries (synced, so account-level).
    pub index_key: Secret32,
    /// Device-only records (settings, offline copy, record revisions).
    pub device_records_key: Secret32,
    /// The account seed itself, kept only to seal it to a joining device.
    pub account_seed: Secret32,
}

impl SessionKeys {
    pub(crate) fn derive(seeds: &Seeds) -> Result<Self> {
        let a = seeds.account();
        let d = seeds.device();
        Ok(Self {
            account_kem: KemSecretKey::from_seed(&kdf::<96>("HUMID-PQ2 account-kem", &[a], &[])?),
            account_dsa: MlDsaSigningKey::from_seed(&kdf::<32>(
                "HUMID-PQ2 account-dsa",
                &[a],
                &[],
            )?),
            device_dsa: MlDsaSigningKey::from_seed(&kdf::<32>("HUMID-PQ2 device-dsa", &[d], &[])?),
            device_kem: KemSecretKey::from_seed(&kdf::<96>("HUMID-PQ2 device-kem", &[d], &[])?),
            index_key: kdf::<32>("HUMID-PQ2 index", &[a], &[])?,
            device_records_key: kdf::<32>("HUMID-PQ2 device-records", &[d], &[])?,
            account_seed: seeds.account_seed()?,
        })
    }

    pub(crate) fn public(&self) -> PublicIdentity {
        PublicIdentity {
            account_kem: self.account_kem.public_key().clone(),
            account_dsa: self.account_dsa.verifying_key().clone(),
            device_dsa: self.device_dsa.verifying_key().clone(),
            device_kem: self.device_kem.public_key().clone(),
        }
    }
}

/// The public half of an identity: safe to show, store and send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// Account hybrid KEM key: documents are sealed to it.
    pub account_kem: KemPublicKey,
    /// Account ML-DSA-87 key: signs every document; pinned.
    pub account_dsa: MlDsaVerifyingKey,
    /// This device's ML-DSA-87 key.
    pub device_dsa: MlDsaVerifyingKey,
    /// This device's hybrid KEM key: another device seals the account seed and pending
    /// document slots to it when this device joins.
    pub device_kem: KemPublicKey,
}

impl PublicIdentity {
    /// The account id: `key_id(account ML-DSA key)`.
    #[must_use]
    pub fn account_id(&self) -> [u8; 32] {
        self.account_dsa.key_id()
    }

    /// The device id: `key_id(device ML-DSA key)`.
    #[must_use]
    pub fn device_id(&self) -> [u8; 32] {
        self.device_dsa.key_id()
    }
}
