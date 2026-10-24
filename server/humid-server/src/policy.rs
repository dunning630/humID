//! The signed, forward-only server policy (SERVER.md §7).
//!
//! One file, `policy.json`, holds every setting that can weaken or strengthen a check. A
//! detached dual signature (`policy.json.sig`) by the identity root covers the **exact file
//! bytes**, so there is no canonical form to get wrong. Each unit refuses:
//! * a signature that doesn't verify under the pinned identity root (both halves);
//! * unknown fields;
//! * a version lower than the highest it has accepted, or the same version with other bytes;
//! * a production policy when this build has no compiled-in identity-root pin.
//!
//! `server.toml` (config.rs) says only *where* things are; nothing in it can weaken a check.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{self, DualPublic, label};
use crate::error::{Error, Result};
use crate::unit::{Mode, ms};
use crate::wire::{B64, Id};

/// The identity root's key id, pinned at build time (`HUMID_IDENTITY_ROOT_ID`, 64 hex). A
/// production policy is refused by a build without it.
pub const BUILT_IN_ROOT_ID: Option<&str> = option_env!("HUMID_IDENTITY_ROOT_ID");

/// The policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Strictly increasing.
    pub version: u64,
    /// When the root signed it (ms).
    pub issued_at: i64,
    /// Development or production.
    pub mode: Mode,
    /// Whether registration needs an access pass.
    pub registration: Registration,
    /// Which devices may join.
    pub device_policy: DevicePolicy,
    /// Station operators' account ids.
    #[serde(default)]
    pub stations: Vec<Id>,
    /// Public-log cosigners (name → ML-DSA-87 key).
    #[serde(default)]
    pub cosigners: Vec<Cosigner>,
    /// The units' public keys.
    pub unit_keys: UnitKeys,
    /// Check-in settings people may choose.
    pub checkin: CheckinPolicy,
    /// Caps and limits.
    pub limits: Limits,
    /// Messaging (relay) settings.
    pub messaging: Messaging,
    /// Recovery rules.
    pub recovery: RecoveryPolicy,
}

/// Registration mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    /// Needs a spent access pass (anon's `spent` statement).
    Pass,
    /// Anyone may register (pilots). The app warns.
    Open,
}

/// Device policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    /// Require a verified hardware attestation at enrolment. Must be true in production.
    pub attestation_required: bool,
    /// After this date (ms), a device whose live key is P-256 only is refused.
    pub p256_only_until: i64,
    /// Oldest Android security patch accepted (YYYYMM), if any.
    #[serde(default)]
    pub android_min_patch: Option<u32>,
}

/// A cosigner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cosigner {
    /// Its name (`[a-z0-9.-]{1,40}`).
    pub name: String,
    /// Its ML-DSA-87 verifying key (PQ2 encoding).
    pub key: B64,
}

/// The units' public keys (each held in that unit's HSM).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitKeys {
    /// Core's statement key (ML-DSA-87).
    pub core: B64,
    /// The keys unit's statement key (ML-DSA-87).
    pub keys: B64,
    /// Anon's statement key (ML-DSA-87).
    pub anon: B64,
    /// The ledger and public-log key (dual). Apps pin it.
    pub ledger: B64,
}

/// Check-in choices.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckinPolicy {
    /// Whether Check-in is offered.
    pub enabled: bool,
    /// Allowed windows (hours).
    pub windows_h: Vec<u32>,
    /// Allowed grace periods (minutes).
    pub grace_min: Vec<u32>,
}

/// Caps and limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Vault bytes per account.
    pub vault_quota_bytes: u64,
    /// Largest document envelope.
    pub max_object_bytes: u64,
    /// Share releases per account per hour.
    pub share_releases_per_hour: u32,
    /// Signed-in sessions per account.
    pub sessions_per_account: u32,
    /// Active devices per account.
    pub devices_per_account: u32,
    /// HTP handshakes per network per minute.
    pub handshakes_per_minute: u32,
    /// Calls per session per minute.
    pub calls_per_minute: u32,
    /// Failed sign-ins per identity per 5 minutes.
    pub signin_failures_per_identity: u32,
    /// Failed sign-ins per network per 5 minutes.
    pub signin_failures_per_network: u32,
    /// Recovery starts per network per hour.
    pub recovery_starts_per_network_hour: u32,
}

/// Messaging.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Messaging {
    /// Whether the relay is on.
    pub enabled: bool,
    /// Bits of a mailbox id a tick names (the anonymity set: everyone sharing the prefix).
    pub prefix_bits: u32,
    /// Prefix slots in one tick (fixed, so every tick looks alike).
    pub tick_slots: u32,
    /// Size of every tick reply (bytes, padded).
    pub tick_reply_bytes: u32,
    /// Post tokens one live check may buy.
    pub post_tokens_per_check: u32,
    /// Days a relay object is kept unacknowledged.
    pub relay_ttl_days: u32,
    /// Objects per mailbox.
    pub max_per_box: u32,
    /// Bytes per mailbox.
    pub max_box_bytes: u64,
    /// Bytes in the whole relay.
    pub max_total_bytes: u64,
}

/// Recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    /// The base wait (ms); evidence scales it (72 h in production).
    pub base_delay_ms: i64,
    /// A duress signal within this window doubles every wait.
    pub duress_window_ms: i64,
    /// How long after the last duress signal a lockdown may be cleared.
    pub duress_cooloff_ms: i64,
    /// Whether the passport piece counts as a proof (only with a second share operator).
    pub passport_counts: bool,
}

impl Policy {
    /// Check the policy's own consistency (beyond its signature).
    ///
    /// # Errors
    /// `bad_policy` with what's wrong.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::bad("bad_policy", m.to_string()));
        if self.mode == Mode::Production {
            if !self.device_policy.attestation_required {
                return bad("production needs device_policy.attestation_required = true");
            }
            if self.registration == Registration::Open {
                return bad("production needs registration = pass");
            }
            if self.cosigners.is_empty() {
                return bad("production needs at least one public-log cosigner");
            }
            if self.recovery.base_delay_ms < 24 * ms::HOUR {
                return bad("production needs recovery.base_delay_ms of at least 24 hours");
            }
            if self.recovery.passport_counts {
                return bad(
                    "the passport can't count as a proof until a second share operator runs",
                );
            }
        }
        if self.checkin.windows_h.is_empty()
            || self.checkin.windows_h.iter().any(|h| *h == 0 || *h > 24)
        {
            return bad("checkin.windows_h must be 1..=24 hours");
        }
        if self.checkin.grace_min.iter().any(|m| *m > 24 * 60) {
            return bad("checkin.grace_min must be at most a day");
        }
        if !(4..=32).contains(&self.messaging.prefix_bits)
            || !self.messaging.prefix_bits.is_multiple_of(4)
        {
            return bad("messaging.prefix_bits must be a multiple of 4 between 4 and 32");
        }
        if self.messaging.tick_slots == 0 || self.messaging.tick_slots > 64 {
            return bad("messaging.tick_slots must be 1..=64");
        }
        if self.messaging.tick_reply_bytes < 4096 || self.messaging.tick_reply_bytes > (4 << 20) {
            return bad("messaging.tick_reply_bytes must be 4 KiB..4 MiB");
        }
        if self.messaging.post_tokens_per_check == 0 || self.messaging.post_tokens_per_check > 64 {
            return bad("messaging.post_tokens_per_check must be 1..=64");
        }
        for c in &self.cosigners {
            if c.name.is_empty()
                || c.name.len() > 40
                || !c
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
            {
                return bad("a cosigner name is 1-40 of a-z 0-9 . -");
            }
            crypto::MlDsaPublic::from_bytes(&c.key)?;
        }
        for k in [
            &self.unit_keys.core,
            &self.unit_keys.keys,
            &self.unit_keys.anon,
        ] {
            crypto::MlDsaPublic::from_bytes(k)?;
        }
        DualPublic::from_bytes(&self.unit_keys.ledger)?;
        Ok(())
    }

    /// Core's statement key.
    ///
    /// # Errors
    /// Never after `validate`.
    pub fn core_key(&self) -> Result<crypto::MlDsaPublic> {
        crypto::MlDsaPublic::from_bytes(&self.unit_keys.core)
    }
    /// The keys unit's statement key.
    ///
    /// # Errors
    /// Never after `validate`.
    pub fn keys_key(&self) -> Result<crypto::MlDsaPublic> {
        crypto::MlDsaPublic::from_bytes(&self.unit_keys.keys)
    }
    /// Anon's statement key.
    ///
    /// # Errors
    /// Never after `validate`.
    pub fn anon_key(&self) -> Result<crypto::MlDsaPublic> {
        crypto::MlDsaPublic::from_bytes(&self.unit_keys.anon)
    }
}

/// A verified policy with the exact bytes and signature it came from (served to apps as is).
#[derive(Clone, Debug)]
pub struct SignedPolicy {
    /// The parsed policy.
    pub policy: Policy,
    /// The exact bytes the root signed.
    pub bytes: Vec<u8>,
    /// The dual signature.
    pub sig: Vec<u8>,
}

/// What the root signs: `lp(file bytes)`.
fn message(bytes: &[u8]) -> Result<Vec<u8>> {
    crypto::lp(&[bytes])
}

/// Sign policy bytes with a root key (the ceremony tool and the tests).
///
/// # Errors
/// HSM failure.
pub fn sign(hsm: &dyn crate::hsm::Hsm, bytes: &[u8]) -> Result<Vec<u8>> {
    hsm.dual_sign(
        crate::hsm::KeyRef::IdentityRoot,
        label::POLICY,
        &message(bytes)?,
    )
}

/// Verify `bytes` + `sig` under `root`, parse and validate. Doesn't check the version.
///
/// # Errors
/// `bad_policy_signature`, `bad_policy`, `no_root_pin`.
pub fn verify(bytes: &[u8], sig: &[u8], root: &DualPublic, now: i64) -> Result<SignedPolicy> {
    if !root.verifies(label::POLICY, &message(bytes)?, sig) {
        return Err(Error::forbidden(
            "bad_policy_signature",
            "The policy isn't signed by the identity root.",
        ));
    }
    let policy: Policy = serde_json::from_slice(bytes)
        .map_err(|e| Error::bad("bad_policy", format!("policy.json: {e}")))?;
    policy.validate()?;
    if policy.issued_at > now + 5 * ms::MINUTE {
        return Err(Error::bad(
            "bad_policy",
            "The policy is dated in the future.",
        ));
    }
    if policy.mode == Mode::Production {
        match BUILT_IN_ROOT_ID {
            Some(pin) if crypto::ct_eq(pin.as_bytes(), hex::encode(root.id()).as_bytes()) => {}
            Some(_) => {
                return Err(Error::forbidden(
                    "root_mismatch",
                    "The identity root isn't the one this build pins.",
                ));
            }
            None => {
                return Err(Error::forbidden(
                    "no_root_pin",
                    "A production policy needs a build with the identity root pinned (HUMID_IDENTITY_ROOT_ID).",
                ));
            }
        }
    }
    Ok(SignedPolicy {
        policy,
        bytes: bytes.to_vec(),
        sig: sig.to_vec(),
    })
}

/// The highest policy a unit has accepted, kept in `<data_dir>/policy.state` as
/// `version <space> hex(sha3-512(bytes))`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// Version.
    pub version: u64,
    /// SHA3-512 of the bytes.
    pub hash: [u8; 64],
}

const STATE_FILE: &str = "policy.state";

fn read_seen(dir: &Path) -> Result<Option<Seen>> {
    let p = dir.join(STATE_FILE);
    let Ok(s) = std::fs::read_to_string(&p) else {
        return Ok(None);
    };
    let (v, h) = s
        .trim()
        .split_once(' ')
        .ok_or_else(|| Error::internal(format!("{} is malformed", p.display())))?;
    let version = v
        .parse()
        .map_err(|_| Error::internal(format!("{} is malformed", p.display())))?;
    let mut hash = [0u8; 64];
    hex::decode_to_slice(h, &mut hash)
        .map_err(|_| Error::internal(format!("{} is malformed", p.display())))?;
    Ok(Some(Seen { version, hash }))
}

fn write_seen(dir: &Path, s: &Seen) -> Result<()> {
    let p = dir.join(STATE_FILE);
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, format!("{} {}\n", s.version, hex::encode(s.hash)))
        .map_err(|e| Error::internal(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &p).map_err(|e| Error::internal(format!("{}: {e}", p.display())))
}

/// Check the forward-only rule against `dir`'s state and record the new policy.
///
/// # Errors
/// `policy_rollback` for an older version, or the same version with other bytes.
pub fn accept(dir: &Path, p: &SignedPolicy) -> Result<()> {
    let now = Seen {
        version: p.policy.version,
        hash: crypto::sha3_512(&p.bytes),
    };
    if let Some(seen) = read_seen(dir)? {
        if now.version < seen.version
            || (now.version == seen.version && !crypto::ct_eq(&now.hash, &seen.hash))
        {
            return Err(Error::forbidden(
                "policy_rollback",
                format!(
                    "Policy version {} isn't newer than version {} already accepted here.",
                    now.version, seen.version
                ),
            ));
        }
        if now == seen {
            return Ok(());
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| Error::internal(format!("{}: {e}", dir.display())))?;
    write_seen(dir, &now)
}

/// Load `policy.json` + `policy.json.sig`, verify, and apply the forward-only rule.
///
/// # Errors
/// Any of [`verify`] and [`accept`]'s refusals; unreadable files.
pub fn load(
    policy_path: &Path,
    root: &DualPublic,
    data_dir: &Path,
    now: i64,
) -> Result<SignedPolicy> {
    let bytes = std::fs::read(policy_path)
        .map_err(|e| Error::internal(format!("{}: {e}", policy_path.display())))?;
    let sig_path = policy_path.with_extension("json.sig");
    let sig = std::fs::read(&sig_path)
        .map_err(|e| Error::internal(format!("{}: {e}", sig_path.display())))?;
    let p = verify(&bytes, &sig, root, now)?;
    accept(data_dir, &p)?;
    Ok(p)
}

/// A development policy with these unit keys (tests and `dev-setup`).
#[must_use]
pub fn development(version: u64, issued_at: i64, unit_keys: UnitKeys) -> Policy {
    Policy {
        version,
        issued_at,
        mode: Mode::Development,
        registration: Registration::Open,
        device_policy: DevicePolicy {
            attestation_required: false,
            p256_only_until: i64::MAX,
            android_min_patch: None,
        },
        stations: vec![],
        cosigners: vec![],
        unit_keys,
        checkin: CheckinPolicy {
            enabled: true,
            windows_h: vec![1, 2, 4, 8, 24],
            grace_min: vec![0, 15, 30, 60],
        },
        limits: Limits {
            vault_quota_bytes: 250 << 20,
            max_object_bytes: 64 << 20,
            share_releases_per_hour: 120,
            sessions_per_account: 16,
            devices_per_account: 16,
            handshakes_per_minute: 30,
            calls_per_minute: 600,
            signin_failures_per_identity: 10,
            signin_failures_per_network: 20,
            recovery_starts_per_network_hour: 20,
        },
        messaging: Messaging {
            enabled: true,
            prefix_bits: 16,
            tick_slots: 16,
            tick_reply_bytes: 64 << 10,
            post_tokens_per_check: 16,
            relay_ttl_days: 14,
            max_per_box: 500,
            max_box_bytes: 64 << 20,
            max_total_bytes: 2 << 30,
        },
        recovery: RecoveryPolicy {
            base_delay_ms: 72 * ms::HOUR,
            duress_window_ms: 14 * ms::DAY,
            duress_cooloff_ms: 24 * ms::HOUR,
            passport_counts: false,
        },
    }
}

/// The unit keys an HSM (or several) would publish (tests and `dev-setup`).
///
/// # Errors
/// HSM failure.
pub fn unit_keys_from(
    core: &dyn crate::hsm::Hsm,
    keys: &dyn crate::hsm::Hsm,
    anon: &dyn crate::hsm::Hsm,
) -> Result<UnitKeys> {
    use crate::hsm::KeyRef;
    Ok(UnitKeys {
        core: B64(core.mldsa_public(KeyRef::CoreStatement)?.to_bytes()),
        keys: B64(keys.mldsa_public(KeyRef::KeysStatement)?.to_bytes()),
        anon: B64(anon.mldsa_public(KeyRef::AnonStatement)?.to_bytes()),
        ledger: B64(core.dual_public(KeyRef::Ledger)?.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::{Hsm, KeyRef, SoftHsm};

    fn setup() -> (SoftHsm, SoftHsm, Policy) {
        let root = SoftHsm::ephemeral().unwrap();
        let unit = SoftHsm::ephemeral().unwrap();
        let keys = unit_keys_from(&unit, &unit, &unit).unwrap();
        (root, unit, development(1, 0, keys))
    }

    fn tmpdir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "humid-policy-{}",
            hex::encode(crypto::random::<8>().unwrap())
        ))
    }

    #[test]
    fn signed_policy_verifies_and_tampering_fails() {
        let (root, _, p) = setup();
        let bytes = serde_json::to_vec(&p).unwrap();
        let sig = sign(&root, &bytes).unwrap();
        let rk = root.dual_public(KeyRef::IdentityRoot).unwrap();
        verify(&bytes, &sig, &rk, 0).unwrap();
        let mut t = bytes.clone();
        t.push(b' ');
        assert_eq!(
            verify(&t, &sig, &rk, 0).unwrap_err().code(),
            "bad_policy_signature",
            "one extra byte breaks it: the exact bytes are signed"
        );
        let other = SoftHsm::ephemeral().unwrap();
        assert!(verify(&bytes, &sign(&other, &bytes).unwrap(), &rk, 0).is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let (root, _, p) = setup();
        let mut v = serde_json::to_value(&p).unwrap();
        v["trust_forwarded"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&v).unwrap();
        let sig = sign(&root, &bytes).unwrap();
        let e = verify(
            &bytes,
            &sig,
            &root.dual_public(KeyRef::IdentityRoot).unwrap(),
            0,
        )
        .unwrap_err();
        assert_eq!(e.code(), "bad_policy");
    }

    #[test]
    fn forward_only() {
        let (root, _, mut p) = setup();
        let rk = root.dual_public(KeyRef::IdentityRoot).unwrap();
        let dir = tmpdir();
        let mk = |p: &Policy| {
            let b = serde_json::to_vec(p).unwrap();
            let s = sign(&root, &b).unwrap();
            verify(&b, &s, &rk, 0).unwrap()
        };
        p.version = 5;
        accept(&dir, &mk(&p)).unwrap();
        accept(&dir, &mk(&p)).unwrap(); // the same file again is fine (restart)
        p.limits.share_releases_per_hour = 9999;
        assert_eq!(
            accept(&dir, &mk(&p)).unwrap_err().code(),
            "policy_rollback",
            "same version, other bytes"
        );
        p.version = 4;
        assert_eq!(accept(&dir, &mk(&p)).unwrap_err().code(), "policy_rollback");
        p.version = 6;
        accept(&dir, &mk(&p)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn production_needs_safe_settings_and_a_pinned_root() {
        let (root, _, mut p) = setup();
        p.mode = Mode::Production;
        assert!(p.validate().is_err(), "dev settings refused in production");
        p.device_policy.attestation_required = true;
        p.registration = Registration::Pass;
        p.cosigners = vec![Cosigner {
            name: "witness.example".into(),
            key: p.unit_keys.core.clone(),
        }];
        p.validate().unwrap();
        let b = serde_json::to_vec(&p).unwrap();
        let s = sign(&root, &b).unwrap();
        let e = verify(&b, &s, &root.dual_public(KeyRef::IdentityRoot).unwrap(), 0).unwrap_err();
        if BUILT_IN_ROOT_ID.is_none() {
            assert_eq!(e.code(), "no_root_pin");
        } else {
            assert_eq!(e.code(), "root_mismatch");
        }
    }
}
