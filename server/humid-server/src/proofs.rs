//! The holder's own proofs (SERVER.md §2.2–2.3), checked by whichever unit acts on them.
//!
//! These formats are this server's proposal for humid-core to confirm (SERVER.md §13): every
//! byte layout is in this one file.
//!
//! ```text
//! device_cert_msg = lp(account_id, device_id, device_vk, live_p256_spki, live_mldsa_vk | "", enrol_th)
//! device_cert     = AccountKey.sign("HUMID-PQ2 device-cert", device_cert_msg)
//! ticket          = lp(METHOD, path, th, u64 seq, device_id, nonce, u64 at)
//! live_p256       = ECDSA-P256-SHA256(H("HUMID-PQ2 live", [ticket]))           secure chip
//! live_mldsa      = LiveMlDsa.sign("HUMID-PQ2 live", ticket)                     where the chip can
//! device_sig      = DeviceKey.sign("HUMID-PQ2 step-up", lp(ticket, SHA3-512(body)))
//! login_sig       = DeviceKey.sign("HUMID-PQ2 login", lp(th, account_id, device_id, challenge, u8 duress))
//! live_login      = ECDSA-P256-SHA256(H("HUMID-PQ2 live-login", [lp(th, account_id, device_id, challenge)]))
//! ```

use serde::{Deserialize, Serialize};

use crate::crypto::{self, MlDsaPublic, label};
use crate::error::{Error, Result};
use crate::wire::{B64, Id};

/// How old a step-up may be.
pub const MAX_AGE_MS: i64 = 60_000;
/// How far ahead of the server's clock a phone may be.
pub const SKEW_MS: i64 = 5_000;

/// An enrolled device's public keys, as the account key certified them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCert {
    /// The account's ML-DSA-87 key (its id is the account id).
    pub account_vk: B64,
    /// The device's ML-DSA-87 key (its id is the device id).
    pub device_vk: B64,
    /// The secure chip's P-256 live key (SubjectPublicKeyInfo).
    pub live_p256: B64,
    /// The chip's ML-DSA-87 live key, where the platform has one.
    #[serde(default)]
    pub live_mldsa: Option<B64>,
    /// The session transcript the enrolment happened in.
    pub enrol_th: B64,
    /// The account key's signature over `device_cert_msg`.
    pub sig: B64,
}

/// A certificate that verified: the keys, parsed.
#[derive(Clone, Debug)]
pub struct Device {
    /// Account id.
    pub account: Id,
    /// Device id.
    pub id: Id,
    /// Device key.
    pub vk: MlDsaPublic,
    /// P-256 live key (SPKI).
    pub live_p256: Vec<u8>,
    /// ML-DSA live key.
    pub live_mldsa: Option<MlDsaPublic>,
}

impl DeviceCert {
    /// The bytes the account key signs.
    ///
    /// # Errors
    /// Malformed keys.
    pub fn message(&self) -> Result<Vec<u8>> {
        let account = MlDsaPublic::from_bytes(&self.account_vk)?.id();
        let device = MlDsaPublic::from_bytes(&self.device_vk)?.id();
        let mldsa = self.live_mldsa.as_ref().map_or(&[][..], |k| &k.0[..]);
        crypto::lp(&[
            &account,
            &device,
            &self.device_vk,
            &self.live_p256,
            mldsa,
            &self.enrol_th,
        ])
    }

    /// Check the account key's signature, and that the account key is `account`.
    ///
    /// # Errors
    /// `bad_device_cert`.
    pub fn verify(&self, account: Option<&Id>) -> Result<Device> {
        let refuse = || {
            Error::forbidden(
                "bad_device_cert",
                "This device wasn't added by the account's own key.",
            )
        };
        let avk = MlDsaPublic::from_bytes(&self.account_vk).map_err(|_| refuse())?;
        let acct = Id(avk.id());
        if account.is_some_and(|a| *a != acct) {
            return Err(refuse());
        }
        if self.live_p256.len() != 91 || self.enrol_th.is_empty() {
            return Err(refuse());
        }
        if !avk.verifies(
            label::DEVICE_CERT,
            &self.message().map_err(|_| refuse())?,
            &self.sig,
        ) {
            return Err(refuse());
        }
        let vk = MlDsaPublic::from_bytes(&self.device_vk).map_err(|_| refuse())?;
        let live_mldsa = match &self.live_mldsa {
            Some(k) => Some(MlDsaPublic::from_bytes(k).map_err(|_| refuse())?),
            None => None,
        };
        Ok(Device {
            account: acct,
            id: Id(vk.id()),
            vk,
            live_p256: self.live_p256.0.clone(),
            live_mldsa,
        })
    }
}

/// A step-up proof as the app sends it (beside the signed body).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUp {
    /// The app route's method.
    pub method: String,
    /// The app route's path (names the target: document, device…).
    pub path: String,
    /// The session transcript hash.
    pub th: B64,
    /// The request slot.
    pub seq: u64,
    /// The device.
    pub device: Id,
    /// A nonce core issued to this session and device.
    pub nonce: B64,
    /// When the check happened (ms).
    pub at: i64,
    /// The session mode (CORE.md §8–9): `0` normal, `1` duress (decoy). Signed by the device
    /// key and the chip, so keys learns it from the holder's own proof, never from core.
    pub mode: u8,
    /// The device key's signature.
    pub device_sig: B64,
    /// The secure chip's P-256 signature.
    pub live_p256: B64,
    /// The chip's ML-DSA signature, where it has one.
    #[serde(default)]
    pub live_mldsa: Option<B64>,
    /// iOS: the App Attest assertion for this check, over
    /// [`app_attest_client_data_hash`] of the live digest (core checks it, with its counter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_attest: Option<B64>,
}

/// A request a holder signed: the proof and the exact body bytes it covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    /// The proof.
    pub proof: StepUp,
    /// The JSON body the device key signed (the unit parses it only after checking).
    pub body: B64,
}

/// What a checked step-up tells the caller.
#[derive(Clone, Debug)]
pub struct Checked {
    /// The proof's short hash (what the ledger records, and what single use is keyed on).
    pub proof_hash: [u8; 32],
    /// The nonce (core consumes it).
    pub nonce: Vec<u8>,
    /// The session transcript.
    pub th: Vec<u8>,
    /// The signed session mode (`1` = duress).
    pub mode: u8,
    /// What the chip signed (`H("HUMID-PQ2 live", [ticket])`): the per-check App Attest
    /// assertion covers it.
    pub live_digest: [u8; 64],
}

/// The ticket bytes: `lp(method, path, th, u64 seq, device, nonce, u64 at, u8 mode)`.
///
/// # Errors
/// Never in practice.
#[allow(clippy::too_many_arguments)] // one field per thing the proof binds
pub fn ticket(
    method: &str,
    path: &str,
    th: &[u8],
    seq: u64,
    device: &Id,
    nonce: &[u8],
    at: i64,
    mode: u8,
) -> Result<Vec<u8>> {
    crypto::lp(&[
        method.as_bytes(),
        path.as_bytes(),
        th,
        &seq.to_be_bytes(),
        device.as_bytes(),
        nonce,
        &at.to_be_bytes(),
        &[mode],
    ])
}

/// What the device key signs for a step-up.
///
/// # Errors
/// Never in practice.
pub fn step_up_message(ticket: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    crypto::lp(&[ticket, &crypto::sha3_512(body)])
}

/// What the chip signs (P-256 hashes it again with SHA-256, as chips do).
///
/// # Errors
/// Never in practice.
pub fn live_digest(label: &str, msg: &[u8]) -> Result<[u8; 64]> {
    crypto::hash(label, &[msg])
}

/// The short hash of a proof.
///
/// # Errors
/// Never in practice.
pub fn proof_hash(device_sig: &[u8]) -> Result<[u8; 32]> {
    let h = crypto::hash(label::PROOF_HASH, &[device_sig])?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    Ok(out)
}

/// What a unit expects a proof to approve.
pub struct Expect<'a> {
    /// The app route's method.
    pub method: &'a str,
    /// The app route's path.
    pub path: &'a str,
    /// The session transcript, when the unit knows it (core does; keys doesn't).
    pub th: Option<&'a [u8]>,
    /// Now (ms).
    pub now: i64,
    /// After this date a P-256-only device is refused.
    pub p256_only_until: i64,
    /// The session mode the proof must carry, when the unit knows the session (core does).
    pub mode: Option<u8>,
}

/// Check a step-up over `body` against `device`'s keys. Freshness, the action, the device
/// signature and every live signature the device has. Single use and nonce issuance are the
/// caller's (core consumes the nonce; keys and anon keep a used-proof table).
///
/// # Errors
/// `step_up_mismatch`, `step_up_stale`, `bad_proof`, `bad_live_proof`, `device_retired`.
pub fn check_step_up(p: &StepUp, body: &[u8], device: &Device, e: &Expect<'_>) -> Result<Checked> {
    if p.method != e.method || p.path != e.path {
        return Err(Error::forbidden(
            "step_up_mismatch",
            "That approval was for a different action.",
        ));
    }
    if p.device != device.id {
        return Err(Error::bad_proof());
    }
    if e.now - p.at > MAX_AGE_MS || p.at - e.now > SKEW_MS {
        return Err(Error::forbidden(
            "step_up_stale",
            "The live check is too old. Try again.",
        ));
    }
    if let Some(th) = e.th
        && !crypto::ct_eq(th, &p.th)
    {
        return Err(Error::forbidden(
            "session_changed",
            "That approval was made in another session.",
        ));
    }
    if p.nonce.len() != 32 || p.th.is_empty() || p.mode > 1 || e.mode.is_some_and(|m| m != p.mode) {
        return Err(Error::bad_proof());
    }
    let t = ticket(
        &p.method, &p.path, &p.th, p.seq, &p.device, &p.nonce, p.at, p.mode,
    )?;
    if !device
        .vk
        .verifies(label::STEP_UP, &step_up_message(&t, body)?, &p.device_sig)
    {
        return Err(Error::bad_proof());
    }
    check_live(
        device,
        label::LIVE,
        &t,
        &p.live_p256,
        p.live_mldsa.as_deref(),
        e.now,
        e.p256_only_until,
    )?;
    Ok(Checked {
        proof_hash: proof_hash(&p.device_sig)?,
        nonce: p.nonce.0.clone(),
        th: p.th.0.clone(),
        mode: p.mode,
        live_digest: live_digest(label::LIVE, &t)?,
    })
}

fn check_live(
    device: &Device,
    lbl: &str,
    msg: &[u8],
    p256: &[u8],
    mldsa: Option<&[u8]>,
    now: i64,
    p256_only_until: i64,
) -> Result<()> {
    let bad_live = || {
        Error::unauth(
            "bad_live_proof",
            "This needs a live face or fingerprint check on this device.",
        )
    };
    if !crypto::p256_verifies(&device.live_p256, &live_digest(lbl, msg)?, p256) {
        return Err(bad_live());
    }
    match (&device.live_mldsa, mldsa) {
        (Some(k), Some(sig)) if k.verifies(lbl, msg, sig) => Ok(()),
        (Some(_), _) => Err(bad_live()),
        (None, _) if now > p256_only_until => Err(Error::forbidden(
            "device_retired",
            "This phone's secure chip can only make classical signatures, which this server no longer accepts.",
        )),
        (None, _) => Ok(()),
    }
}

/// A sign-in as the app sends it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// Session transcript.
    pub th: B64,
    /// Account.
    pub account: Id,
    /// Device.
    pub device: Id,
    /// Core's single-use challenge.
    pub challenge: B64,
    /// 1 for a duress sign-in (only the device key's signature carries it).
    pub duress: u8,
    /// The device key's signature.
    pub login_sig: B64,
    /// The chip's P-256 signature over the plain sign-in.
    pub live_login: B64,
    /// The chip's ML-DSA signature, where it has one.
    #[serde(default)]
    pub live_mldsa: Option<B64>,
    /// iOS: the App Attest assertion for this check (as [`StepUp::app_attest`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_attest: Option<B64>,
}

/// The device key's sign-in message.
///
/// # Errors
/// Never in practice.
pub fn login_message(
    th: &[u8],
    account: &Id,
    device: &Id,
    challenge: &[u8],
    duress: u8,
) -> Result<Vec<u8>> {
    crypto::lp(&[
        th,
        account.as_bytes(),
        device.as_bytes(),
        challenge,
        &[duress],
    ])
}

/// The chip's sign-in message (no duress bit: the chip's challenge is fixed before the prompt).
///
/// # Errors
/// Never in practice.
pub fn live_login_message(
    th: &[u8],
    account: &Id,
    device: &Id,
    challenge: &[u8],
) -> Result<Vec<u8>> {
    crypto::lp(&[th, account.as_bytes(), device.as_bytes(), challenge])
}

/// Check a sign-in against `device` (the challenge's issuance and single use are core's).
/// Returns the proof hash.
///
/// # Errors
/// `bad_proof`, `bad_live_proof`, `device_retired`.
pub fn check_login(l: &Login, device: &Device, now: i64, p256_only_until: i64) -> Result<[u8; 32]> {
    if l.account != device.account
        || l.device != device.id
        || l.duress > 1
        || l.challenge.is_empty()
        || l.challenge.len() > 64
    {
        return Err(Error::bad_proof());
    }
    if !device.vk.verifies(
        label::LOGIN,
        &login_message(&l.th, &l.account, &l.device, &l.challenge, l.duress)?,
        &l.login_sig,
    ) {
        return Err(Error::bad_proof());
    }
    let m = live_login_message(&l.th, &l.account, &l.device, &l.challenge)?;
    check_live(
        device,
        label::LIVE_LOGIN,
        &m,
        &l.live_login,
        l.live_mldsa.as_deref(),
        now,
        p256_only_until,
    )?;
    proof_hash(&l.login_sig)
}

/// An enrolment: the certificate plus the device key's proof of possession and the chip's
/// signature over the same bytes, and the platform attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrolment {
    /// The account-signed certificate.
    pub cert: DeviceCert,
    /// The device key over `device_cert_msg` (proof of possession).
    pub device_pop: B64,
    /// The chip over `H(live-enrol, device_cert_msg)`.
    pub live_enrol: B64,
    /// The platform attestation (Android key attestation, App Attest).
    pub attestation: Attestation,
    /// What the phone says it is (shown, never trusted).
    #[serde(default)]
    pub platform: String,
}

/// A platform attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Attestation {
    /// No attestation (development only).
    None,
    /// Android key attestation chain (DER certificates).
    AndroidKey {
        /// The chain.
        chain: Vec<B64>,
    },
    /// Apple App Attest attestation object.
    AppleAppAttest {
        /// The CBOR object.
        object: B64,
    },
}

/// What a platform attestation is bound to at enrolment:
/// `H("HUMID-PQ2 attest-challenge", [th, device_vk])[0..32]`.
///
/// It names the session (so an attestation can't be replayed into another enrolment) and the
/// **new device's ML-DSA key** (CORE.md §5.3's "attested model": the secure chip vouches for a
/// live key made for exactly the device key the join request names, and the account-signed
/// certificate binds that live key to that device key). Android: the KeyMint
/// `attestationChallenge`; iOS: App Attest's `clientDataHash` is
/// `SHA-256(challenge ‖ live P-256 SPKI)`.
///
/// # Errors
/// Never in practice.
pub fn attest_challenge(th: &[u8], device_vk: &[u8]) -> Result<[u8; 32]> {
    let h = crypto::hash(label::ATTEST_CHALLENGE, &[th, device_vk])?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    Ok(out)
}

/// What an iPhone's per-check App Attest assertion covers: `SHA-256(live digest)`, where the
/// live digest is what the chip signs for that check (`H("HUMID-PQ2 live", [ticket])` for a
/// step-up, `H("HUMID-PQ2 live-login", […])` for a sign-in). So the assertion is bound to the
/// one request the chip approved, and its counter to that device's App Attest key.
#[must_use]
pub fn app_attest_client_data_hash(live_digest: &[u8; 64]) -> [u8; 32] {
    humid_attest::sha256(&[live_digest])
}

/// Check an enrolment: the certificate (under the account key), the device key's possession,
/// the chip's signature, and that the certificate was made in this session (`th`). The
/// platform attestation is core's ([`crate::core::attest`]), checked against this device key.
///
/// # Errors
/// `bad_device_cert`, `bad_proof`, `bad_live_proof`, `session_changed`.
pub fn check_enrolment(en: &Enrolment, account: Option<&Id>, th: &[u8]) -> Result<Device> {
    let d = en.cert.verify(account)?;
    if !crypto::ct_eq(&en.cert.enrol_th, th) {
        return Err(Error::forbidden(
            "session_changed",
            "This device's approval was made in another session.",
        ));
    }
    let m = en.cert.message()?;
    if !d.vk.verifies(label::DEVICE_POP, &m, &en.device_pop) {
        return Err(Error::bad_proof());
    }
    if !crypto::p256_verifies(
        &d.live_p256,
        &live_digest(label::LIVE_ENROL, &m)?,
        &en.live_enrol,
    ) {
        return Err(Error::unauth(
            "bad_live_proof",
            "The device's secure chip didn't sign this enrolment.",
        ));
    }
    Ok(d)
}

/// The duress sign-in, as keys receives it to erase an armed vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuressProof {
    /// The device's certificate.
    pub cert: DeviceCert,
    /// The sign-in, with `duress = 1`.
    pub login: Login,
}

impl DuressProof {
    /// Check: the certificate, and a sign-in with the duress bit set by that device.
    ///
    /// # Errors
    /// `bad_device_cert`, `bad_proof`, `bad_live_proof`.
    pub fn check(&self, account: &Id, now: i64, p256_only_until: i64) -> Result<[u8; 32]> {
        let d = self.cert.verify(Some(account))?;
        if self.login.duress != 1 {
            return Err(Error::bad_proof());
        }
        check_login(&self.login, &d, now, p256_only_until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Phone;

    fn expect<'a>(m: &'a str, p: &'a str, th: &'a [u8], now: i64) -> Expect<'a> {
        Expect {
            method: m,
            path: p,
            th: Some(th),
            now,
            p256_only_until: i64::MAX,
            mode: Some(0),
        }
    }

    #[test]
    fn step_up_round_trip_and_every_refusal() {
        let phone = Phone::new().unwrap();
        let th = [7u8; 64];
        let d = phone.cert(&th).verify(None).unwrap();
        let nonce = [1u8; 32];
        let s = phone
            .step_up("GET", "/v1/objects/x", &th, 3, &nonce, 1000, b"{}")
            .unwrap();
        check_step_up(
            &s.proof,
            &s.body,
            &d,
            &expect("GET", "/v1/objects/x", &th, 1000),
        )
        .unwrap();
        // another action
        assert_eq!(
            check_step_up(
                &s.proof,
                &s.body,
                &d,
                &expect("DELETE", "/v1/objects/x", &th, 1000)
            )
            .unwrap_err()
            .code(),
            "step_up_mismatch"
        );
        assert_eq!(
            check_step_up(
                &s.proof,
                &s.body,
                &d,
                &expect("GET", "/v1/objects/y", &th, 1000)
            )
            .unwrap_err()
            .code(),
            "step_up_mismatch"
        );
        // another body
        assert_eq!(
            check_step_up(
                &s.proof,
                b"{\"x\":1}",
                &d,
                &expect("GET", "/v1/objects/x", &th, 1000)
            )
            .unwrap_err()
            .code(),
            "bad_proof"
        );
        // too old, too far ahead
        assert_eq!(
            check_step_up(
                &s.proof,
                &s.body,
                &d,
                &expect("GET", "/v1/objects/x", &th, 1000 + MAX_AGE_MS + 1)
            )
            .unwrap_err()
            .code(),
            "step_up_stale"
        );
        assert_eq!(
            check_step_up(
                &s.proof,
                &s.body,
                &d,
                &expect("GET", "/v1/objects/x", &th, 1000 - SKEW_MS - 1)
            )
            .unwrap_err()
            .code(),
            "step_up_stale"
        );
        // another session
        assert_eq!(
            check_step_up(
                &s.proof,
                &s.body,
                &d,
                &expect("GET", "/v1/objects/x", &[8u8; 64], 1000)
            )
            .unwrap_err()
            .code(),
            "session_changed"
        );
        // no live signature
        let mut nolive = s.proof.clone();
        nolive.live_p256 = B64(vec![0; 70]);
        assert_eq!(
            check_step_up(
                &nolive,
                &s.body,
                &d,
                &expect("GET", "/v1/objects/x", &th, 1000)
            )
            .unwrap_err()
            .code(),
            "bad_live_proof"
        );
        // another device's keys
        let other = Phone::new().unwrap().cert(&th).verify(None).unwrap();
        assert!(
            check_step_up(
                &s.proof,
                &s.body,
                &other,
                &expect("GET", "/v1/objects/x", &th, 1000)
            )
            .is_err()
        );
        // the signed mode must be the session's: a duress session's proofs carry 1
        let mut e = expect("GET", "/v1/objects/x", &th, 1000);
        e.mode = Some(1);
        assert_eq!(
            check_step_up(&s.proof, &s.body, &d, &e).unwrap_err().code(),
            "bad_proof"
        );
        let mut flipped = s.proof.clone();
        flipped.mode = 1;
        assert_eq!(
            check_step_up(&flipped, &s.body, &d, &e).unwrap_err().code(),
            "bad_proof",
            "the mode is signed: front can't flip it"
        );
        let ds = phone
            .step_up_mode("GET", "/v1/objects/x", &th, 3, &nonce, 1000, b"{}", 1)
            .unwrap();
        assert_eq!(check_step_up(&ds.proof, &ds.body, &d, &e).unwrap().mode, 1);
        // P-256 only after the cut-off date
        let mut e = expect("GET", "/v1/objects/x", &th, 1000);
        e.p256_only_until = 500;
        assert_eq!(
            check_step_up(&s.proof, &s.body, &d, &e).unwrap_err().code(),
            "device_retired"
        );
    }

    #[test]
    fn device_cert_needs_the_account_key() {
        let phone = Phone::new().unwrap();
        let th = [7u8; 64];
        let c = phone.cert(&th);
        let d = c.verify(None).unwrap();
        assert_eq!(c.verify(Some(&d.account)).unwrap().id, d.id);
        assert!(c.verify(Some(&Id([9; 32]))).is_err(), "another account");
        // a device key certified by some other key, presented with this account's key
        let thief = Phone::new().unwrap();
        let mut forged = thief.cert(&th);
        forged.account_vk = c.account_vk.clone();
        assert_eq!(
            forged.verify(Some(&d.account)).unwrap_err().code(),
            "bad_device_cert"
        );
    }

    #[test]
    fn login_and_duress() {
        let phone = Phone::new().unwrap();
        let th = [5u8; 64];
        let d = phone.cert(&th).verify(None).unwrap();
        let ch = [2u8; 32];
        let l = phone.login(&th, &ch, 0).unwrap();
        check_login(&l, &d, 0, i64::MAX).unwrap();
        let mut flipped = l.clone();
        flipped.duress = 1;
        assert!(
            check_login(&flipped, &d, 0, i64::MAX).is_err(),
            "the duress bit is signed"
        );
        let dl = phone.login(&th, &ch, 1).unwrap();
        let dp = DuressProof {
            cert: phone.cert(&th),
            login: dl,
        };
        dp.check(&d.account, 0, i64::MAX).unwrap();
        let ordinary = DuressProof {
            cert: phone.cert(&th),
            login: l,
        };
        assert!(
            ordinary.check(&d.account, 0, i64::MAX).is_err(),
            "an ordinary sign-in can't set off an erase"
        );
    }

    #[test]
    fn enrolment() {
        let phone = Phone::new().unwrap();
        let th = [3u8; 64];
        let en = phone.enrolment(&th).unwrap();
        check_enrolment(&en, None, &th).unwrap();
        assert_eq!(
            check_enrolment(&en, None, &[4u8; 64]).unwrap_err().code(),
            "session_changed"
        );
        let mut nopop = en;
        nopop.device_pop = B64(vec![0; 10]);
        assert_eq!(
            check_enrolment(&nopop, None, &th).unwrap_err().code(),
            "bad_proof"
        );
    }

    #[test]
    fn the_attestation_challenge_names_the_session_and_the_device_key() {
        let a = Phone::new().unwrap();
        let b = Phone::new().unwrap();
        let vk = |p: &Phone| p.device.public().to_bytes();
        let c = attest_challenge(&[1; 64], &vk(&a)).unwrap();
        assert_ne!(c, attest_challenge(&[2; 64], &vk(&a)).unwrap());
        assert_ne!(c, attest_challenge(&[1; 64], &vk(&b)).unwrap());
    }
}
