//! Test support: a simulated phone. Never in a release build (feature `testkit`).
//!
//! It holds what a real phone holds — the account key, its own device key, a secure-chip
//! P-256 key, the account KEM key — and produces the same proofs a phone does
//! (proofs.rs formats), so tests exercise the units' real checks.

use crate::crypto::{self, KemSecret, MlDsaSecret, P256Key, label};
use crate::error::Result;
use crate::proofs::{self, Attestation, DeviceCert, Enrolment, Login, Signed, StepUp};
use crate::wire::{B64, Id};

/// A phone with an account key (shared by the account's devices) and its own device keys.
pub struct Phone {
    /// The account key (in real life: derived from the account seed inside a live check).
    pub account: std::sync::Arc<MlDsaSecret>,
    /// The account's KEM key (documents are sealed to it).
    pub account_kem: std::sync::Arc<KemSecret>,
    /// This device's key.
    pub device: MlDsaSecret,
    /// The secure chip's P-256 key.
    pub chip: P256Key,
}

impl Phone {
    /// A new account's first phone.
    ///
    /// # Errors
    /// Key generation failed.
    pub fn new() -> Result<Self> {
        Ok(Self {
            account: std::sync::Arc::new(MlDsaSecret::generate()?),
            account_kem: std::sync::Arc::new(KemSecret::generate()?),
            device: MlDsaSecret::generate()?,
            chip: P256Key::generate(),
        })
    }

    /// Another device of the same account (it got the account seed through a link or recovery).
    ///
    /// # Errors
    /// Key generation failed.
    pub fn sibling(&self) -> Result<Self> {
        Ok(Self {
            account: self.account.clone(),
            account_kem: self.account_kem.clone(),
            device: MlDsaSecret::generate()?,
            chip: P256Key::generate(),
        })
    }

    /// A device with its own keys whose certificate is signed by *some other* account key
    /// (a thief's phone, presented as this account's).
    ///
    /// # Errors
    /// Key generation failed.
    pub fn impostor_of(&self) -> Result<Self> {
        Self::new()
    }

    /// The account id.
    #[must_use]
    pub fn account_id(&self) -> Id {
        Id(self.account.public().id())
    }

    /// This device's id.
    #[must_use]
    pub fn device_id(&self) -> Id {
        Id(self.device.public().id())
    }

    /// The account key's certificate for this device, made in session `th`.
    ///
    /// # Panics
    /// Signing failure (tests only).
    #[must_use]
    pub fn cert(&self, th: &[u8]) -> DeviceCert {
        let mut c = DeviceCert {
            account_vk: B64(self.account.public().to_bytes()),
            device_vk: B64(self.device.public().to_bytes()),
            live_p256: B64(self.chip.spki()),
            live_mldsa: None,
            enrol_th: B64(th.to_vec()),
            sig: B64(vec![]),
        };
        c.sig = B64(self
            .account
            .sign(label::DEVICE_CERT, &c.message().expect("msg"))
            .expect("sign"));
        c
    }

    /// An enrolment for session `th`.
    ///
    /// # Errors
    /// Signing failure.
    pub fn enrolment(&self, th: &[u8]) -> Result<Enrolment> {
        let cert = self.cert(th);
        let m = cert.message()?;
        Ok(Enrolment {
            device_pop: B64(self.device.sign(label::DEVICE_POP, &m)?),
            live_enrol: B64(self.chip.sign(&proofs::live_digest(label::LIVE_ENROL, &m)?)),
            cert,
            attestation: Attestation::None,
            platform: "test".into(),
        })
    }

    /// The account key's proof of possession at registration.
    ///
    /// # Errors
    /// Signing failure.
    pub fn register_pop(&self, th: &[u8]) -> Result<B64> {
        let m = crypto::lp(&[
            th,
            &self.account.public().to_bytes(),
            &self.account_kem.public().to_bytes(),
        ])?;
        Ok(B64(self.account.sign(label::REGISTER, &m)?))
    }

    /// A sign-in answering `challenge` in session `th`.
    ///
    /// # Errors
    /// Signing failure.
    pub fn login(&self, th: &[u8], challenge: &[u8], duress: u8) -> Result<Login> {
        let (a, d) = (self.account_id(), self.device_id());
        let m = proofs::login_message(th, &a, &d, challenge, duress)?;
        let lm = proofs::live_login_message(th, &a, &d, challenge)?;
        Ok(Login {
            th: B64(th.to_vec()),
            account: a,
            device: d,
            challenge: B64(challenge.to_vec()),
            duress,
            login_sig: B64(self.device.sign(label::LOGIN, &m)?),
            live_login: B64(self
                .chip
                .sign(&proofs::live_digest(label::LIVE_LOGIN, &lm)?)),
            live_mldsa: None,
        })
    }

    /// A step-up approving `method path` with `body`, using `nonce`, at time `at`.
    ///
    /// # Errors
    /// Signing failure.
    #[allow(clippy::too_many_arguments)] // mirrors every field the phone signs
    pub fn step_up(
        &self,
        method: &str,
        path: &str,
        th: &[u8],
        seq: u64,
        nonce: &[u8],
        at: i64,
        body: &[u8],
    ) -> Result<Signed> {
        let d = self.device_id();
        let t = proofs::ticket(method, path, th, seq, &d, nonce, at)?;
        Ok(Signed {
            proof: StepUp {
                method: method.into(),
                path: path.into(),
                th: B64(th.to_vec()),
                seq,
                device: d,
                nonce: B64(nonce.to_vec()),
                at,
                device_sig: B64(self
                    .device
                    .sign(label::STEP_UP, &proofs::step_up_message(&t, body)?)?),
                live_p256: B64(self.chip.sign(&proofs::live_digest(label::LIVE, &t)?)),
                live_mldsa: None,
            },
            body: B64(body.to_vec()),
        })
    }

    /// A recovery-mode statement signed by the account key.
    ///
    /// # Errors
    /// Signing failure.
    pub fn recovery_mode(&self, mode: &str, version: u32, prev: &[u8]) -> Result<B64> {
        let m = crypto::lp(&[
            self.account_id().as_bytes(),
            mode.as_bytes(),
            &version.to_be_bytes(),
            prev,
        ])?;
        Ok(B64(self.account.sign(label::RECOVERY_MODE, &m)?))
    }
}
