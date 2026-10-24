//! Test support: a simulated phone. Never in a release build (feature `testkit`).
//!
//! It holds what a real phone holds — the account key, its own device key, a secure-chip
//! P-256 key, the account KEM key — and produces the same proofs a phone does
//! (proofs.rs formats), so tests exercise the units' real checks.

pub mod cluster;

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
    /// How this phone proves its chip (none: development).
    pub attest: Option<PhoneAttest>,
}

/// A simulated phone's platform attestation, made under the testkit's **test root**
/// (humid-attest `testkit`): accepted only by a development server that trusts that root.
pub struct PhoneAttest {
    /// The test PKI.
    pub pki: std::sync::Arc<humid_attest::testkit::TestPki>,
    /// Which platform.
    pub kind: AttestKind,
}

/// Which platform a simulated phone is.
pub enum AttestKind {
    /// Android 17: a key attestation chain with this KeyDescription (its challenge is filled
    /// in per enrolment).
    Android(Box<humid_attest::testkit::KeyDesc>),
    /// iOS 26: an App Attest key, its App ID, and the next assertion counter.
    Apple {
        /// The App Attest key.
        key: humid_attest::testkit::AppAttestKey,
        /// `<team>.<bundle>`.
        app_id: String,
        /// The environment its attestation claims.
        env: humid_attest::Environment,
        /// The next counter.
        counter: std::sync::atomic::AtomicU32,
    },
}

impl PhoneAttest {
    /// An Android 17 StrongBox phone.
    #[must_use]
    pub fn android(pki: &std::sync::Arc<humid_attest::testkit::TestPki>) -> Self {
        Self {
            pki: pki.clone(),
            kind: AttestKind::Android(Box::new(humid_attest::testkit::KeyDesc::strongbox(&[]))),
        }
    }

    /// An Android phone with this KeyDescription (to make a bad one).
    #[must_use]
    pub fn android_with(
        pki: &std::sync::Arc<humid_attest::testkit::TestPki>,
        kd: humid_attest::testkit::KeyDesc,
    ) -> Self {
        Self {
            pki: pki.clone(),
            kind: AttestKind::Android(Box::new(kd)),
        }
    }

    /// An iOS 26 phone (App Store build).
    #[must_use]
    pub fn apple(pki: &std::sync::Arc<humid_attest::testkit::TestPki>) -> Self {
        Self::apple_with(pki, humid_attest::Environment::Production)
    }

    /// An iOS 26 phone whose build is for `env`.
    #[must_use]
    pub fn apple_with(
        pki: &std::sync::Arc<humid_attest::testkit::TestPki>,
        env: humid_attest::Environment,
    ) -> Self {
        Self {
            pki: pki.clone(),
            kind: AttestKind::Apple {
                key: humid_attest::testkit::AppAttestKey::generate(),
                app_id: humid_attest::testkit::APP_ID.into(),
                env,
                counter: std::sync::atomic::AtomicU32::new(1),
            },
        }
    }

    /// The attestation for an enrolment of `device_vk` with live key `live_spki` in session `th`.
    ///
    /// # Errors
    /// Never in practice.
    pub fn attestation(
        &self,
        th: &[u8],
        device_vk: &[u8],
        live_spki: &[u8],
    ) -> Result<Attestation> {
        let ch = proofs::attest_challenge(th, device_vk)?;
        Ok(match &self.kind {
            AttestKind::Android(kd) => {
                let mut kd = (**kd).clone();
                kd.challenge = ch.to_vec();
                let chain = self.pki.android_chain(
                    &kd,
                    live_spki,
                    &humid_attest::testkit::ChainOpts::default(),
                );
                Attestation::AndroidKey {
                    chain: chain.into_iter().map(B64).collect(),
                }
            }
            AttestKind::Apple {
                key, app_id, env, ..
            } => {
                let cdh = humid_attest::apple::enrolment_client_data_hash(&ch, live_spki);
                Attestation::AppleAppAttest {
                    object: B64(self.pki.app_attestation(key, &cdh, app_id, *env, "26.0")),
                }
            }
        })
    }

    /// The App Attest assertion for a check whose live digest is `digest` (iOS; none on Android).
    #[must_use]
    pub fn assertion(&self, digest: &[u8; 64]) -> Option<B64> {
        match &self.kind {
            AttestKind::Android(_) => None,
            AttestKind::Apple {
                key,
                app_id,
                counter,
                ..
            } => {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(B64(key.assertion(
                    app_id,
                    &proofs::app_attest_client_data_hash(digest),
                    n,
                )))
            }
        }
    }

    /// Set the next assertion counter (a test that replays or rolls back).
    pub fn set_counter(&self, n: u32) {
        if let AttestKind::Apple { counter, .. } = &self.kind {
            counter.store(n, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
            attest: None,
        })
    }

    /// This phone, proving its chip with `a`.
    #[must_use]
    pub fn with_attest(mut self, a: PhoneAttest) -> Self {
        self.attest = Some(a);
        self
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
            attest: None,
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
        let attestation = match &self.attest {
            Some(a) => a.attestation(th, &self.device.public().to_bytes(), &self.chip.spki())?,
            None => Attestation::None,
        };
        Ok(Enrolment {
            device_pop: B64(self.device.sign(label::DEVICE_POP, &m)?),
            live_enrol: B64(self.chip.sign(&proofs::live_digest(label::LIVE_ENROL, &m)?)),
            cert,
            attestation,
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
        let digest = proofs::live_digest(label::LIVE_LOGIN, &lm)?;
        Ok(Login {
            th: B64(th.to_vec()),
            account: a,
            device: d,
            challenge: B64(challenge.to_vec()),
            duress,
            login_sig: B64(self.device.sign(label::LOGIN, &m)?),
            live_login: B64(self.chip.sign(&digest)),
            live_mldsa: None,
            app_attest: self.attest.as_ref().and_then(|x| x.assertion(&digest)),
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
        self.step_up_mode(method, path, th, seq, nonce, at, body, 0)
    }

    /// As [`Phone::step_up`], in session mode `mode` (`1` inside a duress session).
    ///
    /// # Errors
    /// Signing failure.
    #[allow(clippy::too_many_arguments)] // mirrors every field the phone signs
    pub fn step_up_mode(
        &self,
        method: &str,
        path: &str,
        th: &[u8],
        seq: u64,
        nonce: &[u8],
        at: i64,
        body: &[u8],
        mode: u8,
    ) -> Result<Signed> {
        let d = self.device_id();
        let t = proofs::ticket(method, path, th, seq, &d, nonce, at, mode)?;
        let digest = proofs::live_digest(label::LIVE, &t)?;
        Ok(Signed {
            proof: StepUp {
                method: method.into(),
                path: path.into(),
                th: B64(th.to_vec()),
                seq,
                device: d,
                nonce: B64(nonce.to_vec()),
                at,
                mode,
                device_sig: B64(self
                    .device
                    .sign(label::STEP_UP, &proofs::step_up_message(&t, body)?)?),
                live_p256: B64(self.chip.sign(&digest)),
                live_mldsa: None,
                app_attest: self.attest.as_ref().and_then(|x| x.assertion(&digest)),
            },
            body: B64(body.to_vec()),
        })
    }

    /// A signed recovery-mode change body (`ModeBody`), chained to `prev`.
    ///
    /// # Errors
    /// Signing failure.
    pub fn mode_body(&self, mode: &str, version: u32, prev: &[u8]) -> Result<Vec<u8>> {
        let msg = crate::core::recovery::mode_message(&self.account_id(), mode, version, prev)?;
        let st = B64(self.account.sign(label::RECOVERY_MODE, &msg)?);
        serde_json::to_vec(
            &serde_json::json!({ "mode": mode, "version": version, "statement": st }),
        )
        .map_err(|e| crate::Error::internal(e.to_string()))
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
