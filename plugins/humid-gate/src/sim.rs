//! A simulated phone behind the [`Native`] bridge: the byte protocol, each design's prompt
//! behaviour and its failure modes, so the Rust glue and the hardware check can be tested
//! without a device (and run in a desktop development build, labelled "simulated").
//!
//! **Not secure**: its "hardware" keys are ordinary memory.

use std::collections::BTreeMap;

use humid_core::gate::GateError;
use humid_pq2::{kdf, random_bytes};
use zeroize::Zeroizing;

use crate::design::Design;
use crate::native::{LIVE_LABEL, Native};
use crate::wire::{
    K_FACTOR, K_HMAC, K_IOS, K_LIVE, Malformed, OP_ATTEST, OP_AUTHORIZE, OP_DELETE,
    OP_FACTOR_KEY, OP_IMPORT_HMAC, OP_INFO, OP_IOS_TARGET, OP_WIPE, R, W, failure,
};

/// How the simulated phone behaves.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Android (else iPhone).
    pub android: bool,
    /// Android: a StrongBox is present.
    pub strong_box: bool,
    /// Design B: one authentication unlocks every begun operation.
    pub shared_token_works: bool,
    /// Design D: Keystore ML-DSA signing is deterministic.
    pub deterministic_mldsa: bool,
    /// iOS: App Attest is supported.
    pub app_attest: bool,
}

impl SimConfig {
    /// A Pixel-like phone: StrongBox, and the open questions answered "yes".
    #[must_use]
    pub fn android() -> Self {
        Self {
            android: true,
            strong_box: true,
            shared_token_works: true,
            deterministic_mldsa: true,
            app_attest: false,
        }
    }
    /// An iPhone.
    #[must_use]
    pub fn ios() -> Self {
        Self {
            android: false,
            strong_box: false,
            shared_token_works: false,
            deterministic_mldsa: false,
            app_attest: true,
        }
    }
}

/// The simulated phone.
pub struct SimDevice {
    /// Behaviour.
    pub config: SimConfig,
    /// (namespace, name) → key bytes. Removing one models deleting the hardware key.
    keys: BTreeMap<(String, String), Zeroizing<Vec<u8>>>,
    /// Prompts shown so far.
    pub prompts: u32,
    /// When set, the next authorization is cancelled at its first prompt.
    pub cancel_next: bool,
    /// When set, every key is invalid (a new fingerprint was enrolled).
    pub invalidated: bool,
    /// Every secret value this device ever produced (tests check none reaches a report).
    pub produced: Vec<Vec<u8>>,
}

const LIVE: &str = "live";

fn rand(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    random_bytes(&mut v).expect("rng");
    v
}

fn ok() -> W {
    let mut w = W::new();
    w.u8(0);
    w
}

impl SimDevice {
    /// A new phone.
    #[must_use]
    pub fn new(config: SimConfig) -> Self {
        Self {
            config,
            keys: BTreeMap::new(),
            prompts: 0,
            cancel_next: false,
            invalidated: false,
            produced: Vec::new(),
        }
    }

    /// Hardware keys alive in `ns`.
    #[must_use]
    pub fn keys_in(&self, ns: &str) -> usize {
        self.keys.keys().filter(|(n, _)| n == ns).count()
    }

    fn level(&self) -> u8 {
        if !self.config.android {
            3
        } else if self.config.strong_box {
            2
        } else {
            1
        }
    }

    fn key(&self, ns: &str, name: &str) -> Option<&Zeroizing<Vec<u8>>> {
        self.keys.get(&(ns.to_owned(), name.to_owned()))
    }

    fn put(&mut self, ns: &str, name: &str, v: Vec<u8>) {
        self.keys
            .insert((ns.to_owned(), name.to_owned()), Zeroizing::new(v));
    }

    fn secret(&mut self, v: Vec<u8>) -> Vec<u8> {
        self.produced.push(v.clone());
        v
    }

    fn info(&self) -> W {
        let mut w = ok();
        w.u8(u8::from(self.config.android))
            .u8(u8::from(self.config.strong_box))
            .u8(u8::from(self.config.app_attest))
            .u8(1)
            .u8(u8::from(!self.config.android))
            .lp(b"Simulated phone")
            .lp(if self.config.android {
                b"Android 17 (simulated)"
            } else {
                b"iOS 26 (simulated)"
            })
            .lp(if self.config.android {
                b"fingerprint"
            } else {
                b"face"
            });
        w
    }

    fn handle(&mut self, op: u8, req: &[u8]) -> Result<W, (GateError, u32, String)> {
        let bad = |_: Malformed| (GateError::Platform, 0, "malformed request".to_owned());
        let mut r = R::new(req);
        let design = r.u8().map_err(bad)?;
        if op == OP_INFO {
            return Ok(self.info());
        }
        let ns = String::from_utf8_lossy(r.lp().map_err(bad)?).into_owned();
        let design = Design::ALL
            .into_iter()
            .find(|d| d.wire() == design)
            .ok_or((GateError::Platform, 0, "unknown design".into()))?;
        if design.android() != self.config.android {
            return Err((GateError::Platform, 0, "design for the other platform".into()));
        }
        match op {
            OP_IMPORT_HMAC => {
                let alias = String::from_utf8_lossy(r.lp().map_err(bad)?).into_owned();
                let k = r.lp().map_err(bad)?.to_vec();
                r.done().map_err(bad)?;
                if k.len() != 32 {
                    return Err((GateError::Platform, 0, "HMAC key must be 32 bytes".into()));
                }
                self.put(&ns, &alias, k);
                let mut w = ok();
                w.u8(self.level());
                Ok(w)
            }
            OP_IOS_TARGET => {
                let id = String::from_utf8_lossy(r.lp().map_err(bad)?).into_owned();
                r.done().map_err(bad)?;
                let s = rand(32);
                self.put(&ns, &id, s.clone());
                let ct = rand(1568);
                let eph = rand(65);
                let ss_kem = self.secret(sim_kdf(&s, b"kem", &ct));
                let ss_ecdh = self.secret(sim_kdf(&s, b"ecdh", &eph));
                let mut w = ok();
                w.u8(3).lp(&ss_kem).lp(&ct).lp(&ss_ecdh).lp(&eph);
                Ok(w)
            }
            OP_FACTOR_KEY => {
                let alias = String::from_utf8_lossy(r.lp().map_err(bad)?).into_owned();
                if self.key(&ns, &alias).is_none() {
                    self.put(&ns, &alias, rand(32));
                }
                let mut w = ok();
                w.u8(self.level());
                Ok(w)
            }
            OP_DELETE => {
                let name = String::from_utf8_lossy(r.lp().map_err(bad)?).into_owned();
                self.keys.remove(&(ns, name));
                Ok(ok())
            }
            OP_WIPE => {
                self.keys.retain(|(n, _), _| *n != ns);
                Ok(ok())
            }
            OP_ATTEST => {
                let challenge = r.lp().map_err(bad)?.to_vec();
                r.done().map_err(bad)?;
                self.put(&ns, LIVE, rand(32));
                let mut w = ok();
                let mut spki = vec![0x30, 0x59];
                spki.extend_from_slice(&rand(89));
                w.u8(self.level()).lp(&spki);
                if self.config.android {
                    w.lp(b"");
                    w.u32(3);
                    for i in 0..3u8 {
                        let mut cert = vec![0x30, i];
                        cert.extend_from_slice(&challenge);
                        w.lp(&cert);
                    }
                    w.lp(b"").lp(b"").lp(b"");
                } else {
                    w.lp(&rand(2592));
                    w.u32(0);
                    if self.config.app_attest {
                        self.put(&ns, "appattest", rand(32));
                        w.lp(&rand(32)).lp(&rand(5000)).lp(b"");
                    } else {
                        w.lp(b"").lp(b"").lp(b"App Attest isn't supported on this phone");
                    }
                }
                Ok(w)
            }
            OP_AUTHORIZE => self.authorize(design, &ns, &mut r),
            _ => Err((GateError::Platform, 0, "unknown op".into())),
        }
    }

    fn authorize(&mut self, design: Design, ns: &str, r: &mut R) -> Result<W, (GateError, u32, String)> {
        let bad = |_: Malformed| (GateError::Platform, 0, "malformed request".to_owned());
        let _title = r.lp().map_err(bad)?;
        let _purpose = r.u8().map_err(bad)?;
        let n = r.u32().map_err(bad)? as usize;
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            let k = r.u8().map_err(bad)?;
            let a = r.lp().map_err(bad)?.to_vec();
            let b = if k == K_IOS || k == K_HMAC || k == K_FACTOR || k == K_LIVE {
                r.lp().map_err(bad)?.to_vec()
            } else {
                Vec::new()
            };
            let c = if k == K_IOS {
                r.lp().map_err(bad)?.to_vec()
            } else {
                Vec::new()
            };
            ops.push((k, a, b, c));
        }
        r.done().map_err(bad)?;
        // How many prompts this design shows for these ops.
        let crypto_ops = ops.len();
        let prompts = match design {
            Design::Ios | Design::C => 1,
            Design::A | Design::D => crypto_ops.max(1),
            Design::B => {
                if self.config.shared_token_works {
                    1
                } else {
                    crypto_ops.max(1)
                }
            }
        };
        let prompts = u32::try_from(prompts).unwrap_or(u32::MAX);
        if std::mem::take(&mut self.cancel_next) {
            self.prompts += 1;
            return Err((GateError::Cancelled, 1, "the person cancelled".into()));
        }
        if self.invalidated {
            return Err((GateError::KeyInvalidated, 0, "keys invalidated by a new enrolment".into()));
        }
        self.prompts += prompts;
        let mut w = ok();
        w.u32(prompts).u32(5).u32(1).u32(u32::try_from(n).unwrap_or(0));
        for (k, a, b, c) in ops {
            match k {
                K_LIVE => {
                    if self.key(ns, LIVE).is_none() {
                        return Err((GateError::Platform, prompts, "no live key: attest first".into()));
                    }
                    let _ = (a, b);
                    w.u8(1);
                    let mut sig = vec![0x30, 0x44, 0x02, 0x20];
                    sig.extend_from_slice(&rand(32));
                    sig.extend_from_slice(&[0x02, 0x20]);
                    sig.extend_from_slice(&rand(32));
                    let mut sigs: Vec<(u8, Vec<u8>)> = vec![(1, sig)];
                    if !self.config.android {
                        sigs.push((2, rand(4627)));
                        if self.key(ns, "appattest").is_some() {
                            sigs.push((3, rand(120)));
                        }
                    }
                    w.u32(u32::try_from(sigs.len()).unwrap_or(0));
                    for (alg, s) in sigs {
                        w.u8(alg).lp(&s);
                    }
                }
                K_HMAC => {
                    let alias = String::from_utf8_lossy(&a).into_owned();
                    match self.key(ns, &alias).map(|k| k.to_vec()) {
                        Some(key) => {
                            let mac = self.secret(hmac(&key, &b));
                            w.u8(1).lp(&mac);
                        }
                        None => {
                            w.u8(0);
                        }
                    }
                }
                K_IOS => {
                    let id = String::from_utf8_lossy(&a).into_owned();
                    match self.key(ns, &id).map(|k| k.to_vec()) {
                        Some(s) => {
                            w.u8(1).lp(&sim_kdf(&s, b"kem", &b)).lp(&sim_kdf(&s, b"ecdh", &c));
                        }
                        None => {
                            w.u8(0);
                        }
                    }
                }
                K_FACTOR => {
                    let alias = String::from_utf8_lossy(&a).into_owned();
                    match self.key(ns, &alias).map(|k| k.to_vec()) {
                        Some(s) => {
                            let sig = if self.config.deterministic_mldsa {
                                let mut v = Vec::with_capacity(humid_pq2::MLDSA_SIG_LEN);
                                while v.len() < humid_pq2::MLDSA_SIG_LEN {
                                    v.extend_from_slice(&sim_kdf(&s, &[u8::try_from(v.len() / 32 % 256).unwrap_or(0)], &b));
                                }
                                v.truncate(humid_pq2::MLDSA_SIG_LEN);
                                v
                            } else {
                                rand(humid_pq2::MLDSA_SIG_LEN)
                            };
                            let sig = self.secret(sig);
                            w.u8(1).lp(&sig);
                        }
                        None => {
                            w.u8(0);
                        }
                    }
                }
                _ => return Err((GateError::Platform, prompts, "unknown op kind".into())),
            }
        }
        let _ = LIVE_LABEL;
        Ok(w)
    }
}

fn sim_kdf(key: &[u8], what: &[u8], input: &[u8]) -> Vec<u8> {
    kdf::<32>("HUMID-PQ2 sim-device", &[key, what], &[input])
        .expect("kdf")
        .expose()
        .to_vec()
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{KeyInit, Mac};
    let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("hmac");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

impl Native for SimDevice {
    fn call(&mut self, op: u8, req: &[u8]) -> Zeroizing<Vec<u8>> {
        match self.handle(op, req) {
            Ok(w) => w.into_bytes(),
            Err((e, p, m)) => failure(e, p, &m),
        }
    }
}
