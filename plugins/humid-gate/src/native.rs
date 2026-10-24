//! [`NativeGate`]: humid-core's [`HardwareGate`] over the native halves (CORE.md §3, §5).
//!
//! Rust calls the platform directly through a [`Native`] bridge (iOS: a C function exported
//! by the Swift package; Android: a JNI static method), with the byte protocol in
//! [`crate::wire`]. Hardware outputs come back as bytes, are turned into `HW` here with the
//! HUMID-PQ2 KDF, and every intermediate copy is wiped. Nothing in this module is reachable
//! from the web view: the Tauri commands (src/commands.rs) see only public results.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use hmac::{KeyInit, Mac};
use humid_core::gate::{
    GateError, GateInfo, HardwareGate, HwOp, HwOutput, HwTarget, LiveAlg, LiveProof, LiveSig,
    Platform, Prompt, Purpose, TargetKind,
};
use humid_pq2::{Secret32, encoding::ObjectType, kdf, random_bytes};
use zeroize::{Zeroize, Zeroizing};

use crate::design::Design;
use crate::input::{Input, valid_name};
use crate::lows::low_s;
use crate::wire::{
    Failure, K_FACTOR, K_HMAC, K_IOS, K_LIVE, Level, Malformed, OP_ATTEST, OP_AUTHORIZE,
    OP_DELETE, OP_FACTOR_KEY, OP_IMPORT_HMAC, OP_INFO, OP_IOS_TARGET, OP_WIPE, R, W, split,
};

/// The KDF labels that turn hardware outputs into `HW` (CORE.md §3).
pub const LABEL_IOS: &str = "HUMID-PQ2 hw-ios";
/// Android A/B/C: `KDF(label, [HMAC-SHA256(k, msg)], [input])`.
pub const LABEL_ANDROID: &str = "HUMID-PQ2 hw-android";
/// Android D: `KDF(label, [ML-DSA-87 signature], [input])`.
pub const LABEL_ANDROID_D: &str = "HUMID-PQ2 hw-android-dsa";
/// The ML-DSA context the live ML-DSA-87 key signs under, so the signature verifies with
/// humid-pq2's `MlDsaVerifyingKey::verify("HUMID-PQ2 live", msg, sig)`.
pub const LIVE_LABEL: &str = "HUMID-PQ2 live";

/// The native half: one call, bytes in, bytes out. Implementations are the iOS and Android
/// bridges and, in tests, a simulated device.
pub trait Native: Send {
    /// Run `op` on `req`; the answer as [`crate::wire`] describes.
    fn call(&mut self, op: u8, req: &[u8]) -> Zeroizing<Vec<u8>>;
}

/// The bridge, shared by the gate and the attester. Only [`NativeGate`] sends `authorize`.
pub type Bridge = Arc<Mutex<Box<dyn Native>>>;

fn lock(b: &Bridge) -> MutexGuard<'_, Box<dyn Native>> {
    b.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the native side reports about this phone (public).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// `ios` or `android`.
    pub os_family: String,
    /// The OS version, as the platform names it.
    pub os: String,
    /// The phone model.
    pub model: String,
    /// Android: this phone has a StrongBox secure element.
    pub strong_box: bool,
    /// iOS: App Attest is supported here.
    pub app_attest: bool,
    /// A strong biometric is enrolled and usable.
    pub biometrics: bool,
    /// Which: "face", "fingerprint".
    pub modalities: String,
    /// ML-DSA-87 in the secure hardware (iOS 26 Secure Enclave; Android 17 Keystore).
    pub ml_dsa: bool,
}

/// Ask the native side about the phone (no prompt).
///
/// # Errors
/// The native failure.
pub fn device_info(bridge: &Bridge, design: Design) -> Result<DeviceInfo, Failure> {
    let mut w = W::new();
    w.u8(design.wire());
    let resp = lock(bridge).call(OP_INFO, w.bytes());
    let body = split(&resp)?;
    let parse = || -> Result<DeviceInfo, Malformed> {
        let mut r = R::new(body);
        let family = r.u8()?;
        let strong_box = r.u8()? == 1;
        let app_attest = r.u8()? == 1;
        let biometrics = r.u8()? == 1;
        let ml_dsa = r.u8()? == 1;
        let model = r.text()?;
        let os = r.text()?;
        let modalities = r.text()?;
        r.done()?;
        Ok(DeviceInfo {
            os_family: if family == 0 { "ios" } else { "android" }.into(),
            os,
            model,
            strong_box,
            app_attest,
            biometrics,
            modalities,
            ml_dsa,
        })
    };
    parse().map_err(|_| malformed())
}

fn malformed() -> Failure {
    Failure {
        error: GateError::Platform,
        prompts: 0,
        message: "malformed answer from the native gate".into(),
    }
}

/// One `authorize` as the native side measured it (public: counts and times only).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallStat {
    /// The prompt's purpose.
    pub purpose: String,
    /// Operations asked for.
    pub ops: usize,
    /// Biometric prompts the native side showed.
    pub prompts: u32,
    /// Time from the first prompt opening to the last authentication (ms).
    pub auth_ms: u32,
    /// Time spent in hardware operations after authentication (ms).
    pub ops_ms: u32,
    /// Wall time of the whole call (ms).
    pub total_ms: u64,
    /// The gate error, if it failed.
    pub error: Option<String>,
    /// Native diagnostics for a failure (never key material).
    pub message: Option<String>,
}

/// Security levels and counts the gate has seen (public).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    /// Every authorize, in order.
    pub calls: Vec<CallStat>,
    /// Security level of each hardware key made, in order.
    pub key_levels: Vec<Level>,
    /// Targets made (no prompt), and their total time (ms).
    pub targets: usize,
    /// Time spent making targets (ms).
    pub target_ms: u64,
    /// Inputs retired.
    pub retired: usize,
}

/// A shared, read-mostly view of the gate's [`Stats`] (the hardware check reads it).
pub type StatsHandle = Arc<Mutex<Stats>>;

/// The hardware gate over a native bridge.
pub struct NativeGate {
    bridge: Bridge,
    design: Design,
    ns: String,
    platform: Platform,
    stats: StatsHandle,
}

/// Turn a design's raw hardware output into `HW` for `input`.
fn hw(design: Design, keys: &[&[u8]], input: &[u8]) -> Result<Secret32, GateError> {
    let label = match design {
        Design::Ios => LABEL_IOS,
        Design::A | Design::B | Design::C => LABEL_ANDROID,
        Design::D => LABEL_ANDROID_D,
    };
    kdf::<32>(label, keys, &[input]).map_err(|_| GateError::Platform)
}

/// HMAC-SHA256 in software, for a key the core has just picked (proposal A: the value is
/// known at target time). The key and the MAC are wiped.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    m.update(msg);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

fn random_name() -> Result<String, GateError> {
    let mut b = [0u8; 10];
    random_bytes(&mut b).map_err(|_| GateError::Platform)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn random32() -> Result<Zeroizing<[u8; 32]>, GateError> {
    let mut b = Zeroizing::new([0u8; 32]);
    random_bytes(&mut b[..]).map_err(|_| GateError::Platform)?;
    Ok(b)
}

/// What one prompt title may be (the native side checks again).
fn title(p: &Prompt) -> String {
    let t: String = p
        .title
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = t.trim();
    let t = if t.is_empty() { "Confirm it's you" } else { t };
    t.chars().take(120).collect()
}

fn purpose_byte(p: Purpose) -> u8 {
    match p {
        Purpose::Enroll => 1,
        Purpose::Unlock => 2,
        Purpose::Seal => 3,
        Purpose::Open => 4,
        Purpose::AddDevice => 5,
        Purpose::AdoptDocuments => 6,
    }
}

/// The ML-DSA context for live signatures: `SUITE ‖ u16 0x0004 ‖ "HUMID-PQ2 live"`, as
/// humid-pq2 builds it for `MlDsaSigningKey::sign`.
#[must_use]
pub fn live_mldsa_context() -> Vec<u8> {
    let mut c = humid_pq2::SUITE.to_vec();
    c.extend_from_slice(&ObjectType::MLDSA_SIGNATURE.to_be_bytes());
    c.extend_from_slice(LIVE_LABEL.as_bytes());
    c
}

impl NativeGate {
    /// A gate for `design` over `bridge`, keeping its hardware keys in namespace `ns`
    /// (`[a-z0-9]{1,40}`: "app" for the app, "hc…" for the hardware check).
    ///
    /// # Errors
    /// [`GateError::Platform`] for a bad namespace or a design for the other platform.
    pub fn new(bridge: Bridge, design: Design, ns: &str, info: &DeviceInfo) -> Result<Self, GateError> {
        if !valid_name(ns) || design.android() != (info.os_family == "android") {
            return Err(GateError::Platform);
        }
        let platform = match (design.android(), info.strong_box) {
            (false, _) => Platform::AppleSecureEnclave,
            (true, true) => Platform::AndroidStrongBox,
            (true, false) => Platform::AndroidTee,
        };
        Ok(Self {
            bridge,
            design,
            ns: ns.to_owned(),
            platform,
            stats: StatsHandle::default(),
        })
    }

    /// The design in use.
    #[must_use]
    pub fn design(&self) -> Design {
        self.design
    }

    /// The gate's statistics (counts and times; no secrets).
    #[must_use]
    pub fn stats(&self) -> StatsHandle {
        self.stats.clone()
    }

    fn call(&self, op: u8, w: &W) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let resp = lock(&self.bridge).call(op, w.bytes());
        split(&resp)?;
        Ok(resp)
    }

    fn head(&self, w: &mut W) {
        w.u8(self.design.wire()).lp(self.ns.as_bytes());
    }

    fn record_level(&self, level: Level) {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .key_levels
            .push(level);
    }

    fn target_ios(&mut self) -> Result<HwTarget, GateError> {
        let id = random_name()?;
        let mut w = W::new();
        self.head(&mut w);
        w.lp(id.as_bytes());
        let resp = self.call(OP_IOS_TARGET, &w).map_err(|f| f.error)?;
        let parse = || -> Result<HwTarget, GateError> {
            let mut r = R::new(&resp[1..]);
            let level = Level::from_u8(r.u8()?);
            let ss_kem = r.lp()?;
            let ct = r.lp()?.to_vec();
            let ss_ecdh = r.lp()?;
            let eph = r.lp()?.to_vec();
            r.done()?;
            if ss_kem.len() != 32 || ss_ecdh.len() != 32 || ct.len() != 1568 || eph.len() != 65
            {
                return Err(GateError::Platform);
            }
            self.record_level(level);
            let input = Input::Ios { id: id.clone(), ct, eph }.encode();
            let value = hw(Design::Ios, &[ss_kem, ss_ecdh], &input)?;
            Ok(HwTarget {
                input,
                value: Some(value),
            })
        };
        let out = parse();
        if out.is_err() {
            self.delete(&id);
        }
        out
    }

    fn target_hmac(&mut self) -> Result<HwTarget, GateError> {
        let alias = random_name()?;
        let key = random32()?;
        let msg = random32()?;
        let mut w = W::new();
        self.head(&mut w);
        w.lp(alias.as_bytes()).lp(&key[..]);
        let resp = self.call(OP_IMPORT_HMAC, &w).map_err(|f| f.error)?;
        drop(w); // the request held the key bytes: wiped now
        let mut r = R::new(&resp[1..]);
        let level = r.u8().map(Level::from_u8).map_err(GateError::from)?;
        r.done()?;
        self.record_level(level);
        let input = Input::Hmac {
            design: self.design,
            alias,
            msg: msg.to_vec(),
        }
        .encode();
        let mac = hmac_sha256(&key, &msg[..]);
        drop(key); // from here on only the Keystore holds it (CORE.md §5 A)
        let value = hw(self.design, &[&mac[..]], &input)?;
        Ok(HwTarget {
            input,
            value: Some(value),
        })
    }

    fn target_factor(&mut self) -> Result<HwTarget, GateError> {
        const ALIAS: &str = "factor";
        let mut w = W::new();
        self.head(&mut w);
        w.lp(ALIAS.as_bytes());
        let resp = self.call(OP_FACTOR_KEY, &w).map_err(|f| f.error)?;
        let mut r = R::new(&resp[1..]);
        let level = r.u8().map(Level::from_u8).map_err(GateError::from)?;
        r.done()?;
        self.record_level(level);
        let msg = random32()?;
        Ok(HwTarget {
            input: Input::Factor {
                alias: ALIAS.into(),
                msg: msg.to_vec(),
            }
            .encode(),
            value: None,
        })
    }

    fn delete(&mut self, name: &str) {
        let mut w = W::new();
        self.head(&mut w);
        w.lp(name.as_bytes());
        let _ = self.call(OP_DELETE, &w);
    }

    /// Delete every hardware key in this gate's namespace, live keys included.
    pub fn wipe(&mut self) {
        let mut w = W::new();
        self.head(&mut w);
        let _ = self.call(OP_WIPE, &w);
    }
}

/// What a `Derive` asks the native side for, by input.
enum Want {
    Native(Input),
    /// Not one of ours (another adapter's, or damaged): Unavailable without asking.
    Foreign,
}

impl HardwareGate for NativeGate {
    fn info(&self) -> GateInfo {
        GateInfo {
            platform: self.platform,
            max_ops: self.design.max_ops(),
        }
    }

    fn target(&mut self, kind: TargetKind) -> Result<HwTarget, GateError> {
        let t0 = Instant::now();
        let _ = kind; // every design makes wrap and document targets the same way
        let out = match self.design {
            Design::Ios => self.target_ios(),
            Design::A | Design::B | Design::C => self.target_hmac(),
            Design::D => self.target_factor(),
        };
        let mut s = self.stats.lock().unwrap_or_else(PoisonError::into_inner);
        s.targets += 1;
        s.target_ms += u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        out
    }

    fn authorize(&mut self, prompt: &Prompt, ops: &[HwOp]) -> Result<Vec<HwOutput>, GateError> {
        if ops.len() > self.design.max_ops() {
            return Err(GateError::TooManyOps);
        }
        let t0 = Instant::now();
        let wants: Vec<Option<Want>> = ops
            .iter()
            .map(|op| match op {
                HwOp::Derive(b) => Some(match Input::decode(b) {
                    Ok(i) if i.design().android() == self.design.android() => Want::Native(i),
                    _ => Want::Foreign,
                }),
                HwOp::SignLive(_) => None,
            })
            .collect();
        let mut w = W::new();
        self.head(&mut w);
        w.lp(title(prompt).as_bytes()).u8(purpose_byte(prompt.purpose));
        let asked: Vec<usize> = (0..ops.len())
            .filter(|&i| !matches!(wants[i], Some(Want::Foreign)))
            .collect();
        w.u32(u32::try_from(asked.len()).map_err(|_| GateError::TooManyOps)?);
        let ctx = live_mldsa_context();
        for &i in &asked {
            match (&ops[i], &wants[i]) {
                (HwOp::SignLive(m), _) => {
                    w.u8(K_LIVE).lp(m).lp(&ctx);
                }
                (_, Some(Want::Native(Input::Ios { id, ct, eph }))) => {
                    w.u8(K_IOS).lp(id.as_bytes()).lp(ct).lp(eph);
                }
                (_, Some(Want::Native(Input::Hmac { alias, msg, .. }))) => {
                    w.u8(K_HMAC).lp(alias.as_bytes()).lp(msg);
                }
                (_, Some(Want::Native(Input::Factor { alias, msg }))) => {
                    w.u8(K_FACTOR).lp(alias.as_bytes()).lp(msg);
                }
                _ => return Err(GateError::Platform),
            }
        }
        let resp = lock(&self.bridge).call(OP_AUTHORIZE, w.bytes());
        let result = self.outputs(ops, &wants, &asked, &resp);
        let mut stat = CallStat {
            purpose: format!("{:?}", prompt.purpose),
            ops: ops.len(),
            total_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            ..CallStat::default()
        };
        match (&result, split(&resp)) {
            (Ok((_, p, a, o)), _) => {
                stat.prompts = *p;
                stat.auth_ms = *a;
                stat.ops_ms = *o;
            }
            (Err(e), Err(f)) => {
                stat.prompts = f.prompts;
                stat.error = Some(format!("{e:?}"));
                stat.message = Some(f.message);
            }
            (Err(e), Ok(_)) => stat.error = Some(format!("{e:?}")),
        }
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .push(stat);
        result.map(|(o, ..)| o)
    }

    fn retire(&mut self, input: &[u8]) {
        let Ok(i) = Input::decode(input) else { return };
        let name = match i {
            Input::Ios { id, .. } => id,
            Input::Hmac { alias, .. } => alias,
            // proposal D's key is long-lived: only the rollback floor refuses an old wrap
            Input::Factor { .. } => return,
        };
        self.delete(&name);
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retired += 1;
    }
}

type Outputs = (Vec<HwOutput>, u32, u32, u32);

impl NativeGate {
    /// Decode an authorize answer into outputs in op order, turning raw hardware outputs
    /// into `HW` and wiping them.
    fn outputs(
        &self,
        ops: &[HwOp],
        wants: &[Option<Want>],
        asked: &[usize],
        resp: &[u8],
    ) -> Result<Outputs, GateError> {
        let body = split(resp).map_err(|f| f.error)?;
        let mut r = R::new(body);
        let prompts = r.u32()?;
        let auth_ms = r.u32()?;
        let ops_ms = r.u32()?;
        if r.u32()? as usize != asked.len() {
            return Err(GateError::Platform);
        }
        let mut out: Vec<Option<HwOutput>> = (0..ops.len()).map(|_| None).collect();
        for (i, slot) in out.iter_mut().enumerate() {
            if matches!(wants[i], Some(Want::Foreign)) {
                *slot = Some(HwOutput::Unavailable);
            }
        }
        for &i in asked {
            let present = r.u8()? == 1;
            let o = match (&ops[i], &wants[i]) {
                (HwOp::SignLive(_), _) => {
                    if !present {
                        return Err(GateError::Platform); // audit L1: fail closed
                    }
                    HwOutput::Live(read_live(&mut r)?)
                }
                (HwOp::Derive(input), Some(Want::Native(kind))) => {
                    if present {
                        let raw: Vec<&[u8]> = match kind {
                            Input::Ios { .. } => vec![r.lp()?, r.lp()?],
                            Input::Hmac { .. } | Input::Factor { .. } => vec![r.lp()?],
                        };
                        let ok_len = match kind {
                            Input::Ios { .. } | Input::Hmac { .. } => {
                                raw.iter().all(|x| x.len() == 32)
                            }
                            Input::Factor { .. } => raw[0].len() == humid_pq2::MLDSA_SIG_LEN,
                        };
                        if !ok_len {
                            return Err(GateError::Platform);
                        }
                        HwOutput::Derived(hw(kind.design(), &raw, input)?)
                    } else {
                        HwOutput::Unavailable
                    }
                }
                _ => return Err(GateError::Platform),
            };
            out[i] = Some(o);
        }
        r.done()?;
        let outs = out
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(GateError::Platform)?;
        Ok((outs, prompts, auth_ms, ops_ms))
    }
}

fn read_live(r: &mut R) -> Result<LiveProof, GateError> {
    let n = r.u32()?;
    if n == 0 || n > 3 {
        return Err(GateError::Platform);
    }
    let mut sigs = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let alg = match r.u8()? {
            1 => LiveAlg::EcdsaP256,
            2 => LiveAlg::MlDsa87,
            3 => LiveAlg::AppAttest,
            _ => return Err(GateError::Platform),
        };
        let b = r.lp()?;
        if b.is_empty() || b.len() > 8192 {
            return Err(GateError::Platform);
        }
        let bytes = if alg == LiveAlg::EcdsaP256 {
            low_s(b)
        } else {
            b.to_vec()
        };
        sigs.push(LiveSig { alg, bytes });
    }
    if !sigs.iter().any(|s| s.alg == LiveAlg::EcdsaP256) {
        return Err(GateError::Platform);
    }
    Ok(LiveProof { sigs })
}

/// The device's live keys and what vouches for them (all public, for the server).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// Security level of the P-256 live key.
    pub level: Option<Level>,
    /// The P-256 live key, SubjectPublicKeyInfo DER.
    #[serde(skip)]
    pub p256_spki: Vec<u8>,
    /// The ML-DSA-87 live key (raw, 2592 bytes), where the hardware has one.
    #[serde(skip)]
    pub mldsa_vk: Vec<u8>,
    /// Android: the key attestation certificate chain, leaf first (DER).
    #[serde(skip)]
    pub chain: Vec<Vec<u8>>,
    /// iOS: the App Attest key id.
    #[serde(skip)]
    pub app_attest_key_id: Vec<u8>,
    /// iOS: the App Attest attestation object (CBOR), empty if App Attest is unavailable.
    #[serde(skip)]
    pub app_attest_object: Vec<u8>,
    /// Why App Attest (or ML-DSA) is missing, when it is (diagnostics).
    pub note: String,
}

/// The attestation challenge for a new device (SERVER.md §2.7):
/// `H("HUMID-PQ2 attest-challenge", [th, device_vk])[0..32]`.
///
/// # Errors
/// Never in practice (the label is valid).
pub fn attest_challenge(th: &[u8], device_vk: &[u8]) -> Result<[u8; 32], GateError> {
    let h = humid_pq2::labelled_hash("HUMID-PQ2 attest-challenge", &[th, device_vk])
        .map_err(|_| GateError::Platform)?;
    let mut c = [0u8; 32];
    c.copy_from_slice(&h[..32]);
    Ok(c)
}

/// Makes and attests the live keys. Shares the bridge with the gate but can't authorize:
/// it never touches a hardware input, so handing it to the app layer leaves review M1 intact.
#[derive(Clone)]
pub struct Attester {
    bridge: Bridge,
    design: Design,
    ns: String,
}

impl Attester {
    /// An attester for the gate's namespace.
    #[must_use]
    pub fn new(bridge: Bridge, design: Design, ns: &str) -> Self {
        Self {
            bridge,
            design,
            ns: ns.to_owned(),
        }
    }

    /// Replace this namespace's live keys with new ones bound to `challenge` (no prompt):
    /// Android, a P-256 Keystore key (StrongBox, else TEE: sign only, biometric every use,
    /// unlocked device only, invalidated by a new enrolment) with `challenge` as its
    /// attestationChallenge; iOS, Secure Enclave P-256 and ML-DSA-87 keys and an App Attest
    /// key attested with `clientDataHash = SHA-256(challenge ‖ P-256 SPKI)`. The old keys go
    /// only once the new ones exist (audit L2).
    ///
    /// # Errors
    /// The native failure.
    pub fn attest(&self, challenge: &[u8; 32]) -> Result<Attestation, Failure> {
        let mut w = W::new();
        w.u8(self.design.wire()).lp(self.ns.as_bytes()).lp(challenge);
        let resp = lock(&self.bridge).call(OP_ATTEST, w.bytes());
        let body = split(&resp)?;
        let parse = || -> Result<Attestation, Malformed> {
            let mut r = R::new(body);
            let level = Level::from_u8(r.u8()?);
            let p256_spki = r.lp()?.to_vec();
            let mldsa_vk = r.lp()?.to_vec();
            let n = r.u32()?;
            if n > 10 {
                return Err(Malformed);
            }
            let chain = (0..n)
                .map(|_| r.lp().map(<[u8]>::to_vec))
                .collect::<Result<Vec<_>, _>>()?;
            let app_attest_key_id = r.lp()?.to_vec();
            let app_attest_object = r.lp()?.to_vec();
            let note = r.text()?;
            r.done()?;
            if p256_spki.len() != 91 {
                return Err(Malformed);
            }
            Ok(Attestation {
                level: Some(level),
                p256_spki,
                mldsa_vk,
                chain,
                app_attest_key_id,
                app_attest_object,
                note,
            })
        };
        parse().map_err(|_| malformed())
    }
}

/// Wipe helper for byte vectors the native side handed over.
pub(crate) fn wipe(v: &mut Vec<u8>) {
    v.zeroize();
}
