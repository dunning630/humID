//! The hardware gate: the one per-platform operation behind every live check (CORE.md §3).
//!
//! A platform adapter (Swift on iOS 26+, Kotlin on Android 17+) implements
//! [`HardwareGate`]. The core never sees a hardware key; it sees 32-byte outputs of
//! hardware operations, as bytes over FFI, which it wipes after use.

use humid_pq2::Secret32;

/// Why the prompt opens (the adapter picks the system prompt's wording from it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Set up this device.
    Enroll,
    /// Unlock the core.
    Unlock,
    /// Seal a new document.
    Seal,
    /// Open one document.
    Open,
    /// Give another device access to documents.
    AddDevice,
    /// Turn documents shared to this (new) device into hardware-bound ones.
    AdoptDocuments,
}

/// What the one biometric prompt says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// Why.
    pub purpose: Purpose,
    /// The line shown in the system prompt ("Open Passport").
    pub title: String,
}

impl Prompt {
    /// A prompt.
    #[must_use]
    pub fn new(purpose: Purpose, title: &str) -> Self {
        Self {
            purpose,
            title: title.to_owned(),
        }
    }
}

/// What a new hardware input will protect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    /// The next device wrap `W_{n+1}` (CORE.md §4).
    Wrap,
    /// One document's slot on this device (CORE.md §6).
    Document,
}

/// A hardware input made without a prompt.
///
/// `input` is opaque platform bytes stored next to what it protects (iOS: the Secure
/// Enclave ML-KEM ciphertext and P-256 ephemeral key; Android: a key alias and a random
/// HMAC message). `value` is `HW` for that input when the platform can know it now
/// (public-key targets: iOS), or `None` when the hardware must compute it inside an
/// authorization (symmetric targets: Android HMAC), in which case the core adds a
/// [`HwOp::Derive`] for it to the same authorization.
pub struct HwTarget {
    /// Opaque platform input, at most [`MAX_INPUT`] bytes.
    pub input: Vec<u8>,
    /// `HW(input)` if already known.
    pub value: Option<Secret32>,
}

/// Largest hardware input the core stores.
pub const MAX_INPUT: usize = 4096;

/// One operation inside an authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HwOp {
    /// Compute the 32-byte `HW(input)`.
    Derive(Vec<u8>),
    /// Sign `challenge` with the device's hardware liveness key(s).
    SignLive(Vec<u8>),
}

/// The result of one [`HwOp`], in the same position.
pub enum HwOutput {
    /// `HW(input)`.
    Derived(Secret32),
    /// The liveness signature(s).
    Live(LiveProof),
    /// This `Derive` named no hardware key this device has (retired, or another device's);
    /// the other ops in the prompt still ran.
    Unavailable,
}

/// Signature algorithm of a liveness key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveAlg {
    /// ECDSA P-256 / SHA-256, DER, low-S (Secure Enclave, Android Keystore).
    EcdsaP256,
    /// ML-DSA-87 (iOS 26 CryptoKit SecureEnclave.MLDSA87; Android 17 Keystore where present).
    MlDsa87,
    /// iOS App Attest assertion over `SHA-256(signed message)`, made in the same check
    /// (SERVER.md §2.7). Not a live-key signature: it proves the genuine app made the
    /// request, and rides beside the signatures as the proof's `app_attest` field.
    AppAttest,
}

/// One liveness signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSig {
    /// Which key.
    pub alg: LiveAlg,
    /// The signature.
    pub bytes: Vec<u8>,
}

/// The hybrid live proof: what the server verifies against the device's attested keys.
/// Public data: the UI may forward it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LiveProof {
    /// One per liveness key (P-256, and ML-DSA-87 where the platform has it).
    pub sigs: Vec<LiveSig>,
}

/// Why the gate refused. Never carries secret data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    /// The person cancelled the prompt.
    Cancelled,
    /// Too many failed attempts; the platform locked biometrics.
    Lockout,
    /// The hardware key is gone (new biometric enrolled, device reset).
    KeyInvalidated,
    /// The input names no hardware key this device has (retired, or another device's).
    UnknownInput,
    /// More operations than one authorization can carry on this platform.
    TooManyOps,
    /// Any other platform failure.
    Platform,
}

/// Which hardware family the adapter is (for the assurance label and the policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// iOS 26+ Secure Enclave.
    AppleSecureEnclave,
    /// Android 17+ StrongBox.
    AndroidStrongBox,
    /// Android 17+ TEE (no StrongBox on this phone).
    AndroidTee,
    /// The software double (tests, simulator). Never accepted by a production server.
    Software,
}

/// What the adapter can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateInfo {
    /// Hardware family.
    pub platform: Platform,
    /// Most operations one authorization can carry.
    pub max_ops: usize,
}

/// The per-platform hardware operation (CORE.md §3).
///
/// Contract:
/// * [`authorize`](HardwareGate::authorize) shows **exactly one** biometric prompt (live
///   biometric only: no passcode fallback, no reuse of an earlier authentication) and runs
///   every op inside it, or none. It returns outputs in op order. A `Derive` on an input the
///   hardware doesn't know gives [`HwOutput::Unavailable`] without failing the other ops
///   (the core tries fallback wraps in the same prompt).
/// * [`target`](HardwareGate::target) never prompts.
/// * [`retire`](HardwareGate::retire) makes an input permanently unusable where the platform
///   allows it (delete the hardware key it names), so an old wrap can't be reopened.
/// * Outputs travel as bytes, never text, and the adapter wipes its copies.
/// * The adapter is moved into the [`Core`](crate::Core) and nothing else keeps a handle to
///   it: whoever can call `authorize` can compute `HW_n` (review M1).
pub trait HardwareGate {
    /// What this adapter is.
    fn info(&self) -> GateInfo;

    /// Make a new hardware input for `kind`, without a prompt.
    ///
    /// # Errors
    /// [`GateError`] if the platform can't.
    fn target(&mut self, kind: TargetKind) -> Result<HwTarget, GateError>;

    /// One biometric prompt; inside it, every op.
    ///
    /// # Errors
    /// [`GateError`]; on error no output exists.
    fn authorize(&mut self, prompt: &Prompt, ops: &[HwOp]) -> Result<Vec<HwOutput>, GateError>;

    /// Best effort: destroy what `input` names. Unknown inputs are ignored.
    fn retire(&mut self, input: &[u8]);
}
