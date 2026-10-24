//! The byte protocol between Rust and the native halves (Swift on iOS, Kotlin on Android).
//!
//! Rust is the only caller: it calls the native side directly (a C function on iOS, a JNI
//! static method on Android), never through the web view's IPC, so a hardware output never
//! becomes text and never reaches JavaScript. Both directions are length-prefixed bytes:
//!
//! ```text
//! request  = (op passed separately) fields…            lp(x) = u32 BE length ‖ x
//! response = u8 status ‖ body                           status 0 = ok
//!          | u8 status ‖ u32 prompts ‖ lp(message)      status 1–6 = GateError, message non-secret
//! ```
//!
//! The same encoding is implemented in `android/…/Wire.kt` and `ios/…/Wire.swift`;
//! `tests/fixtures/gate-wire.json` holds golden vectors that the Rust and Kotlin tests both
//! check.

use humid_core::gate::GateError;
use zeroize::Zeroizing;

/// Platform information (no prompt).
pub const OP_INFO: u8 = 1;
/// Android A/B/C: import an HMAC-SHA256 key whose bytes the core picked.
pub const OP_IMPORT_HMAC: u8 = 2;
/// iOS: a new Secure Enclave ML-KEM-1024 key, an encapsulation to it and a P-256 agreement.
pub const OP_IOS_TARGET: u8 = 3;
/// One biometric authorization running every op.
pub const OP_AUTHORIZE: u8 = 4;
/// Delete one hardware key.
pub const OP_DELETE: u8 = 5;
/// Make the live key(s) bound to an attestation challenge and return the attestation.
pub const OP_ATTEST: u8 = 6;
/// Delete every key of a namespace (the hardware check cleans up after itself).
pub const OP_WIPE: u8 = 7;
/// Android D: make sure the ML-DSA-87 factor key exists.
pub const OP_FACTOR_KEY: u8 = 8;

/// Authorize op: HMAC-SHA256 under an imported Keystore key (`alias`, `msg`).
pub const K_HMAC: u8 = 1;
/// Authorize op: liveness signature(s) over `msg` (`msg`, ML-DSA context).
pub const K_LIVE: u8 = 2;
/// Authorize op: iOS Secure Enclave decapsulation + P-256 agreement (`id`, `ct`, `eph`).
pub const K_IOS: u8 = 3;
/// Authorize op: Android D, ML-DSA-87 signature by the factor key over `msg`.
pub const K_FACTOR: u8 = 4;

/// Security level a native key reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Software (never accepted).
    Software,
    /// Android TEE.
    Tee,
    /// Android StrongBox.
    StrongBox,
    /// Apple Secure Enclave.
    SecureEnclave,
    /// Not known (the platform didn't say).
    Unknown,
}

impl Level {
    pub(crate) fn from_u8(b: u8) -> Self {
        match b {
            0 => Level::Software,
            1 => Level::Tee,
            2 => Level::StrongBox,
            3 => Level::SecureEnclave,
            _ => Level::Unknown,
        }
    }
}

/// A request or response being built. Requests can hold key bytes (an imported HMAC key),
/// so the buffer is wiped on drop.
#[derive(Default)]
pub struct W(Zeroizing<Vec<u8>>);

impl W {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// One byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    /// A big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// A big-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// `u32 len ‖ bytes`.
    ///
    /// # Panics
    /// Never for what this crate sends (every field is far below 4 GiB).
    pub fn lp(&mut self, b: &[u8]) -> &mut Self {
        self.u32(u32::try_from(b.len()).expect("field under 4 GiB"));
        self.0.extend_from_slice(b);
        self
    }
    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    /// Take the bytes (still wiped on drop).
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A reader over a response. Every read is bounds-checked; [`R::done`] refuses trailing
/// bytes.
pub struct R<'a> {
    b: &'a [u8],
    i: usize,
}

/// Malformed bytes from the native side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

impl From<Malformed> for GateError {
    fn from(_: Malformed) -> Self {
        GateError::Platform
    }
}

impl<'a> R<'a> {
    /// Read `b`.
    #[must_use]
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.i.checked_add(n).ok_or(Malformed)?;
        let s = self.b.get(self.i..end).ok_or(Malformed)?;
        self.i = end;
        Ok(s)
    }
    /// One byte.
    ///
    /// # Errors
    /// [`Malformed`] past the end.
    pub fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }
    /// A big-endian u32.
    ///
    /// # Errors
    /// [`Malformed`] past the end.
    pub fn u32(&mut self) -> Result<u32, Malformed> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// A big-endian u64.
    ///
    /// # Errors
    /// [`Malformed`] past the end.
    pub fn u64(&mut self) -> Result<u64, Malformed> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    /// `u32 len ‖ bytes`.
    ///
    /// # Errors
    /// [`Malformed`] past the end.
    pub fn lp(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// A length-prefixed UTF-8 string (lossy: diagnostics only).
    ///
    /// # Errors
    /// [`Malformed`] past the end.
    pub fn text(&mut self) -> Result<String, Malformed> {
        Ok(String::from_utf8_lossy(self.lp()?).into_owned())
    }
    /// Fails unless every byte was read.
    ///
    /// # Errors
    /// [`Malformed`] with bytes left over.
    pub fn done(&self) -> Result<(), Malformed> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }
}

/// A native call that failed: the gate error, how many prompts it had shown, and a
/// non-secret message for the hardware check's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// What the core sees.
    pub error: GateError,
    /// Prompts shown before it failed.
    pub prompts: u32,
    /// Why (diagnostics; never key material).
    pub message: String,
}

/// The gate error a status byte names.
#[must_use]
pub fn error_of(status: u8) -> GateError {
    match status {
        1 => GateError::Cancelled,
        2 => GateError::Lockout,
        3 => GateError::KeyInvalidated,
        4 => GateError::UnknownInput,
        5 => GateError::TooManyOps,
        _ => GateError::Platform,
    }
}

/// The status byte for a gate error (the simulator and tests).
#[must_use]
pub fn status_of(e: GateError) -> u8 {
    match e {
        GateError::Cancelled => 1,
        GateError::Lockout => 2,
        GateError::KeyInvalidated => 3,
        GateError::UnknownInput => 4,
        GateError::TooManyOps => 5,
        GateError::Platform => 6,
    }
}

/// Split a response into its body, or the failure it reports.
///
/// # Errors
/// The [`Failure`] the native side reported, or a `Platform` failure for malformed bytes.
pub fn split(resp: &[u8]) -> Result<&[u8], Failure> {
    let malformed = || Failure {
        error: GateError::Platform,
        prompts: 0,
        message: "malformed answer from the native gate".into(),
    };
    let (&status, body) = resp.split_first().ok_or_else(malformed)?;
    if status == 0 {
        return Ok(body);
    }
    let mut r = R::new(body);
    let prompts = r.u32().map_err(|_| malformed())?;
    let message = r.text().map_err(|_| malformed())?;
    Ok::<(), ()>(()).ok();
    Err(Failure {
        error: error_of(status),
        prompts,
        message: message.chars().take(300).collect(),
    })
}

/// A failure response (the simulator).
#[must_use]
pub fn failure(e: GateError, prompts: u32, message: &str) -> Zeroizing<Vec<u8>> {
    let mut w = W::new();
    w.u8(status_of(e)).u32(prompts).lp(message.as_bytes());
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut w = W::new();
        w.u8(7).u32(0x0102_0304).u64(9).lp(b"abc").lp(b"");
        let b = w.into_bytes();
        let mut r = R::new(&b);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0x0102_0304);
        assert_eq!(r.u64().unwrap(), 9);
        assert_eq!(r.lp().unwrap(), b"abc");
        assert_eq!(r.lp().unwrap(), b"");
        r.done().unwrap();
    }

    #[test]
    fn short_and_trailing_bytes_are_refused() {
        assert_eq!(R::new(&[0, 0, 0, 9, 1]).lp(), Err(Malformed));
        assert_eq!(R::new(&[0xff, 0xff, 0xff, 0xff]).lp(), Err(Malformed));
        let r = R::new(&[1]);
        assert_eq!(r.done(), Err(Malformed));
    }

    #[test]
    fn failures_carry_code_prompts_and_message() {
        let f = failure(GateError::Cancelled, 1, "user cancelled");
        let e = split(&f).unwrap_err();
        assert_eq!(e.error, GateError::Cancelled);
        assert_eq!(e.prompts, 1);
        assert_eq!(e.message, "user cancelled");
        assert_eq!(split(&[0, 1, 2]).unwrap(), &[1, 2]);
        assert_eq!(split(&[]).unwrap_err().error, GateError::Platform);
        for s in 1..=6 {
            assert_eq!(status_of(error_of(s)), s);
        }
    }
}
