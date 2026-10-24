// Windows: a fingerprint match through the Windows Biometric Framework
// (WinBio), then a 32-byte secret is unprotected with DPAPI.
//
// Windows Hello is deliberately not used: Hello always lets the user type a
// PIN instead of a face or finger, and apps cannot turn that off. WinBio talks
// to the fingerprint reader directly and only ever answers "this finger
// belongs to the signed-in Windows account" or not. There is no PIN path.
//
// Like Linux, the secret is protected by the operating system (DPAPI, for the
// signed-in user), not by secure hardware tied to the finger, and there is no
// attestation a server can check. The gate reports assurance "os"; servers
// with the default device policy ("attested") accept phones only.
//
// The calls are declared here rather than through the `windows` crate so the
// exact winbio.h / dpapi.h signatures are visible in one place.

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use super::{random32, Secret};
use crate::{Error, Probe, Result};

pub const METHOD: &str = "windows-winbio-fingerprint";
pub const ASSURANCE: &str = "os";

const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

// winbio_types.h / winbio_err.h
const WINBIO_TYPE_FINGERPRINT: u32 = 0x0000_0008;
const WINBIO_POOL_SYSTEM: u32 = 1;
const WINBIO_FLAG_DEFAULT: u32 = 0;
const WINBIO_DB_DEFAULT: *const Guid = 1 as *const Guid;
const WINBIO_SUBTYPE_ANY: u8 = 0xFF;
const WINBIO_ID_TYPE_SID: u32 = 3;
const SECURITY_MAX_SID_SIZE: usize = 68;

const WINBIO_E_UNSUPPORTED_FACTOR: u32 = 0x8009_8001;
const WINBIO_E_INVALID_UNIT: u32 = 0x8009_8002;
const WINBIO_E_UNKNOWN_ID: u32 = 0x8009_8003;
const WINBIO_E_CANCELED: u32 = 0x8009_8004;
const WINBIO_E_NO_MATCH: u32 = 0x8009_8005;
const WINBIO_E_BAD_CAPTURE: u32 = 0x8009_8008;

// winnt.h / dpapi.h
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

#[repr(C)]
#[allow(dead_code)] // only ever passed as the WINBIO_DB_DEFAULT sentinel
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

/// WINBIO_IDENTITY: a type tag and a union. The union is sized generously
/// (256 bytes) so it covers every member in every SDK; for a SID it holds
/// `{ ULONG Size; UCHAR Data[SECURITY_MAX_SID_SIZE]; }`.
#[repr(C)]
struct Identity {
    kind: u32,
    value: [u32; 64],
}

#[repr(C)]
struct DataBlob {
    len: u32,
    data: *mut u8,
}

#[repr(C)]
#[allow(dead_code)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[link(name = "winbio")]
unsafe extern "system" {
    fn WinBioOpenSession(
        factor: u32,
        pool: u32,
        flags: u32,
        units: *const u32,
        unit_count: usize,
        database: *const Guid,
        session: *mut u32,
    ) -> i32;
    fn WinBioCloseSession(session: u32) -> i32;
    fn WinBioVerify(
        session: u32,
        identity: *mut Identity,
        subfactor: u8,
        unit: *mut u32,
        matched: *mut u8,
        reject_detail: *mut u32,
    ) -> i32;
    fn WinBioCancel(session: u32) -> i32;
    fn WinBioEnumBiometricUnits(factor: u32, units: *mut *mut c_void, count: *mut usize) -> i32;
    fn WinBioFree(address: *mut c_void) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(token: *mut c_void, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
    fn GetLengthSid(sid: *mut c_void) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *const DataBlob,
        description: *const u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *const DataBlob,
        description: *mut *mut u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
}

fn winbio_error(hr: i32) -> Error {
    match hr as u32 {
        WINBIO_E_CANCELED => Error::Cancelled,
        WINBIO_E_NO_MATCH => Error::Platform("That fingerprint doesn't match your Windows account.".into()),
        WINBIO_E_BAD_CAPTURE => Error::Platform("Couldn't read your fingerprint. Try again.".into()),
        WINBIO_E_UNKNOWN_ID => Error::Unavailable(
            "No fingerprint is enrolled for your Windows account. Add one in Settings > Accounts > Sign-in options > Fingerprint recognition.".into(),
        ),
        WINBIO_E_UNSUPPORTED_FACTOR | WINBIO_E_INVALID_UNIT => {
            Error::Unavailable("This PC has no fingerprint reader HumID can use.".into())
        }
        other => Error::Platform(format!("Windows Biometric Framework error 0x{other:08X}.")),
    }
}

/// The signed-in user's SID, as bytes.
fn current_sid() -> Result<Vec<u8>> {
    let fail = || Error::Platform("Windows did not report the signed-in account.".into());
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(fail());
        }
        let mut buf = vec![0u64; 64]; // 512 bytes, 8-aligned: TOKEN_USER plus the SID it points to
        let mut used = 0u32;
        let ok = GetTokenInformation(token, TOKEN_USER_CLASS, buf.as_mut_ptr().cast(), 512, &mut used);
        CloseHandle(token);
        if ok == 0 {
            return Err(fail());
        }
        let user = &*(buf.as_ptr() as *const SidAndAttributes);
        let len = GetLengthSid(user.sid) as usize;
        if len == 0 || len > SECURITY_MAX_SID_SIZE {
            return Err(fail());
        }
        Ok(std::slice::from_raw_parts(user.sid as *const u8, len).to_vec())
    }
}

/// Block until the reader sees a finger enrolled to the signed-in account.
/// Gives up after a minute so a forgotten prompt doesn't hang the app.
fn verify_finger() -> Result<()> {
    let sid = current_sid()?;
    let mut identity = Identity { kind: WINBIO_ID_TYPE_SID, value: [0; 64] };
    identity.value[0] = sid.len() as u32;
    unsafe {
        let data = identity.value.as_mut_ptr().add(1).cast::<u8>();
        std::ptr::copy_nonoverlapping(sid.as_ptr(), data, sid.len());
    }

    let mut session = 0u32;
    let hr = unsafe {
        WinBioOpenSession(WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, null(), 0, WINBIO_DB_DEFAULT, &mut session)
    };
    if hr < 0 {
        return Err(winbio_error(hr));
    }

    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let done = done.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + VERIFY_TIMEOUT;
            while Instant::now() < deadline {
                if done.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            if !done.load(Ordering::SeqCst) {
                unsafe { WinBioCancel(session) };
            }
        })
    };

    let (mut unit, mut matched, mut reject) = (0u32, 0u8, 0u32);
    let hr = unsafe { WinBioVerify(session, &mut identity, WINBIO_SUBTYPE_ANY, &mut unit, &mut matched, &mut reject) };
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    unsafe { WinBioCloseSession(session) };

    if hr < 0 {
        return Err(winbio_error(hr));
    }
    if matched == 0 {
        return Err(winbio_error(WINBIO_E_NO_MATCH as i32));
    }
    Ok(())
}

fn entropy(id: &str) -> Vec<u8> {
    format!("HUMID-GATE-v2 windows {id}").into_bytes()
}

fn protect(secret: &[u8], id: &str) -> Result<Vec<u8>> {
    let ent = entropy(id);
    let input = DataBlob { len: secret.len() as u32, data: secret.as_ptr() as *mut u8 };
    let ent_blob = DataBlob { len: ent.len() as u32, data: ent.as_ptr() as *mut u8 };
    let mut out = DataBlob { len: 0, data: null_mut() };
    let ok = unsafe { CryptProtectData(&input, null(), &ent_blob, null_mut(), null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
    if ok == 0 || out.data.is_null() {
        return Err(Error::Platform("Windows could not protect the HumID key.".into()));
    }
    let v = unsafe { std::slice::from_raw_parts(out.data, out.len as usize).to_vec() };
    unsafe { LocalFree(out.data.cast()) };
    Ok(v)
}

fn unprotect(blob: &[u8], id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let ent = entropy(id);
    let input = DataBlob { len: blob.len() as u32, data: blob.as_ptr() as *mut u8 };
    let ent_blob = DataBlob { len: ent.len() as u32, data: ent.as_ptr() as *mut u8 };
    let mut out = DataBlob { len: 0, data: null_mut() };
    let ok = unsafe { CryptUnprotectData(&input, null_mut(), &ent_blob, null_mut(), null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
    if ok == 0 || out.data.is_null() {
        return Err(Error::KeyInvalidated);
    }
    let secret = unsafe {
        let s = std::slice::from_raw_parts_mut(out.data, out.len as usize);
        let v = Zeroizing::new(s.to_vec());
        s.zeroize();
        LocalFree(out.data.cast());
        v
    };
    if secret.len() != 32 {
        return Err(Error::KeyInvalidated);
    }
    Ok(secret)
}

pub fn probe() -> Result<Probe> {
    let mut units = null_mut();
    let mut count = 0usize;
    let hr = unsafe { WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, &mut units, &mut count) };
    if !units.is_null() {
        unsafe { WinBioFree(units) };
    }
    let ok = hr >= 0 && count > 0;
    Ok(Probe {
        available: ok,
        method: METHOD.into(),
        assurance: ASSURANCE.into(),
        label: "your fingerprint".into(),
        modalities: vec!["fingerprint".into()],
        proof: None,
        reason: (!ok).then(|| {
            "This PC has no fingerprint reader. HumID needs a live fingerprint here; Windows Hello isn't used because it always allows a PIN instead.".into()
        }),
    })
}

pub fn enroll(id: &str, _prompt: &str) -> Result<Secret> {
    verify_finger()?;
    let secret = random32();
    let blob = protect(&secret, id)?;
    let mut s = Secret::new(secret, "fingerprint");
    s.handle.insert("blob".into(), json!(B64.encode(blob)));
    Ok(s)
}

pub fn release(handle: &Value, id: &str, _prompt: &str) -> Result<Secret> {
    let blob = handle
        .get("blob")
        .and_then(Value::as_str)
        .and_then(|b| B64.decode(b).ok())
        .ok_or(Error::BadHandle)?;
    verify_finger()?;
    Ok(Secret::new(unprotect(&blob, id)?, "fingerprint"))
}

pub fn forget(_id: &str) -> Result<()> {
    // The secret lives only in the handle, which the app deletes with the identity.
    Ok(())
}
