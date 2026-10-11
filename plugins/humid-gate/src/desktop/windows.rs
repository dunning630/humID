// Windows: Windows Hello KeyCredential. Enrolment creates an RSA key held by
// Windows Hello (in the TPM when the machine has one). Each release asks
// Hello to sign a fixed HumID challenge; RSA PKCS#1 v1.5 signatures are
// deterministic, so SHA-256 of the signature is a stable secret that only a
// Hello-verified user can reproduce.
//
// Windows Hello accepts the user's PIN as well as face or fingerprint, and the
// API does not let an app insist on biometrics. The interrupt record says so
// (factor: "biometric-or-pin").

use sha2::{Digest, Sha256};
use windows::core::{Array, HSTRING};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use zeroize::Zeroizing;

use super::Secret;
use crate::{Error, Probe, Result};

pub const METHOD: &str = "windows-hello-keycredential";
pub const ASSURANCE: &str = "hardware";
const CHALLENGE: &[u8] = b"HUMID-GATE-v1 windows-hello release";

fn name(id: &str) -> HSTRING {
    HSTRING::from(format!("HumID-{id}"))
}

fn plat(e: windows::core::Error) -> Error {
    Error::Platform(format!("Windows Hello: {}", e.message()))
}

fn status(s: KeyCredentialStatus) -> Result<()> {
    match s {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => Err(Error::Cancelled),
        KeyCredentialStatus::NotFound => Err(Error::KeyInvalidated),
        KeyCredentialStatus::SecurityDeviceLocked => Err(Error::Platform("Windows Hello is locked after too many attempts.".into())),
        _ => Err(Error::Platform("Windows Hello could not verify you.".into())),
    }
}

fn sign(cred: &KeyCredential) -> Result<Secret> {
    let challenge = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(plat)?;
    let r = cred.RequestSignAsync(&challenge).map_err(plat)?.join().map_err(plat)?;
    status(r.Status().map_err(plat)?)?;
    let sig = r.Result().map_err(plat)?;
    let mut raw = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&sig, &mut raw).map_err(plat)?;
    let digest = Sha256::digest(&raw[..]);
    Ok(Secret {
        bytes: Zeroizing::new(digest.to_vec()),
        detail: Some(serde_json::json!({ "factor": "biometric-or-pin" })),
    })
}

pub fn probe() -> Result<Probe> {
    let ok = KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.join())
        .unwrap_or(false);
    Ok(Probe {
        available: ok,
        method: METHOD.into(),
        assurance: ASSURANCE.into(),
        label: "Windows Hello".into(),
        reason: (!ok).then(|| "Windows Hello is not set up on this PC. Set it up in Settings > Accounts > Sign-in options.".into()),
    })
}

pub fn enroll(id: &str, _prompt: &str) -> Result<Secret> {
    let r = KeyCredentialManager::RequestCreateAsync(&name(id), KeyCredentialCreationOption::ReplaceExisting)
        .map_err(plat)?
        .join()
        .map_err(plat)?;
    status(r.Status().map_err(plat)?)?;
    sign(&r.Credential().map_err(plat)?)
}

pub fn release(id: &str, _prompt: &str) -> Result<Secret> {
    let r = KeyCredentialManager::OpenAsync(&name(id)).map_err(plat)?.join().map_err(plat)?;
    status(r.Status().map_err(plat)?)?;
    sign(&r.Credential().map_err(plat)?)
}

pub fn forget(id: &str) -> Result<()> {
    // Deleting a credential that is already gone is fine.
    let _ = KeyCredentialManager::DeleteAsync(&name(id)).map(|op| op.join());
    Ok(())
}
