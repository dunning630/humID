// macOS: a random 32-byte secret in the data-protection keychain with access
// control .biometryCurrentSet. macOS will only hand it back after a Touch ID
// match (the login password cannot stand in for it), and the item is
// destroyed if the enrolled fingerprints change. There is no attestation for
// Mac apps, so the server sees this as a biometric-only desktop ("os").
//
// Requires a signed build with the keychain-access-groups entitlement
// (shell/src-tauri/Entitlements.plist); unsigned builds get errSecMissingEntitlement.

use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{delete_generic_password_options, generic_password, set_generic_password_options};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
use core_foundation::base::TCFType;
use core_foundation::string::{CFString, CFStringRef};
use zeroize::Zeroizing;

use super::{random32, Secret};
use crate::{Error, Probe, Result};

pub const METHOD: &str = "macos-keychain-biometry";
pub const ASSURANCE: &str = "os";
const SERVICE: &str = "app.humid.gate";

// Not exported by security-framework-sys; declared here from Security.framework.
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecUseOperationPrompt: CFStringRef;
}

const ERR_USER_CANCELED: i32 = -128;
const ERR_ITEM_NOT_FOUND: i32 = -25300;
const ERR_AUTH_FAILED: i32 = -25293;
const ERR_MISSING_ENTITLEMENT: i32 = -34018;

fn options(id: &str) -> PasswordOptions {
    let mut o = PasswordOptions::new_generic_password(SERVICE, id);
    o.use_protected_keychain();
    o
}

fn map(e: security_framework::base::Error) -> Error {
    match e.code() {
        ERR_USER_CANCELED => Error::Cancelled,
        ERR_ITEM_NOT_FOUND => Error::KeyInvalidated,
        ERR_AUTH_FAILED => Error::Platform("Touch ID did not match.".into()),
        ERR_MISSING_ENTITLEMENT => Error::Unavailable(
            "This build is not signed with the keychain entitlement, so Touch ID keys cannot be stored.".into(),
        ),
        _ => Error::Platform(format!("Keychain error {}: {}", e.code(), e)),
    }
}

pub fn probe() -> Result<Probe> {
    let ctx = unsafe { LAContext::new() };
    let ok = unsafe { ctx.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }.is_ok();
    Ok(Probe {
        available: ok,
        method: METHOD.into(),
        assurance: ASSURANCE.into(),
        label: "Touch ID".into(),
        modalities: vec!["fingerprint".into()],
        proof: None,
        reason: (!ok).then(|| "Touch ID is not available or has no fingerprints enrolled on this Mac.".into()),
    })
}

fn read(id: &str, prompt: &str) -> Result<Secret> {
    let mut o = options(id);
    o.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) },
        CFString::new(prompt).into_CFType(),
    ));
    let bytes = generic_password(o).map_err(map)?;
    if bytes.len() != 32 {
        return Err(Error::KeyInvalidated);
    }
    Ok(Secret::new(Zeroizing::new(bytes), "fingerprint"))
}

pub fn enroll(id: &str, prompt: &str) -> Result<Secret> {
    let secret = random32();
    let mut o = options(id);
    let ac = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(map)?;
    o.set_access_control(ac);
    set_generic_password_options(&secret, o).map_err(map)?;
    // Read it straight back so enrolment itself requires a Touch ID match.
    read(id, prompt)
}

pub fn release(_handle: &serde_json::Value, id: &str, prompt: &str) -> Result<Secret> {
    read(id, prompt)
}

pub fn forget(id: &str) -> Result<()> {
    match delete_generic_password_options(options(id)) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERR_ITEM_NOT_FOUND => Ok(()),
        Err(e) => Err(map(e)),
    }
}
