use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Result of checking whether this device can run the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub available: bool,
    /// Stable method id written into every envelope's interrupt record.
    pub method: String,
    /// "hardware" | "os" | "none"
    pub assurance: String,
    pub label: String,
    /// Which live biometrics the sensor offers: "face", "fingerprint".
    #[serde(default)]
    pub modalities: Vec<String>,
    /// How the device can prove its checks to the server: "android-key",
    /// "apple-app-attest", or none (desktops).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What the phone's secure chip produced during one live check:
/// `{ pub, sig, attestation? }`, all base64. `pub` is the liveness key
/// (P-256, SubjectPublicKeyInfo DER), `sig` its ECDSA-SHA256 signature over
/// the request's challenge, and `attestation` (only when `attest` was sent)
/// either `{ kind: "android-key", chain: [cert DER…] }` or
/// `{ kind: "apple-app-attest", object }`. Desktops never return one.
pub type Live = Value;

/// Opaque data the gate needs to find its key again. Always has an `id`;
/// platforms add fields (Android stores its wrapped secret here). The JS side
/// persists it with the identity and hands it back unchanged.
pub type Handle = Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrolled {
    pub handle: Handle,
    /// Base64 of the 32-byte gate secret.
    pub secret: String,
    pub method: String,
    pub assurance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<Live>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Released {
    pub secret: String,
    pub method: String,
    pub assurance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<Live>,
    /// A replacement for the handle that was passed in, when the platform moved the
    /// secret to a new key during this release (Android: a 2.0 time-bound key to a
    /// per-use one). The caller stores it in place of the old handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<Handle>,
}

/// `challenge`: base64 bytes the liveness key signs during the check (known
/// before the prompt opens). `attest`: base64 bytes to attest a NEW liveness
/// key to (the HTP session transcript); sent only when a device is added.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    pub prompt: Option<String>,
    pub challenge: Option<String>,
    pub attest: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRequest {
    pub handle: Handle,
    pub prompt: Option<String>,
    pub challenge: Option<String>,
    pub attest: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgetRequest {
    pub handle: Handle,
}

pub(crate) fn handle_id(handle: &Handle) -> crate::Result<String> {
    handle
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(str::to_owned)
        .ok_or(crate::Error::BadHandle)
}
