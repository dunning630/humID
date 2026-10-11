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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Released {
    pub secret: String,
    pub method: String,
    pub assurance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    pub prompt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRequest {
    pub handle: Handle,
    pub prompt: Option<String>,
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
