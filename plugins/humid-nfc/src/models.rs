use serde::{Deserialize, Serialize};

/// Can this device read a chip? `kind`: "phone" (built-in NFC), "reader" (PC/SC), "none".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub available: bool,
    pub kind: String,
    #[serde(default)]
    pub readers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginRequest {
    /// Shown by the system sheet on iPhone while it waits for the document.
    pub prompt: Option<String>,
    /// How long to wait for a document, in milliseconds (default 60 s).
    pub timeout_ms: Option<u64>,
    /// Desktop: which PC/SC reader (default: the first contactless one).
    pub reader: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransceiveRequest {
    pub session: String,
    /// The command APDU, base64.
    pub apdu: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// The response APDU including SW1 SW2, base64.
    pub response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRequest {
    pub session: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndRequest {
    pub session: String,
    /// Shown as the outcome on iPhone (success message, or an error).
    pub message: Option<String>,
    pub error: Option<String>,
}
