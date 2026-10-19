use serde::{Deserialize, Serialize};

/// Can this phone open the document scanner?
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    /// The longest side of the page handed back, in pixels (default 3200).
    pub max_side: Option<u32>,
}

/// One flattened page: a JPEG, base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub data: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
}
