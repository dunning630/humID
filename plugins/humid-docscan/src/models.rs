use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;

/// A rectangle in CSS pixels of the web view (the frame the person lines the document up in).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// The web view's size in CSS pixels (innerWidth × innerHeight), so native can scale CSS pixels
/// to its own view's points or pixels without guessing the page zoom.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Size {
    pub w: f64,
    pub h: f64,
}

/// A point in CSS pixels (a tap).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

/// What the document is: a card (ID-1), a passport's photo page (ID-3), a sheet of paper, or
/// anything at all (no outline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    Id1,
    Td3,
    Page,
    Full,
}

/// What to read while the camera runs. The raw text goes to the app, which parses it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reads {
    #[serde(default)]
    pub pdf417: bool,
    #[serde(default)]
    pub mrz: bool,
    /// The photo waits for the text (a license's back, a passport page), at most 2.5 s once lined
    /// up. Off for a side that only looks out for the other side (a license front showing its barcode).
    #[serde(default)]
    pub require: bool,
}

/// Which picture `take` hands over: the document cut out, or the whole frame (Photo and Page
/// keep it as the "Original").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Which {
    Doc,
    Full,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub available: bool,
    #[serde(default)]
    pub lenses: Vec<String>,
    /// Close focus through a second lens (the iPhone's ultra-wide "macro").
    #[serde(default, rename = "macro")]
    pub macro_lens: bool,
    #[serde(default)]
    pub torch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_focus_mm: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opened {
    pub session: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorchState {
    pub on: bool,
}

/// What the shutter gave (the same as the `captured` event, without the freeze picture).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StillMeta {
    pub id: String,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
}

/* ---------------- requests to the Swift / Kotlin side ---------------- */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenRequest {
    pub shape: Shape,
    pub read: Reads,
    pub frame: Rect,
    pub view: Size,
    pub auto: bool,
    pub haptics: bool,
    pub events: Channel<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct FrameRequest {
    pub frame: Rect,
    pub view: Size,
}

#[derive(Serialize)]
pub(crate) struct FocusRequest {
    pub x: f64,
    pub y: f64,
}

#[derive(Serialize)]
pub(crate) struct TorchRequest {
    pub on: bool,
}

#[derive(Serialize)]
pub(crate) struct TakeRequest {
    pub id: String,
    pub which: Which,
}

/// `take`'s answer from native: the JPEG as base64 (fast in Swift and Kotlin), turned into raw
/// bytes here so the web view never decodes base64.
#[derive(Deserialize)]
pub(crate) struct Taken {
    pub data: String,
}
