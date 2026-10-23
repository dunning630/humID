// macOS, Windows, Linux. Each OS module exposes the same four blocking
// functions; this file runs them off the async runtime and wraps the secret.
//
// Every desktop gate is biometric-only (Touch ID, a fingerprint reader), but
// none has a liveness key the server can verify, so `challenge` and `attest`
// are ignored and `live` is never returned. Servers decide whether to accept
// such devices (HUMID_DEVICE_POLICY=biometric) or not (attested, the default).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::de::DeserializeOwned;
use serde_json::json;
use tauri::{plugin::PluginApi, AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::models::*;
use crate::{Error, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
use windows as os;

/// What an OS backend returns from enroll/release.
pub(crate) struct Secret {
    pub bytes: Zeroizing<Vec<u8>>,
    pub detail: Option<serde_json::Value>,
    /// Extra fields to store in the handle at enrolment (Windows keeps its
    /// DPAPI blob there). Ignored on release.
    pub handle: serde_json::Map<String, serde_json::Value>,
}

impl Secret {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>, factor: &str) -> Self {
        Secret { bytes, detail: Some(json!({ "factor": factor })), handle: Default::default() }
    }
}

pub(crate) fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random source");
    B64.encode(b)
}

pub(crate) fn random32() -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(vec![0u8; 32]);
    getrandom::fill(&mut v).expect("OS random source");
    v
}

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> Result<HumidGate<R>> {
    Ok(HumidGate(app.clone()))
}

pub struct HumidGate<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| Error::Platform(format!("gate worker failed: {e}")))?
}

impl<R: Runtime> HumidGate<R> {
    pub async fn probe(&self) -> Result<Probe> {
        blocking(os::probe).await
    }

    pub async fn enroll(&self, req: EnrollRequest) -> Result<Enrolled> {
        let prompt = req.prompt.unwrap_or_else(|| "Bind your HumID identity to this device".into());
        let id = new_id();
        let (handle, s) = blocking(move || {
            let mut s = os::enroll(&id, &prompt)?;
            let mut handle = std::mem::take(&mut s.handle);
            handle.insert("id".into(), json!(id));
            Ok((serde_json::Value::Object(handle), s))
        })
        .await?;
        Ok(Enrolled {
            handle,
            secret: B64.encode(&*s.bytes),
            method: os::METHOD.into(),
            assurance: os::ASSURANCE.into(),
            detail: s.detail,
            live: None,
        })
    }

    pub async fn release(&self, req: ReleaseRequest) -> Result<Released> {
        let id = handle_id(&req.handle)?;
        let prompt = req.prompt.unwrap_or_else(|| "Confirm it's you".into());
        let handle = req.handle;
        let s = blocking(move || os::release(&handle, &id, &prompt)).await?;
        Ok(Released {
            secret: B64.encode(&*s.bytes),
            method: os::METHOD.into(),
            assurance: os::ASSURANCE.into(),
            detail: s.detail,
            live: None,
            handle: None,
        })
    }

    pub async fn forget(&self, req: ForgetRequest) -> Result<()> {
        let id = handle_id(&req.handle)?;
        blocking(move || os::forget(&id)).await
    }

    /// Desktops: not listed (the warning is an Android one).
    pub async fn enabled_accessibility_services(&self) -> Result<AccessibilityServices> {
        Ok(AccessibilityServices::default())
    }
}
