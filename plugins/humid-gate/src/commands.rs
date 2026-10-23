use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::{HumidGateExt, Result};

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<Probe> {
    app.humid_gate().probe().await
}

#[command]
pub(crate) async fn enroll<R: Runtime>(
    app: AppHandle<R>,
    prompt: Option<String>,
    challenge: Option<String>,
    attest: Option<String>,
) -> Result<Enrolled> {
    app.humid_gate().enroll(EnrollRequest { prompt, challenge, attest }).await
}

#[command]
pub(crate) async fn release<R: Runtime>(
    app: AppHandle<R>,
    handle: Handle,
    prompt: Option<String>,
    challenge: Option<String>,
    attest: Option<String>,
) -> Result<Released> {
    app.humid_gate().release(ReleaseRequest { handle, prompt, challenge, attest }).await
}

#[command]
pub(crate) async fn forget<R: Runtime>(app: AppHandle<R>, handle: Handle) -> Result<()> {
    app.humid_gate().forget(ForgetRequest { handle }).await
}

/// Android: the accessibility services switched on (APP-09). Other platforms: none.
#[command]
pub(crate) async fn enabled_accessibility_services<R: Runtime>(app: AppHandle<R>) -> Result<AccessibilityServices> {
    app.humid_gate().enabled_accessibility_services().await
}
