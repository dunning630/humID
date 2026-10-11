use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::{HumidGateExt, Result};

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<Probe> {
    app.humid_gate().probe().await
}

#[command]
pub(crate) async fn enroll<R: Runtime>(app: AppHandle<R>, prompt: Option<String>) -> Result<Enrolled> {
    app.humid_gate().enroll(EnrollRequest { prompt }).await
}

#[command]
pub(crate) async fn release<R: Runtime>(
    app: AppHandle<R>,
    handle: Handle,
    prompt: Option<String>,
) -> Result<Released> {
    app.humid_gate().release(ReleaseRequest { handle, prompt }).await
}

#[command]
pub(crate) async fn forget<R: Runtime>(app: AppHandle<R>, handle: Handle) -> Result<()> {
    app.humid_gate().forget(ForgetRequest { handle }).await
}
