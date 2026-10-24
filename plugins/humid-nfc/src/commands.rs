use tauri::{AppHandle, Runtime, command};

use crate::models::*;
use crate::{HumidNfcExt, Result};

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<Probe> {
    app.humid_nfc().probe().await
}

#[command]
pub(crate) async fn begin<R: Runtime>(
    app: AppHandle<R>,
    prompt: Option<String>,
    timeout_ms: Option<u64>,
    reader: Option<String>,
) -> Result<Session> {
    app.humid_nfc()
        .begin(BeginRequest {
            prompt,
            timeout_ms,
            reader,
        })
        .await
}

#[command]
pub(crate) async fn transceive<R: Runtime>(
    app: AppHandle<R>,
    session: String,
    apdu: String,
) -> Result<Response> {
    app.humid_nfc()
        .transceive(TransceiveRequest { session, apdu })
        .await
}

#[command]
pub(crate) async fn message<R: Runtime>(
    app: AppHandle<R>,
    session: String,
    message: String,
) -> Result<()> {
    app.humid_nfc()
        .message(MessageRequest { session, message })
        .await
}

#[command]
pub(crate) async fn end<R: Runtime>(
    app: AppHandle<R>,
    session: String,
    message: Option<String>,
    error: Option<String>,
) -> Result<()> {
    app.humid_nfc()
        .end(EndRequest {
            session,
            message,
            error,
        })
        .await
}
