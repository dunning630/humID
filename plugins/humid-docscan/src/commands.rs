use tauri::{AppHandle, Runtime, command};

use crate::models::*;
use crate::{HumidDocscanExt, Result};

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<Probe> {
    app.humid_docscan().probe().await
}

#[command]
pub(crate) async fn scan<R: Runtime>(app: AppHandle<R>, max_side: Option<u32>) -> Result<Page> {
    app.humid_docscan().scan(ScanRequest { max_side }).await
}
