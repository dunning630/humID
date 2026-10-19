// Android: forward to the Kotlin scanner. Everywhere else: unavailable, so the app
// uses its own camera.

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

#[cfg(target_os = "android")]
pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<HumidDocscan<R>> {
    let handle = api.register_android_plugin("app.humid.docscan", "HumidDocscanPlugin")?;
    Ok(HumidDocscan(handle))
}

#[cfg(target_os = "android")]
pub struct HumidDocscan<R: Runtime>(tauri::plugin::PluginHandle<R>);

#[cfg(target_os = "android")]
impl<R: Runtime> HumidDocscan<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(self.0.run_mobile_plugin_async("probe", ()).await?)
    }
    pub async fn scan(&self, req: ScanRequest) -> crate::Result<Page> {
        Ok(self.0.run_mobile_plugin_async("scan", req).await?)
    }
}

#[cfg(not(target_os = "android"))]
const WHY: &str = "The phone's document scanner is only on Android.";

#[cfg(not(target_os = "android"))]
pub fn init<R: Runtime, C: DeserializeOwned>(app: &AppHandle<R>, _api: PluginApi<R, C>) -> crate::Result<HumidDocscan<R>> {
    Ok(HumidDocscan(app.clone()))
}

#[cfg(not(target_os = "android"))]
pub struct HumidDocscan<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

#[cfg(not(target_os = "android"))]
impl<R: Runtime> HumidDocscan<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(Probe { available: false, reason: Some(WHY.into()) })
    }
    pub async fn scan(&self, _req: ScanRequest) -> crate::Result<Page> {
        Err(crate::Error::Unavailable(WHY.into()))
    }
}
