// iOS and Android: forward to the Swift / Kotlin readers.

use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_humid_nfc);

pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<HumidNfc<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("app.humid.nfc", "HumidNfcPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_humid_nfc)?;
    Ok(HumidNfc(handle))
}

pub struct HumidNfc<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> HumidNfc<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(self.0.run_mobile_plugin_async("probe", ()).await?)
    }
    pub async fn begin(&self, req: BeginRequest) -> crate::Result<Session> {
        Ok(self.0.run_mobile_plugin_async("begin", req).await?)
    }
    pub async fn transceive(&self, req: TransceiveRequest) -> crate::Result<Response> {
        Ok(self.0.run_mobile_plugin_async("transceive", req).await?)
    }
    pub async fn message(&self, req: MessageRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("message", req).await?;
        Ok(())
    }
    pub async fn cancel(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("cancel", ()).await?;
        Ok(())
    }
    pub async fn end(&self, req: EndRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("end", req).await?;
        Ok(())
    }
}
