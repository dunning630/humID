// iOS and Android: forward to the Swift / Kotlin camera.

use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_humid_docscan);

pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<HumidDocscan<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("app.humid.docscan", "HumidDocscanPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_humid_docscan)?;
    Ok(HumidDocscan(handle))
}

pub struct HumidDocscan<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> HumidDocscan<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(self.0.run_mobile_plugin_async("probe", ()).await?)
    }
    pub(crate) async fn open(&self, req: OpenRequest) -> crate::Result<Opened> {
        Ok(self.0.run_mobile_plugin_async("open", req).await?)
    }
    pub(crate) async fn frame(&self, req: FrameRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("frame", req).await?;
        Ok(())
    }
    pub(crate) async fn focus(&self, req: FocusRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("focus", req).await?;
        Ok(())
    }
    pub(crate) async fn torch(&self, req: TorchRequest) -> crate::Result<TorchState> {
        Ok(self.0.run_mobile_plugin_async("torch", req).await?)
    }
    pub(crate) async fn capture(&self) -> crate::Result<StillMeta> {
        Ok(self.0.run_mobile_plugin_async("capture", ()).await?)
    }
    pub(crate) async fn take(&self, req: TakeRequest) -> crate::Result<Taken> {
        Ok(self.0.run_mobile_plugin_async("take", req).await?)
    }
    pub(crate) async fn pause(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("pause", ()).await?;
        Ok(())
    }
    pub(crate) async fn resume(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("resume", ()).await?;
        Ok(())
    }
    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin_async::<serde_json::Value>("close", ()).await?;
        Ok(())
    }
}
