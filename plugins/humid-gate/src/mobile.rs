// iOS and Android: forward to the Swift / Kotlin implementations, which own
// the system biometric prompt and the hardware key store.

use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_humid_gate);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<HumidGate<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("app.humid.gate", "HumidGatePlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_humid_gate)?;
    Ok(HumidGate(handle))
}

pub struct HumidGate<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> HumidGate<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(self.0.run_mobile_plugin_async("probe", ()).await?)
    }

    pub async fn enroll(&self, req: EnrollRequest) -> crate::Result<Enrolled> {
        Ok(self.0.run_mobile_plugin_async("enroll", req).await?)
    }

    pub async fn release(&self, req: ReleaseRequest) -> crate::Result<Released> {
        handle_id(&req.handle)?;
        Ok(self.0.run_mobile_plugin_async("release", req).await?)
    }

    pub async fn forget(&self, req: ForgetRequest) -> crate::Result<()> {
        handle_id(&req.handle)?;
        self.0.run_mobile_plugin_async::<serde_json::Value>("forget", req).await?;
        Ok(())
    }

    /// Android lists them; iOS has no API for other apps' accessibility access, so none.
    pub async fn enabled_accessibility_services(&self) -> crate::Result<AccessibilityServices> {
        #[cfg(target_os = "android")]
        return Ok(self.0.run_mobile_plugin_async("enabledAccessibilityServices", ()).await?);
        #[cfg(not(target_os = "android"))]
        Ok(AccessibilityServices::default())
    }
}
