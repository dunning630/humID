// Computers: no native camera. The app uses the web view's own camera (getUserMedia).

use serde::de::DeserializeOwned;
use tauri::{AppHandle, Runtime, plugin::PluginApi};

use crate::Error;
use crate::models::*;

const WHY: &str = "The native document camera is only on iPhone and Android.";

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<HumidDocscan<R>> {
    Ok(HumidDocscan(app.clone()))
}

pub struct HumidDocscan<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

fn no<T>() -> crate::Result<T> {
    Err(Error::Unavailable(WHY.into()))
}

impl<R: Runtime> HumidDocscan<R> {
    pub async fn probe(&self) -> crate::Result<Probe> {
        Ok(Probe {
            available: false,
            reason: Some(WHY.into()),
            ..Default::default()
        })
    }
    pub(crate) async fn open(&self, _req: OpenRequest) -> crate::Result<Opened> {
        no()
    }
    pub(crate) async fn frame(&self, _req: FrameRequest) -> crate::Result<()> {
        no()
    }
    pub(crate) async fn focus(&self, _req: FocusRequest) -> crate::Result<()> {
        no()
    }
    pub(crate) async fn torch(&self, _req: TorchRequest) -> crate::Result<TorchState> {
        no()
    }
    pub(crate) async fn capture(&self) -> crate::Result<StillMeta> {
        no()
    }
    pub(crate) async fn take(&self, _req: TakeRequest) -> crate::Result<Taken> {
        no()
    }
    pub(crate) async fn pause(&self) -> crate::Result<()> {
        no()
    }
    pub(crate) async fn resume(&self) -> crate::Result<()> {
        no()
    }
    pub(crate) async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}
