// The commands the camera screen calls. Each request is checked (validate.rs) before it
// reaches native code; requests for a camera that isn't open are refused here.

use tauri::{AppHandle, Runtime, State as TauriState, command, ipc::Channel};

use crate::models::*;
use crate::{Error, HumidDocscanExt, Result, State, validate};

fn opened(state: &State) -> Result<Size> {
    state
        .0
        .lock()
        .map_err(|_| Error::NotOpen)?
        .view
        .ok_or(Error::NotOpen)
}

fn set_view(state: &State, view: Option<Size>) {
    if let Ok(mut s) = state.0.lock() {
        s.view = view;
    }
}

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<Probe> {
    app.humid_docscan().probe().await
}

#[command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
    shape: Shape,
    read: Option<Reads>,
    frame: Rect,
    view: Size,
    auto: Option<bool>,
    haptics: Option<bool>,
    events: Channel<serde_json::Value>,
) -> Result<Opened> {
    let view = validate::view(&view)?;
    let frame = validate::frame(&frame, &view)?;
    let req = OpenRequest {
        shape,
        read: read.unwrap_or_default(),
        frame,
        view,
        auto: auto.unwrap_or(true),
        haptics: haptics.unwrap_or(true),
        events,
    };
    let out = app.humid_docscan().open(req).await?;
    validate::id(&out.session)?;
    set_view(&state, Some(view));
    Ok(out)
}

#[command]
pub(crate) async fn frame<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
    frame: Rect,
    view: Size,
) -> Result<()> {
    opened(&state)?;
    let view = validate::view(&view)?;
    let frame = validate::frame(&frame, &view)?;
    app.humid_docscan()
        .frame(FrameRequest { frame, view })
        .await?;
    set_view(&state, Some(view));
    Ok(())
}

#[command]
pub(crate) async fn focus<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
    x: f64,
    y: f64,
) -> Result<()> {
    let view = opened(&state)?;
    let p = validate::point(&Point { x, y }, &view)?;
    app.humid_docscan()
        .focus(FocusRequest { x: p.x, y: p.y })
        .await
}

#[command]
pub(crate) async fn torch<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
    on: bool,
) -> Result<TorchState> {
    opened(&state)?;
    app.humid_docscan().torch(TorchRequest { on }).await
}

#[command]
pub(crate) async fn capture<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
) -> Result<StillMeta> {
    opened(&state)?;
    let meta = app.humid_docscan().capture().await?;
    validate::id(&meta.id)?;
    Ok(meta)
}

/// The still's JPEG, as raw bytes (an ArrayBuffer in the web view): once per picture, then
/// native forgets it.
#[command]
pub(crate) async fn take<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
    id: String,
    which: Which,
) -> Result<tauri::ipc::Response> {
    opened(&state)?;
    validate::id(&id)?;
    let taken = app.humid_docscan().take(TakeRequest { id, which }).await?;
    let bytes = validate::jpeg_b64(&taken.data)?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[command]
pub(crate) async fn pause<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
) -> Result<()> {
    opened(&state)?;
    app.humid_docscan().pause().await
}

#[command]
pub(crate) async fn resume<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
) -> Result<()> {
    opened(&state)?;
    app.humid_docscan().resume().await
}

/// Always allowed (closing a camera that isn't open does nothing).
#[command]
pub(crate) async fn close<R: Runtime>(
    app: AppHandle<R>,
    state: TauriState<'_, State>,
) -> Result<()> {
    set_view(&state, None);
    app.humid_docscan().close().await
}
