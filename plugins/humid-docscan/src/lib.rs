//! tauri-plugin-humid-docscan — HumID's document camera (`humid-docscan@2`).
//!
//! The camera runs natively, under a transparent web view; the app's own camera screen
//! (Preact) stays on top and draws the frame, the words and the buttons. Native code owns the
//! camera, focus, exposure, torch, lens and zoom, finds the document, judges sharp and steady,
//! reads the PDF417 barcode and the MRZ lines as raw text, takes a zero-shutter-lag still and
//! cuts the document out of it. The app gets events (what to say) and, once per photo, the
//! cut-out JPEG; it parses, checks and seals as for any photo.
//!
//! | Platform | Camera                                                                 |
//! |----------|------------------------------------------------------------------------|
//! | iOS 26+  | AVFoundation (virtual device, held on the wide lens for cards), Vision |
//! | Android 17+ | CameraX, zxing-cpp for PDF417                                       |
//! | desktop  | unavailable: the app uses the web view's camera                        |
//!
//! It holds no secrets: no key ever reaches it, frames stay in memory, and a still is
//! handed over once and then forgotten.

use std::sync::Mutex;

use tauri::{
    Manager, Runtime,
    plugin::{Builder, TauriPlugin},
};

mod commands;
mod error;
mod models;
mod validate;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

pub use error::{Error, Result};
pub use models::*;

#[cfg(desktop)]
use desktop::HumidDocscan;
#[cfg(mobile)]
use mobile::HumidDocscan;

/// What Rust remembers about the open camera, to check later requests against.
#[derive(Default)]
pub(crate) struct Open {
    /// The web view's size when the camera was opened or its frame last changed.
    pub view: Option<Size>,
}

pub(crate) struct State(pub Mutex<Open>);

pub trait HumidDocscanExt<R: Runtime> {
    fn humid_docscan(&self) -> &HumidDocscan<R>;
}

impl<R: Runtime, T: Manager<R>> HumidDocscanExt<R> for T {
    fn humid_docscan(&self) -> &HumidDocscan<R> {
        self.state::<HumidDocscan<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("humid-docscan")
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::open,
            commands::frame,
            commands::focus,
            commands::torch,
            commands::capture,
            commands::take,
            commands::pause,
            commands::resume,
            commands::close
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let cam = mobile::init(app, api)?;
            #[cfg(desktop)]
            let cam = desktop::init(app, api)?;
            app.manage(cam);
            app.manage(State(Mutex::new(Open::default())));
            Ok(())
        })
        .build()
}
