//! tauri-plugin-humid-docscan — document capture for HumID on Android.
//!
//! Opens the phone's own document scanner (ML Kit through Google Play services) for
//! one page: it finds the document's edges, takes the photo when it is steady, and
//! flattens it. The page comes back to the app as JPEG bytes and the scanner's file is
//! deleted. Everything runs on the phone; the picture is never sent anywhere. Reading
//! the barcode or MRZ and sealing the photo stay in the shared JS, as for any photo.
//!
//! | Platform        | Capture                                               |
//! |-----------------|-------------------------------------------------------|
//! | Android         | ML Kit document scanner, "base" mode (crop and turn)  |
//! | iPhone, desktop | unavailable: the app uses its own camera              |
//!
//! Versioned on its own (`humid-docscan@1`).

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

mod commands;
mod error;
mod models;
mod platform;

pub use error::{Error, Result};
pub use models::*;

use platform::HumidDocscan;

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
        .invoke_handler(tauri::generate_handler![commands::probe, commands::scan])
        .setup(|app, api| {
            let scanner = platform::init(app, api)?;
            app.manage(scanner);
            Ok(())
        })
        .build()
}
