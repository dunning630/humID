//! tauri-plugin-humid-nfc — the chip reader transport for HumID.
//!
//! It only moves bytes: open a session with a chip (a passport or ID card, or a
//! contactless payment card), send command APDUs, return response APDUs, close;
//! or `cancel` to stop waiting when the screen that asked goes away. All of ICAO 9303 (BAC, PACE,
//! secure messaging, files, Active Authentication) is done by `@humid/emrtd`
//! in the shared JS, the same on every platform.
//!
//! | Platform | Reader                                         |
//! |----------|------------------------------------------------|
//! | iOS      | Core NFC `NFCTagReaderSession`, ISO 7816 tags   |
//! | Android  | `NfcAdapter` reader mode, `IsoDep`             |
//! | Windows  | PC/SC (WinSCard): USB or built-in contactless  |
//! | macOS    | PC/SC (CryptoTokenKit): USB contactless reader |
//! | Linux    | not yet (needs libpcsclite at run time)        |
//!
//! Versioned on its own (`humid-nfc@1`; 1.1 adds `cancel`).

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

mod commands;
mod error;
mod models;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

pub use error::{Error, Result};

/// The desktop reader without Tauri, for the hardware-in-the-loop test (examples/apdu-bridge.rs).
#[cfg(desktop)]
#[doc(hidden)]
pub mod reader {
    pub use crate::desktop::pcsc_reader::{begin, cancel, end, probe, transceive};
}
pub use models::*;

#[cfg(desktop)]
use desktop::HumidNfc;
#[cfg(mobile)]
use mobile::HumidNfc;

pub trait HumidNfcExt<R: Runtime> {
    fn humid_nfc(&self) -> &HumidNfc<R>;
}

impl<R: Runtime, T: Manager<R>> HumidNfcExt<R> for T {
    fn humid_nfc(&self) -> &HumidNfc<R> {
        self.state::<HumidNfc<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("humid-nfc")
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::begin,
            commands::transceive,
            commands::message,
            commands::end,
            commands::cancel
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let nfc = mobile::init(app, api)?;
            #[cfg(desktop)]
            let nfc = desktop::init(app, api)?;
            app.manage(nfc);
            Ok(())
        })
        .build()
}
