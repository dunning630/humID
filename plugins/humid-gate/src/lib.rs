//! tauri-plugin-humid-gate — the native biometric interrupt for HumID.
//!
//! One contract, five implementations. Each releases a 32-byte secret only
//! after the operating system has verified the user biometrically:
//!
//! | Platform | Key store                                   | Assurance |
//! |----------|---------------------------------------------|-----------|
//! | iOS      | Keychain, `.biometryCurrentSet` (Swift)     | hardware  |
//! | Android  | Keystore AES key, BIOMETRIC_STRONG (Kotlin) | hardware  |
//! | macOS    | Keychain, `.biometryCurrentSet`             | hardware  |
//! | Windows  | Windows Hello KeyCredential                 | hardware  |
//! | Linux    | fprintd match + Secret Service keyring      | os        |
//!
//! The plugin is versioned on its own (`humid-gate@1`). The JS side
//! (`@humid/gate`, adapter "native") depends on the command names and the
//! response shapes in `models.rs`, nothing else.

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
pub use models::*;

#[cfg(desktop)]
use desktop::HumidGate;
#[cfg(mobile)]
use mobile::HumidGate;

/// Access the gate from Rust code in the shell.
pub trait HumidGateExt<R: Runtime> {
    fn humid_gate(&self) -> &HumidGate<R>;
}

impl<R: Runtime, T: Manager<R>> HumidGateExt<R> for T {
    fn humid_gate(&self) -> &HumidGate<R> {
        self.state::<HumidGate<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("humid-gate")
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::enroll,
            commands::release,
            commands::forget
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let gate = mobile::init(app, api)?;
            #[cfg(desktop)]
            let gate = desktop::init(app, api)?;
            app.manage(gate);
            Ok(())
        })
        .build()
}
