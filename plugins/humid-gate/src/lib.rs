//! tauri-plugin-humid-gate — the native biometric interrupt for HumID.
//!
//! One contract, five implementations. Each releases a 32-byte secret only
//! after a LIVE biometric check (face or fingerprint). No implementation
//! accepts a PIN, password or passcode instead.
//!
//! | Platform | Secret                               | Liveness key, proof               | Assurance |
//! |----------|--------------------------------------|-----------------------------------|-----------|
//! | iOS      | Keychain, `.biometryCurrentSet`      | Secure Enclave P-256, App Attest  | hardware  |
//! | Android  | Keystore AES, BIOMETRIC_STRONG       | Keystore P-256 per use, key attestation | hardware |
//! | macOS    | Keychain, `.biometryCurrentSet`      | none                              | os        |
//! | Windows  | DPAPI, released after a WinBio match | none                              | os        |
//! | Linux    | Secret Service, after an fprintd match | none                            | os        |
//!
//! On phones the liveness key signs each request's challenge inside the same
//! check that releases the secret, and is attested to the server when a
//! device is added, so the server can tell a real live check from a bot.
//!
//! The plugin is versioned on its own (`humid-gate@2`). The JS side
//! (`@humid/gate`, adapter "native") depends on the command names and the
//! request / response shapes in `models.rs`, nothing else.

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
            commands::forget,
            commands::enabled_accessibility_services
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
