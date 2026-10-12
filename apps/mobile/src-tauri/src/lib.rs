//! HumID native shell. Deliberately thin: it hosts the web modules, registers
//! the biometric gate plugin and offers one command for saving files. Feature
//! work happens in the modules and the plugin, so the shell itself rarely
//! needs a new release.

use std::io::Write;

use percent_encoding::percent_decode_str;
use tauri::ipc::{InvokeBody, Request};
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_fs::{FsExt, OpenOptions};

/// `save_bytes@1` — used by @humid/io. Body: raw bytes. Header
/// `x-humid-name`: URI-encoded suggested file name. Shows the system save
/// dialog; returns where the file went, or null if the user cancelled.
#[tauri::command]
async fn save_bytes(app: AppHandle, request: Request<'_>) -> Result<Option<String>, String> {
    let InvokeBody::Raw(data) = request.body() else {
        return Err("save_bytes expects a raw byte body".into());
    };
    let name = request
        .headers()
        .get("x-humid-name")
        .and_then(|v| v.to_str().ok())
        .map(|v| percent_decode_str(v).decode_utf8_lossy().into_owned())
        .unwrap_or_else(|| "humid-export".into());
    // Keep only the file name; never let a stored name pick a directory.
    let name = name.rsplit(['/', '\\']).next().unwrap_or("humid-export").to_owned();

    let Some(target) = app.dialog().file().set_file_name(&name).blocking_save_file() else {
        return Ok(None);
    };
    let shown = target.to_string();
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // FsExt handles Android content:// URIs and iOS security-scoped paths.
    let mut file = app.fs().open(target, opts).map_err(|e| format!("could not write {name}: {e}"))?;
    file.write_all(data).map_err(|e| format!("could not write {name}: {e}"))?;
    Ok(Some(shown))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_humid_gate::init())
        .invoke_handler(tauri::generate_handler![save_bytes])
        .run(tauri::generate_context!())
        .expect("error while running HumID");
}
