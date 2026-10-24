//! HumID native shell. Deliberately thin: it hosts the web modules, registers
//! the biometric gate and chip reader plugins and offers one command for saving files. Feature
//! work happens in the modules and the plugin, so the shell itself rarely
//! needs a new release.

use std::io::Write;

use percent_encoding::percent_decode_str;
use tauri::ipc::{InvokeBody, Request};
use tauri::plugin::{Builder as PluginBuilder, TauriPlugin};
use tauri::{AppHandle, Runtime, Url};
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
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("humid-export")
        .to_owned();

    let Some(target) = app
        .dialog()
        .file()
        .set_file_name(&name)
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let shown = target.to_string();
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // FsExt handles Android content:// URIs and iOS security-scoped paths.
    let mut file = app
        .fs()
        .open(target, opts)
        .map_err(|e| format!("could not write {name}: {e}"))?;
    file.write_all(data)
        .map_err(|e| format!("could not write {name}: {e}"))?;
    Ok(Some(shown))
}

/// The WebView shows HumID and nothing else. Any navigation away from the app's own
/// origin is refused here, before it happens: a link in a document, a crafted
/// `href`, or a redirect can't turn the vault's window into a browser. Links that
/// should open elsewhere go through the opener plugin (src/core/external.js), which
/// hands https:, tel: and mailto: to the system's own apps.
///
/// Registered as a plugin: Tauri asks every plugin's `on_navigation` for the main
/// window and cancels the navigation if any says no.
fn stay_home<R: Runtime>() -> TauriPlugin<R> {
    PluginBuilder::new("humid-stay-home")
        .on_navigation(|_webview, url| own_origin(url, cfg!(debug_assertions)))
        .build()
}

/// Is `url` the app's own bundled origin? Release builds accept only the bundle's origin:
/// `tauri://localhost` (iOS, macOS, Linux) and `http(s)://tauri.localhost` (Android,
/// Windows). Loopback (`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`) is a development
/// server's address and is accepted only when `loopback` is set, which only debug builds
/// (`tauri dev`) do: in a release build a page on the phone's own loopback, served by any
/// other app, is somewhere else.
fn own_origin(url: &Url, loopback: bool) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => {
            let host = url.host_str().unwrap_or("");
            host == "tauri.localhost"
                || (loopback
                    && (host == "localhost"
                        || host == "127.0.0.1"
                        || host == "[::1]"
                        || host.ends_with(".localhost")))
        }
        // a blank page while the WebView is created
        "about" => url.as_str() == "about:blank",
        _ => false,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_humid_gate::init())
        .plugin(tauri_plugin_humid_nfc::init())
        .plugin(tauri_plugin_humid_docscan::init())
        .plugin(stay_home())
        .invoke_handler(tauri::generate_handler![save_bytes])
        .run(tauri::generate_context!())
        .expect("error while running HumID");
}

#[cfg(test)]
mod tests {
    use super::own_origin;
    use tauri::Url;

    fn ok(url: &str, loopback: bool) -> bool {
        own_origin(&Url::parse(url).unwrap(), loopback)
    }

    #[test]
    fn release_builds_stay_on_the_bundle() {
        for url in [
            "tauri://localhost/",
            "tauri://localhost/index.html#/vault",
            "https://tauri.localhost/",
            "http://tauri.localhost/index.html",
            "about:blank",
        ] {
            assert!(ok(url, false), "{url} is the app's own origin");
        }
        for url in [
            "http://localhost:5173/",
            "http://127.0.0.1:8480/",
            "http://[::1]:8480/",
            "http://ipc.localhost/",
            "https://evil.localhost/",
            "tauri://evil/",
            "https://example.com/",
            "https://tauri.localhost.example.com/",
            "about:srcdoc",
            "blob:https://tauri.localhost/0b0c",
            "data:text/html,hi",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            assert!(!ok(url, false), "{url} is refused in a release build");
        }
    }

    #[test]
    fn development_builds_also_reach_loopback() {
        for url in [
            "http://localhost:5173/",
            "http://127.0.0.1:8480/",
            "http://[::1]:8480/",
            "https://tauri.localhost/",
        ] {
            assert!(ok(url, true), "{url} is allowed in a development build");
        }
        for url in [
            "https://example.com/",
            "file:///etc/passwd",
            "tauri://evil/",
        ] {
            assert!(
                !ok(url, true),
                "{url} is refused even in a development build"
            );
        }
    }
}
