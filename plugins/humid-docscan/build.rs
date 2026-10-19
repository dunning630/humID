const COMMANDS: &[&str] = &["probe", "scan"];

fn main() {
    // Android only: iPhone and desktop answer "unavailable" from Rust and the app uses its own camera.
    tauri_plugin::Builder::new(COMMANDS).android_path("android").build();
}
