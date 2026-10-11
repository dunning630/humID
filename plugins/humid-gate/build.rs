const COMMANDS: &[&str] = &["probe", "enroll", "release", "forget"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
