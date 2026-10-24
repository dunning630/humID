const COMMANDS: &[&str] = &[
    "probe",
    "enroll",
    "release",
    "forget",
    "enabled_accessibility_services",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();

    // The Swift side uses these system frameworks (Face ID / Touch ID, App Attest).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        for fw in ["LocalAuthentication", "DeviceCheck", "Security"] {
            println!("cargo:rustc-link-lib=framework={fw}");
        }
    }
}
