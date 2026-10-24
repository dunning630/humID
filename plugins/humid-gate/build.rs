// Commands the web view may call. None of them carries a secret: the gate's hardware
// operations are reached from Rust only (src/native.rs), never through the IPC.
// The two hardware_check_* commands exist only in development builds and in hardware-check
// test builds (HUMID_HWCHECK=1); their permissions are always generated so the default set
// stays one file, and in a release build they name commands that aren't there.
const COMMANDS: &[&str] = &[
    "probe",
    "enabled_accessibility_services",
    "hardware_check_designs",
    "hardware_check_run",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();

    // HUMID_HWCHECK=1: a hardware-check test build (never published; release.yml refuses).
    println!("cargo::rustc-check-cfg=cfg(humid_hwcheck)");
    println!("cargo:rerun-if-env-changed=HUMID_HWCHECK");
    if std::env::var("HUMID_HWCHECK").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=humid_hwcheck");
    }

    // The Swift side: Face ID / Touch ID, the Secure Enclave (CryptoKit, Security), App Attest.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        for fw in [
            "LocalAuthentication",
            "DeviceCheck",
            "Security",
            "CryptoKit",
        ] {
            println!("cargo:rustc-link-lib=framework={fw}");
        }
    }
}
