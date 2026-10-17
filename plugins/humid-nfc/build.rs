const COMMANDS: &[&str] = &["probe", "begin", "transceive", "message", "end", "cancel"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();

    // The Swift side reads ISO 7816 tags with Core NFC.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        println!("cargo:rustc-link-lib=framework=CoreNFC");
    }
}
