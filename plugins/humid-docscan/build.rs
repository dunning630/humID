const COMMANDS: &[&str] = &["probe", "open", "frame", "focus", "torch", "capture", "take", "pause", "resume", "close"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();

    // The Swift side: the camera, Vision for the document and the MRZ lines, Core Image for the cut.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("ios") {
        for fw in ["AVFoundation", "Vision", "CoreImage", "CoreMedia", "CoreVideo", "Accelerate", "UIKit"] {
            println!("cargo:rustc-link-lib=framework={fw}");
        }
    }
}
