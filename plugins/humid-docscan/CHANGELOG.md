# tauri-plugin-humid-docscan

## 2.0.0

- The document camera itself, on iPhone (iOS 26, AVFoundation + Vision) and Android (17, CameraX),
  under a transparent web view: commands `probe open frame focus torch capture take pause resume close`
  and an event channel (`ready look focus code captured interrupted error`). See README.md.
- Removed: the ML Kit document scanner (`scan`, Play services). Nothing had opened it since 3.0.1.
- Every request is checked in Rust (`src/validate.rs`, unit tested); `take` returns raw bytes.
- Compiled in CI (iOS: the Swift package through the Rust library; Android: Gradle), not yet run on a
  device. The guidance and detector ports are unit tested against the app's own JS.

## 1.0.1

- A page the scanner left behind is cleared at start-up and before each scan.

## 1.0.0

- The phone's document scanner (ML Kit) for one page, on Android.
