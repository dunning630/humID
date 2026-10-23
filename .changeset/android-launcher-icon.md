---
"@humid/mobile": patch
---

Android shows the HumID peace-sign icon. The release build regenerates the Android project with `tauri android init`, which writes Tauri's own launcher icons (the blue-and-orange logo), and nothing put HumID's back. A release step now replaces them with `src-tauri/icons/android` (every density, the adaptive icon's layers and its background colour) and fails the build if any didn't land.
