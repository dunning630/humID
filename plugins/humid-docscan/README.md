# tauri-plugin-humid-docscan (`humid-docscan@2`)

HumID's document camera on phones. The camera runs natively, under a transparent web view;
the app's camera screen (`apps/mobile/src/screens/add/camera.jsx`) stays on top and draws the
frame, the words and the buttons. Design: HumID 5.0 audit 5 (the ID-document camera), §2.

| | iPhone (iOS 26+) | Android (17+, API 37) |
|---|---|---|
| Camera | AVFoundation, the virtual (triple / dual-wide / wide) device | CameraX: Preview + ImageAnalysis + ImageCapture, one session |
| Lens | cards and passport pages stay on the wide lens (`.restricted`, zoom only); pages switch to macro by themselves | the HAL picks the lens for `CONTROL_ZOOM_RATIO` |
| Zoom | `1.25 × MFD(wide) / d_fill(1×)`, 1…2.5 | the same, from a calibrated `LENS_INFO_MINIMUM_FOCUS_DISTANCE` |
| Focus | continuous AF, near range, point on the frame; subject-area refocus; tap = one-shot `.autoFocus` | `FocusMeteringAction` at the frame, re-issued when it auto-cancels; tap = the same at the tap |
| Focus state | KVO `isAdjustingFocus`, `lensPosition` | `CONTROL_AF_STATE`, `LENS_FOCUS_DISTANCE` |
| Finding | Vision rectangles (cards), document segmentation (pages, photos) | `DocFind.kt` (a port of `core/docfind.js`) on the Y plane |
| Guidance | `Guidance.swift` | `Guidance.kt` |
| PDF417 | `AVCaptureMetadataOutput`, in the pipeline; Vision on the still if missed | zxing-cpp on the Y plane, ≤ 4 Hz |
| MRZ | Vision text on the band, ≤ 3 Hz while lined up | none live (audit 5 §2.3: the app reads the still) |
| Still | zero-shutter-lag `AVCapturePhotoOutput`, ~12 MP, `CIPerspectiveCorrection` | ZSL `ImageCapture` where offered, `Matrix.setPolyToPoly` |
| Haptics | `UIImpactFeedbackGenerator` / `UINotificationFeedbackGenerator` | `performHapticFeedback` |

Both guidance ports are line-by-line copies of `apps/mobile/src/core/lookstate.js`, the rules
every HumID camera follows (the web camera in development too). `tests/fixtures/guidance.json`
holds the golden vectors: `tests/lookstate.test.js` runs them on the JS, `GuidanceTest.kt` on
the Kotlin. `DocFindTest.kt` checks the Kotlin detector against the JS one on the camera fixtures
(`tests/fixtures/docfind-golden.json`, made by `tools/docfind-golden.mjs`).

## Commands

All arguments are checked in Rust (`src/validate.rs`, unit tested) before they reach native code.

| Command | Arguments | Answer |
|---|---|---|
| `probe` | | `{ available, lenses, macro, torch, minFocusMm? }` |
| `open` | `shape` (`id1` `td3` `page` `full`), `read { pdf417, mrz, require }`, `frame` and `view` (CSS px), `auto`, `haptics`, `events` (a Channel) | `{ session }` |
| `frame` | `frame`, `view` (layout or rotation changed) | |
| `focus` | `x`, `y` (CSS px): one-shot AF there; the result comes as a `focus` event | |
| `torch` | `on` | `{ on }` |
| `capture` | (the shutter: focuses first if it isn't in focus) | `{ id, width, height }`, and a `captured` event |
| `take` | `id`, `which` (`doc` or `full`) | the JPEG as raw bytes (an ArrayBuffer), once |
| `pause`, `resume`, `close` | | |

## Events (on the `events` channel, at most 10 a second)

```
{ t: "ready", lens, zoom, minFocusMm?, torch }
{ t: "look", state: "searching"|"aligning"|"focusing"|"sharp"|"ready", key, aligned, quad (CSS px) | null,
  focus: "scanning"|"focused"|"failed"|null, steady, light: "ok"|"dark"|"glare", progress (0..1), lens }
{ t: "focus", x, y, af: "focused"|"failed" }
{ t: "code", kind: "pdf417"|"mrz", state: "seen"|"reading"|"read", text?, lines? }
{ t: "captured", id, how: "auto"|"shutter", width, height, cut, freeze (720 px JPEG, base64), codes { pdf417?, mrz? }, quad?, af, lens, zoom? }
{ t: "interrupted", reason }
{ t: "error", code: "denied"|"busy"|"nocamera"|"failed", message, soft? }
```

`key` is one of `core/doctpl.js` MESSAGES (`dark glare bright closer fill far back tooclose shift
tilt flat hold shape showback showfront showpage`); the words live in the app.

## What it never does

It holds no keys and no secrets. Frames are never written, logged or sent; the analysis looks at
the Y plane in place. A still stays in memory until `take` hands it over, then it is dropped. The
Android preview is a `TextureView` (`COMPATIBLE`) inside the window, so `FLAG_SECURE` covers it.
No ML Kit, no Play services, no usage reporting (zxing-cpp is the same engine as the app's own
barcode reader).
