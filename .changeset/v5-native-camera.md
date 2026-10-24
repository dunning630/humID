---
"@humid/mobile": major
---

5.0: the document camera is native on phones (`humid-docscan@2`: AVFoundation on iPhone, CameraX on Android), under a transparent web view, with the camera screen on top. Focus is the camera's real autofocus on the frame; "Focusing…" is said only while it really focuses; the tap ring shows only when the camera takes the tap and follows its answer; a card held too close says "Move back a little" and the frame never shrinks; the barcode and the passport lines are read in the camera's pipeline; the photo is a zero-shutter-lag still cut out natively, handed to the app once as raw bytes. The JS live guidance (guide.js, guidecap.js, analyzer.js, scancore.js, docnear.js) and the ML Kit document scanner are gone; the web view's own camera stays for development and the browser tests, with the audit's interim fixes.
