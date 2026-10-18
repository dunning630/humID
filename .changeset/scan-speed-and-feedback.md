---
"@humid/mobile": minor
---

Scanning is faster and always says what it is doing.

- **Faster.** The camera analyses a 224 px copy of the picture (as exact as 320 px was) in a worker, off the main thread, one look at a time, paced by the video's own frames instead of a timer; it stops the moment a photo is taken. Barcodes are found and read in workers too (a second worker, so the outline never waits for a read); the MRZ reader straightens only the strip of the card the lines sit in, not the whole card. The scan engines start loading when the document type is chosen, in parallel with the camera, not after it. Where a phone's WebView has no worker or OffscreenCanvas, the same analysis runs on the main thread. On a phone-like CPU (4x slower than the build machine) the main thread spends about 4x less per look, 1.8x less per MRZ attempt and 3x less per barcode attempt.
- **Clear.** One card above the shutter shows the step (Find · Steady · Read · Verify · Done) and a plain line on what to do, with a progress bar, instead of a line of small print. Problems say what to fix: Too dark (with a light button), Too bright, Glare, Too far, Not the right document, Not a license barcode. The outline snaps onto the document and fills as it holds steady. A scan that finds nothing offers the shutter after 10 seconds and, after 30, stops and offers Try again or Take photo. Screen readers hear each change once; a short buzz marks a kept photo; every target is at least 44 px; motion follows the reduced-motion setting.
- **For the Add camera.** `scan.js` exports `scanOptions(mode)` (`license`, `passport`, `card`), `warmScan(mode)` and `<DocCamera mode="passport" />`.

Everything stays on the phone; frames and text read from them are never logged or stored.
