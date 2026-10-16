---
"@humid/mobile": patch
---

Android: taking a document photo is confirmed, and back never leaves HumID.

- The camera keeps a photo before it closes. It shows "Saving the photo…", then a
  tick and a short buzz. If the photo can't be kept (the phone ran out of memory
  encoding it, or the camera gave a blank frame), the camera stays open and says
  why, instead of dropping back to "Scan the front" as if nothing happened.
- After the front of a card, the camera goes straight on to the back, with
  "Front saved. Now turn it over." and a thumbnail of the front.
- Photo encoding no longer spreads 32,768 bytes into one call, which can overflow
  the stack in an Android WebView; blank frames are retried.
- The Android back button and edge-swipe gesture close what's on top (the camera,
  an open document, the top sheet, a setup step) or return to the Vault tab. At the
  Vault, back does nothing: it never exits the app.
