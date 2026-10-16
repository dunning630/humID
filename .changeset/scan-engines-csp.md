---
"@humid/mobile": patch
---

Scan an ID: details fill in again in the phone and desktop apps, and auto-capture
works hand-held.

- The barcode reader and the MRZ reader never started in the apps: their engines
  load from the app itself, and the app's content security policy didn't allow it
  (`connect-src` was missing `'self'`), so a license's barcode or a passport's lines
  were never read and nothing was filled in. Fixed, and the browser tests now load
  the app from the Android app's own origin (`http://tauri.localhost`) under the
  app's policy, so this can't slip through again.
- If a reader can't start, the camera now says so instead of watching for a code it
  can never read.
- Auto-capture is tuned for a hand-held phone: the document can sit a little off the
  frame, a little small, on a table of nearly the same colour (three clear edges are
  enough), and with the small shake and sensor noise of a real hand.
- Barcodes are read from a wider area than the frame, with a harder try every few
  frames, and the still photo is read wide too.
