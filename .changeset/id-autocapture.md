---
"@humid/mobile": patch
---

Scan an ID: the camera takes the photo by itself, for every side of every document.

- Fronts (and any side with nothing to read) are taken once a document of the right
  shape for the type being scanned (a card, or a passport photo page) is lined up
  with the frame, lit, in focus and steady for about half a second. It's checked on
  the phone on a small grey copy of the picture, several times a second.
- Barcode and MRZ sides still capture the moment they read. If a code won't read but
  the document has sat lined up for nine seconds, the photo is taken anyway.
- The corners show how close it is (white: looking, amber: nearly, green: taking it),
  and the hint says what to fix: move closer, line up the edges, more light, glare,
  hold still. The shutter is still there.
- A save that fails keeps the camera open with the reason, then tries again by itself.
