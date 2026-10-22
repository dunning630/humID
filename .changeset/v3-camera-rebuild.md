---
"@humid/mobile": minor
---

**The document camera, rebuilt around what the person needs to know.** The frame stays fixed (the crop never moves), and now: a lock box inside it follows the document the camera actually sees and settles onto the frame when it's lined up; one instruction and a row of live chips (Framed · Sharp · Steady · Light · Barcode / ID lines) sit right under the frame instead of 200 px below it; problems are said after 0.35 s (not up to 2.2 s) and good news at once; a ring fills round the frame as it holds still.

A license's barcode and a passport's lines are now **read live**, the moment they're in the frame, so the photo is taken when the details are in rather than read (or missed) afterwards. The photo freezes in the frame with a flash, and before moving on the camera **says back what it read** (name, date of birth, number, expiry, city; a card's brand and last four). When something had to be read and wasn't, it says so plainly with Try again or Keep the photo — no silent retry loop. A license back held up for the front is read and kept as the back. Tap the picture to focus; a blur while lined up asks the camera to focus again. `core/capture.js` replaces `core/scanflow.js`.
