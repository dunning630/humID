---
"@humid/mobile": minor
---

The camera finds the document by itself, straightens it and turns it upright; documents can be stamped with where they were sealed.

- **No lining up.** Wherever a card or page is in view, and however it's tilted, the
  camera finds its four corners several times a second (on the phone, plain arithmetic
  on a small grey copy of the view: edges, straight lines, the four that make a
  document), draws the outline over it, follows it, and takes the photo once it has
  held still, lit and in focus. A card's own shape is preferred over the photo printed
  on it. Replaces the fixed-frame check (`core/detect.js` → `core/docfind.js`).
- **Straightened and upright.** The corners are found again in the full photo and the
  document is mapped back to a flat rectangle of its true shape (snapped to card,
  letter, A4 or legal proportions when close), then turned the way its text reads.
  IDs: the MRZ is read from the card straightened out of the live picture, both ways
  up; the card photos in the record are the straightened cards.
- **Take a photo: seal it straightened, or the original.** The seal screen proposes the
  straightened, upright version (Suggested), with turn buttons, and offers the photo
  exactly as taken. Only the one chosen is sealed.
- **Stamp where it's sealed.** On every seal screen (files, photos, IDs), on unless
  turned off for that document: the phone's location at the moment of sealing, with
  its accuracy and time, kept in the document's encrypted index beside its name. The
  vault server can't read it, it isn't written into the file, and the document shows
  it as "Sealed at" with a map link opened only on a tap. Android asks for location
  access (precise or approximate) the first time; iOS and macOS show their own prompt.
