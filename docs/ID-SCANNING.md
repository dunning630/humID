# Scanning IDs into the vault

**Vault → + → Scan an ID** turns a driver's license, passport or ID card into
one sealed vault record: the details as structured fields, photos of each
side, and, for chip documents, the chip's own data and photo. Everything is
read on the phone; nothing about the document leaves it unencrypted.

## What gets read

| Document | Camera | Chip (NFC) |
|---|---|---|
| US and Canadian driver's licenses and state IDs | Front photo; the PDF417 barcode on the back is read live (AAMVA DL/ID versions 1-10): name, number, dates, address, class, restrictions, endorsements, REAL ID flag, height, eyes | No chip |
| Passports | The photo page; the two machine-readable lines (MRZ, TD3) are read live | DG1 (the MRZ), DG2 (the photo) and EF.SOD, over BAC or PACE |
| National ID cards, residence permits | Front photo; the back's barcode or three-line MRZ (TD1) | Same as passports, opened with the MRZ details or the 6-digit CAN |
| Anything else | Front and back photos | — |

The camera finds the document by itself: nobody lines anything up. Wherever the
card or page is in view, and however it's tilted, its outline is drawn over it and
follows it as it moves (`apps/mobile/src/core/docfind.js`: edges → straight lines →
the four that make a document, measured on a small grey copy of the whole view,
several times a second, on the phone). A card's own shape (1.586:1, a passport page
1.42:1) is preferred over, say, the photo printed on it. The outline turns green when
it's about to take the photo.

For a side with something to read, it captures once it has read the barcode, or once
several frames agree on an MRZ whose check digits all pass; the MRZ is read from the
card straightened out of the live picture, both ways up (the check digits settle which
is right). For a side without (the front of a card), it captures once the document has
held still, lit and in focus, for about half a second. A side with a code that won't
read is photographed anyway after the card has sat steady in view for nine seconds.
The shutter and **Photo** (pick an existing picture) always work too, and every field
can be typed or corrected before sealing.

Each photo is then **straightened**: the four corners are found again in the full
photo, more finely, and the card is mapped back to a flat rectangle of its true shape
(a perspective warp), then turned the way its text reads. If the card couldn't be
found, the photo is cropped to the on-screen frame as before.

Each photo is kept before the camera closes: a tick confirms it, and the camera
moves straight on to the other side. If a photo can't be kept (a blank frame from
the camera, or not enough memory to encode it), the camera stays open and says
so. On Android, back closes the camera, then the sheet, and never leaves HumID.

## How sure the details are

Each field remembers where it came from, and a better source replaces a
weaker one: **typed** (the holder's correction) > **chip** > **barcode** >
**MRZ from a photo**. The record shows the strongest source:

- **Chip.** The data groups are hashed and compared with the hashes the
  issuing country signed in EF.SOD (`checkIntegrity`). The app doesn't check
  the Document Signer's certificate chain to the country's CSCA; the recovery
  service does that, with the CSCA certificates the server trusts, when a chip
  *anchors* an identity (Security → ID chip). The chip's files stay in the
  record, so the check can be repeated.
- **Barcode.** Read exactly, but a barcode isn't signed: it proves what's
  printed, not that the card is genuine.
- **MRZ from a photo.** OCR, checked with the ICAO check digits. A character
  is only corrected when exactly one plausible fix (O/0, I/1, B/8, S/5, Z/2,
  G/6) makes its check digit agree; ambiguous fields are flagged for the
  holder to check. Live scanning also votes character by character across
  frames and accepts a reading only when it repeats.

## Where it's stored

One vault item of type `application/vnd.humid.id+json` (`@humid/idscan`
schema `humid.id/1`), sealed like any document (ML-KEM-1024 + X25519,
ML-DSA-87). Its encrypted index entry also carries the kind, issuing country,
state and expiry date, so the vault list can show *expires in 30 days* without
opening it. Opening it shows the card view; **Save a copy** exports the JSON
with its photos.

## The pieces

| Where | What |
|---|---|
| `packages/idscan` | MRZ parsing and repair (`findMrz`, `MrzConsensus`), AAMVA (`parseAamva`), chip files (`readDg1`, `readDg2`, `checkIntegrity`), the record (`newRecord`, `applyMrz`, `applyAamva`, `applyChip`, `applyTyped`) |
| `packages/emrtd` | `readDocument(…, { photo: true })` also reads DG2, with long offsets (READ BINARY B1) for photos over 32 KB. Identity proofs never ask for the photo. |
| `apps/mobile/src/core/scan.js` | Engines and image handling: zxing-cpp (WebAssembly) for PDF417; Tesseract (WebAssembly, in a worker) with an MRZ-trained OCR-B model ([vendor/ocr](../apps/mobile/vendor/ocr/README.md)); JPEG 2000 chip photos decoded with the PDF.js decoder |
| `apps/mobile/src/screens/ids.jsx` | The camera (`DocCamera`), the flow (`IdSheet`) and the card view (`IdView`) |

The engines ship in the app (about 5.5 MB in `assets/ocr` and `assets/scan`)
and load only when someone scans. Running WebAssembly needs
`'wasm-unsafe-eval'` in the content security policy (app, Caddy edge, Windows
edge); it allows compiling WebAssembly, not JavaScript `eval`.

## Testing

- `node --test tests/idscan.test.js`: ICAO MRZ specimens, OCR noise and
  voting, AAMVA versions (US and Canada), chip reads with the photo (BAC and
  PACE, over 32 KB, JPEG 2000), tampering, and the record.
- `node tests/browser/idscan.mjs`: the development build in Chromium with a
  fake camera showing specimen documents (`tests/fixtures/id`), through
  barcode, live MRZ, the simulated chip, sealing and opening again. CI runs it
  in the `id-scan (browser)` job.

The specimen fixtures are marked SPECIMEN / NOT A REAL DOCUMENT and use ICAO's
fictional Utopia (UTO) or a fictional person.

## Any document: Take a photo

**Vault → + → Take a photo** uses the same camera for any document or card. Once the
page holds still it's photographed, straightened (snapped to letter, A4, legal or card
proportions when it's within 6% of one) and turned upright: which way the text lines
run, from how ink is spread across rows and columns, then which way is up, from
ascenders outnumbering descenders and lines starting together at the left margin.
The seal screen proposes that version (**Straightened · Suggested**), with turn
buttons in case the guess is wrong, and **Original**: the photo exactly as the camera
took it. Only the version chosen is sealed; the other is discarded.

## Where it was sealed

Every seal screen (a file, a photo, an ID) has **Stamp where it's sealed**, on unless
it's turned off for that document. While the screen is open the phone's location is
watched, and the freshest fix (no older than two minutes, waiting up to five seconds
for one) goes into the document's encrypted index beside its name and category:
latitude and longitude to six decimals, the accuracy the phone gave, and the fix's
time (`apps/mobile/src/core/place.js`). The document's details show it as **Sealed
at**, with a map link that opens only when tapped. Nothing is looked up online.

- The vault server only ever holds the index encrypted under a key from the account
  seed, so it can't read the location (`tests/browser/photo.mjs` checks the server's
  stored files for it).
- It isn't written into the file itself (no EXIF), so a copy saved or sent elsewhere
  carries no location.
- It's what the phone reported (satellites, Wi-Fi, cell towers), not a proof: a
  rooted phone can report anywhere.
- With location access off for HumID, or no fix in time, the document is sealed
  without one and the screen says why.
