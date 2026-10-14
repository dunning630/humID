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

The camera captures by itself once it has read the barcode, or once several
frames agree on an MRZ whose check digits all pass. The shutter and **Photo**
(pick an existing picture) always work too, and every field can be typed or
corrected before sealing.

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
