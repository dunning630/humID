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
held still, lit and in focus, for about a second, and the camera's focus has settled
(the picture is as sharp as it has been while held). A side with a code that won't
read is photographed anyway after the card has sat steady in view for twelve seconds,
but never while a barcode is in view.

**What it says while it works** (`core/scanflow.js`, `screens/add/camera.jsx`). A card above
the shutter shows one state at a time: *Looking for the document → Hold steady →
Reading → Verifying → Done*, with the steps as a row and a progress bar. Anything the
person can fix is said in a few words and held back until it has lasted 0.7 s, so it
doesn't flicker: *Too dark* (with a light button), *Too bright*, *Glare*, *Too far*,
*Not the right document*, *Not a license barcode*. After 10 s without a read the round
button is called out; after 30 s the camera stops analysing and offers *Try again* and
*Take photo*. The card is the screen reader's live region (each change once), a short buzz
marks a kept photo, and every button is at least 44 px. Nothing about a frame or what
was read from it is logged or stored.

**How little the phone is asked to do per look.** The document is looked for in a 224 px
copy of the view (as exact as 320 px) made by the browser off the main thread
(`createImageBitmap`), analysed in a worker (`core/scanworker.js`, started by
`core/analyzer.js`; a second worker reads barcodes), at most one look at a time, paced by
the video's own frames and by how long the last look took. Without worker or
OffscreenCanvas support the same code (`core/scancore.js`) runs on the main thread. The
MRZ reader straightens only the strip the two or three lines sit in
(`bandPlan` / `liveMrzBand`), not the whole card. The readers load when the document type
is chosen (`warmScan(mode)`), in parallel with the camera. `scanOptions(mode)` in
`core/scan.js` gives the camera its shape and readers for `license`, `passport` or `card`.

**Barcodes are found the way a store's scan-and-go app finds them**
(`apps/mobile/src/core/barcodefind.js`), not by lining anything up. Every look, a
small grey copy of the whole view is searched for patches that change sharply in one
direction (across the bars) and little in the other (along them): text and edges
change both ways, a barcode doesn't. From far away only a PDF417's bold start and stop
bars stand out, so the camera looks again, closer, around them, and finds the whole
barcode. It's highlighted on screen; its tilt is measured (a structure tensor of the
picture's gradients) and the reader is handed just that spot at full resolution,
turned so the bars stand exactly upright and enlarged if small. The reader then rarely
needs its slow "try harder" mode. Only a license's barcode is accepted (it must parse
as AAMVA); another barcode in view, such as a store card's, is passed over for the
next one, and one that won't read gives way to the next one in view for a moment. The
status line says what's happening: "Barcode found. Reading…", then "Move a little
closer to the barcode" or "Hold steady on the barcode…".
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
| `apps/mobile/src/core/docfind.js` | Finding a document in view, the calm capture (`tracker`: steady, held, focus settled), straightening and turning upright |
| `apps/mobile/src/core/barcodefind.js` | Finding barcodes anywhere in view, their tilt, and the spot to hand the reader |
| `apps/mobile/src/core/scanclean.js` | The clean scan: even light, white paper, crisp ink |
| `apps/mobile/src/core/scanflow.js`, `scancore.js`, `analyzer.js`, `scanworker.js` | The visible scan state machine; the per-frame analysis; running it in a worker (or here); the worker |
| `apps/mobile/src/screens/add/camera.jsx` | The camera (`DocCamera`, guided and free-form) and its state card (`ScanState`) |
| `apps/mobile/src/screens/add/ids.jsx` | The ID flow (`IdFlow`) and the card view (`IdView`) |
| `apps/mobile/src/core/docscan.js`, `plugins/humid-docscan` | Android: the phone's document scanner takes the photo (below) |

The engines ship in the app (about 5.5 MB in `assets/ocr` and `assets/scan`)
and load only when someone scans. Running WebAssembly needs
`'wasm-unsafe-eval'` in the content security policy (app, Caddy edge, Windows
edge); it allows compiling WebAssembly, not JavaScript `eval`.

## Testing

- `node --test tests/idscan.test.js`: ICAO MRZ specimens, OCR noise and
  voting, AAMVA versions (US and Canada), chip reads with the photo (BAC and
  PACE, over 32 KB, JPEG 2000), tampering, and the record.
- `node --test tests/scanflow.test.js`: the scan state machine and its words, the failures, the
  time budget, the strip of a card against the whole-card route (lying, standing, upside down),
  the camera screen's live region, targets and worker, and that nothing is logged.
- `node --test tests/barcodefind.test.js tests/scanclean.test.js tests/docfind.test.js`:
  the barcode found centred, sideways, upside down, small and far, tilted, on a desk of
  printed text, beside another barcode; no barcode found in text or on an ID's front;
  the tilt measured; a shadowed, warm-lit page cleaned to white and even paper with
  dark ink, a coloured form kept coloured; the calm capture's hold and focus check.
- `node tests/browser/idscan.mjs`: the development build in Chromium with a
  fake camera showing specimen documents (`tests/fixtures/id`), through
  barcode, live MRZ, the simulated chip, sealing and opening again, and a cluttered
  desk (`camera-license-desk.mjpeg`, made by `make-desk.py`) where the license lies
  sideways and small beside a store card with its own, bigger PDF417: the license is
  read live. CI runs it in the `id-scan (browser)` job.

The specimen fixtures are marked SPECIMEN / NOT A REAL DOCUMENT and use ICAO's
fictional Utopia (UTO) or a fictional person.

## The guided scan (apps 2.2.0)

Cards, licences, ID cards and passports are scanned the way a bank's app does it:
a fixed outline, plain-word guidance, an automatic or manual still, a crop to the outline.
The camera no longer tracks a free-form quadrilateral live (that outline jumped, and the photo
depended on it). Add > Photo and the Android document scanner are unchanged.

**3.0.1.** What it is comes first: Add opens "What are you adding?", listing each kind directly
(Passport, Driver's license, State ID or ID card, Green card or residence permit, Another card,
Payment card, Document, Photo, Wallet pass, File; the last one used on top), and picking one opens
its camera at once, with no "Start camera" step. The readers for that kind (the barcode reader for
a license, the reader for the lines of <<< for a passport) start loading from the touch, so they are
ready when the camera is. A **Document** is a page: an outline standing up at 1:1.35, between US Letter
(1:1.294) and A4 (1:1.414), so either lines up; an evenly bright page isn't called glare. **Photo** is the
whole view with nothing drawn over it. No four-point outline is drawn anywhere: the template's corners go
amber when close and green when lined up, and the outline stays green, with a green line sweeping it,
while the photo is read. **Which way up:** the guided photo is kept the way up it was lined up in the
preview. No guess from the print turns it any more (`uprightOf` had turned real license fronts upside
down), and a still the phone hands back turned 180° from the preview (a sensor mounted the other way up)
is recognised by comparing it with the preview both ways and turned back (`takeStill`, `turned`). A
passport page whose lines read only turned is still turned by its lines; the review's Rotate turns a card
half round.

**The template.** `templateFor` (`core/guide.js`) gives the outline for the kind chosen on "What are you
adding?" (`SCAN_MODE` in `addroute.js`): ID-1, 85.6 x 54 mm, for licences, ID cards and payment cards (front and
back); ID-3, 125 x 88 mm, for the passport page. It is centred, dimmed outside, with corner marks and faint
zones (barcode, MRZ, number). The camera starts after the kind is chosen, never before, and the stream is
released on exit, Back or background.

**Guidance** (`measure`, `judge`; pure, on a 288 px-wide picture of the outline plus a 30% margin, about 2-25 ms):

| Says | When (thresholds in `TH`) |
|---|---|
| Too dark (with the light button) | document in view: p95 < 85 or mean < 30; nothing in view: mean < 28 and p95 < 50 |
| Too much glare | 253+ saturated share >= 2.5% and a patch cell >= 50% (white paper: p50 >= 228, share >= 10%, 2 cells) |
| Move closer / Fill the outline | the edges' scale of the outline < 0.78 / < 0.88 |
| Move back a little | scale > 1.06 |
| Line it up (which way) | an edge more than 8.5% inside or 3% outside the outline, or a centre shift > 4.5% |
| Straighten the card / passport page | turn > 6 degrees (1 to 10 degrees is deskewed in the crop instead) |
| Hold the phone flat | keystone > 5.5 degrees |
| Not sharp yet | Laplacian variance over gradient energy < 0.55, or < 60% of the best seen; said after 1.8 s |
| Hold steady | frame-to-frame motion > 0.004 outline widths |
| Show the back / front / the photo page | no PDF417 on a licence back; a PDF417 on a licence front; no MRZ lines on a passport; said after 1.8 to 2.2 s |

Edges come from five-run profiles per side with a robust line fit; the shape is checked against the
template's aspect (> 7% off: nothing is said about size and nothing is taken by itself, the round button
works). A problem is said after 0.7 s (`SAY_AFTER` for the slower ones); the scan-state card (`scanflow.js`,
`scanui.jsx`) shows it, as a live region.

**Capture.** Lined up, steady and sharp for 0.6 s (`holdTracker`, 0.22 s grace) fires the shot with a short
vibration; the round button is always there. `takeStill` (`core/guidecap.js`) asks `ImageCapture.takePhoto` for up to
4096 px on the long side, maps the outline into the photo (`stillMapping`), and only uses it if a small grey copy
agrees with the preview frame (normalised cross-correlation >= 0.6, shifts of 3 px searched). Otherwise
(no ImageCapture, as in iOS WKWebView; a refused or different photo) it takes the full video frame. The crop is
the outline plus a 4% margin, at most 2400 px wide, deskewed when the card is turned 1 to 10 degrees, set
upright from the guide orientation and the print, and handed to `develop()` as before, so reading and
sealing are unchanged. The Rotate control stays on the review. Nothing is logged and no raw frame is kept.

**Preview size.** The long side only (1920 px; 2560 for a passport), with `resizeMode: "none"`, never a width and a height
together: those make a browser cut the frame to that shape and lose the top and bottom of the page. If the preview
comes back the other way round for the screen, the camera asks once more with both sizes in the screen's orientation (`previewTurned`). Not 4K (a 4K preview made the WebView unsteady
in 2.1.1). Evidence, on synthetic specimens in Chromium: the PDF417 reads from frames 540, 720 and 1080 px
wide; the MRZ reads at 720 and 1080 but misread a character at 540. So 1080 px is about 1.5x the width
that was proven, and the passport asks for more. Real print and real optics need the device check below.

**Tests.** `tests/guide.test.js` (metrics, verdicts, hold timer, templates, constraints, still mapping);
`tests/browser/guided.mjs` (27 scenes with synthetic MJPEG fixtures from `tests/fixtures/id/make-guided.py`:
too small, right, too big, tilted, keystone, blurred, glared, dark, shaking, wrong side, a takePhoto
stand-in; asserts the message, that nothing is taken by itself until lined up, and the crop's overlap
with the known document, about 0.997). Use `ONLY=regex` to run some.

**Check on a phone** (the fake camera cannot tell): focus and the sharpness threshold on real video;
glare under a lamp and window; whether `takePhoto` exists in the Android WebView, which size it returns,
its framing and orientation (the correlation check falls back to the frame); the preview orientation;
the vibration; the torch button; PDF417 and MRZ reads from real prints; a low-contrast card on a similar
table (the outline cannot find its edges: only the round button works).

## Any document: Take a photo

**Vault → + → Take a photo** uses the same camera for any document or card. Once the
page holds still it's photographed, straightened (snapped to letter, A4, legal or card
proportions when it's within 6% of one) and turned upright: which way the text lines
run, from how ink is spread across rows and columns, then which way is up, from
ascenders outnumbering descenders and lines starting together at the left margin.
The seal screen offers three versions:

- **Clean scan** (suggested when the page looks like paper): the straightened page
  made to look like it came off a flatbed scanner (`apps/mobile/src/core/scanclean.js`).
  The light falling on the page is estimated block by block (the level 90% of each
  block is darker than: paper, even in a block of text), smoothed, and divided out,
  so shadows and uneven light go and ink keeps its darkness relative to the paper
  around it. A mild colour cast is taken off by lifting the weaker channels (never
  dimming one), then the levels are set: paper white, ink near black. Every step
  scales R, G and B alike except that small correction, so a blue or yellow form keeps
  its colour.
- **Straightened**: the same page with its true colours and light (suggested instead
  when the picture doesn't look like paper: a photo, a dark card).
- **Original**: the photo exactly as the camera took it.

The first two can be turned by hand in case the guess is wrong. Only the version
chosen is sealed; the others are discarded.

## Android: the phone's document scanner (apps 2.1.1; IDs off it since 2.1.2; not used to add since 3.0.1)

**3.0.1: nothing opens the scanner any more.** Its screen draws its own four-point outline
around whatever it finds, before the person has said what they're adding; since 3.0.1 the
kind is picked first and every kind gets HumID's own camera with the template made for it
(a page included). The plugin and `core/docscan.js` stay in the build, unused by Add;
`tests/browser/docscan.mjs` checks that no kind opens it. What follows is how it worked.

Until 3.0.1, on Android, **Add ▸ Photo** and **Another card** opened the phone's own document scanner
instead of HumID's live view. Driver's licenses, passports, ID cards, permits and payment
cards stay on HumID's camera, whose screen blocks screenshots and the recents thumbnail
(the scanner's screen is Google's and isn't covered; see
[SECURITY.md](SECURITY.md#the-android-document-scanner-apps-211-narrowed-in-212)). The scanner is ML Kit's document scanner, run by Google Play services
(`plugins/humid-docscan`, `humid-docscan@1`). It finds the edges, takes a
full-resolution, focused photo once the document is steady and flattens it. HumID
then does what it does with any photo: turns it upright, reads the license barcode or
the MRZ from the still page (`readStill`), and seals it. The live view inside the app's
web view was the weak point: a 4K stream, an outline that jumped, and a photo that was
a frame of that video.

- **Base mode only** (crop and turn): no filters and no ML clean-up, so nothing can
  change what a document says. One page; no gallery import.
- **On the phone.** The scanning runs on the device and the picture never leaves it.
  The page is handed back as JPEG bytes (at most 3,200 px on its long side) and the
  scanner's file is deleted at once; a start-up sweep clears any page left behind. ML Kit reports anonymous usage figures to Google
  (never pictures); the scanner runs under Play services' camera permission.
- **HumID stays unlocked** while the scanner is on screen, as for the file picker, for
  at most 60 s off the screen and 90 s in all (`markPicking({ hiddenMs })`).
- **Fallbacks.** Backing out of the scanner goes back a step. A page that can't be handed
  back offers *Scan again* or *Use HumID's camera*. A phone without the scanner (no Play
  services, too little memory) gets HumID's own camera, as before, for the rest of the
  session. iPhone, the web build and the desktop keep HumID's camera.
- **Tested** in Chromium with a stand-in scanner (`tests/browser/docscan.mjs`: license
  front and back, passport, back out, scan again, no scanner) and `tests/docscan.test.js`.
  The scanner itself can only be tried on a phone.

## Measuring a capture

How long from the shutter to the review screen, and where it goes. In a development
build (`DEMO_BUILD`; never in a release build) the app records timings in
`globalThis.__humidTrace.ev`: entries `[name, ms since page start, extra]`. Marks from the
camera (`shoot`, `develop`, `developed`, `kept`, ...), `span:<stage>` entries with the stage's
duration in `extra` (`develop-grab`, `develop-corners`, `develop-straighten`, `develop-orient`,
`clean`, `jpeg`, `docscan-decode`, ...) and the seal marks (`seal-start`, `seal-prepared`,
`seal-place`, `seal-keys`, `seal-signed`, `seal-uploaded`). Never a picture, text or size.

- On a phone: build with demo allowed, open the app in the Android System WebView, attach
  with Chrome's `chrome://inspect`, take a document, then run
  `copy(JSON.stringify(__humidTrace.ev))` in the console.
- In a desktop browser with a fake camera, repeatably (4x CPU throttle, 3 runs, median and
  spread): `python3 tests/bench/make-4k-fixtures.py $OUT/fixtures`, then
  `PORT=5333 OUT=$OUT node tests/bench/capture.mjs` (`PROFILE=1` adds top functions).
  Sandbox and laptop CPUs are not phones: compare before with after, not with a phone.
- Not covered by the harness: the native IPC (base64 over JSON), Play services' scanner, and
  the real camera's still capture. Time those on the device.

## Where it was sealed

Every seal screen (a file, a photo, an ID) has **Stamp where it's sealed**, on unless
it's turned off for that document. While the screen is open the phone's location is
watched, and the freshest fix (no older than two minutes, waiting up to three seconds
for one; the phone starts looking when the camera opens, if location was already allowed, and stops after 90 seconds) goes into the document's encrypted index beside its name and category:
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
