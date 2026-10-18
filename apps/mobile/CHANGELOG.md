# @humid/mobile

## 2.1.0

### Minor Changes

- 1390a6d: Add document no longer opens the camera. It opens "What are you adding?" first; after a kind is chosen, a short "what to show" screen (with a lighting tip) has one primary **Start camera**. The chosen kind sets what the camera reads (license: barcode, passport: MRZ, card: card scan). The camera and its preview are released when you leave the screen, go back or switch apps, and Android Back still steps back one level at a time.
- 5998690: Scanning is faster and always says what it is doing.
  
  - **Faster.** The camera analyses a 224 px copy of the picture (as exact as 320 px was) in a worker, off the main thread, one look at a time, paced by the video's own frames instead of a timer; it stops the moment a photo is taken. Barcodes are found and read in workers too (a second worker, so the outline never waits for a read); the MRZ reader straightens only the strip of the card the lines sit in, not the whole card. The scan engines start loading when the document type is chosen, in parallel with the camera, not after it. Where a phone's WebView has no worker or OffscreenCanvas, the same analysis runs on the main thread. On a phone-like CPU (4x slower than the build machine) the main thread spends about 4x less per look, 1.8x less per MRZ attempt and 3x less per barcode attempt.
  - **Clear.** One card above the shutter shows the step (Find · Steady · Read · Verify · Done) and a plain line on what to do, with a progress bar, instead of a line of small print. Problems say what to fix: Too dark (with a light button), Too bright, Glare, Too far, Not the right document, Not a license barcode. The outline snaps onto the document and fills as it holds steady. A scan that finds nothing offers the shutter after 10 seconds and, after 30, stops and offers Try again or Take photo. Screen readers hear each change once; a short buzz marks a kept photo; every target is at least 44 px; motion follows the reduced-motion setting.
  - **For the Add camera.** `scan.js` exports `scanOptions(mode)` (`license`, `passport`, `card`), `warmScan(mode)` and `<DocCamera mode="passport" />`.
  
  Everything stays on the phone; frames and text read from them are never logged or stored.

### Patch Changes

- 944f96f: A document's **Sealed** time is now the vault server's clock (when it received the live-sealed document), shown to the minute, instead of the time the phone wrote into the envelope. The holder can set a phone's clock; they can't set the server's. The genuine app can't talk to the server with a clock more than two minutes off, so the two normally agree; if they ever don't, the phone's time is shown beside it as "Phone's clock said …", never as the seal time.
- a70c5d3: Fail closed on passport and ID chips. Chip data is used (and the chip photo decoded) only when its files match the chip's own signed list of hashes; a malformed SOD, an unchecked result or a hash mismatch now shows "Chip couldn't be verified", uses none of the chip's data, and offers to continue with the printed details, marked "Not verified". A chip that does match is now described as "Chip data integrity-checked" rather than verified, because the issuing country's signature isn't checked on the phone.
- Updated dependencies [a70c5d3]
- Updated dependencies [f216b9a]
  - @humid/idscan@1.0.3
  - @humid/cards@1.0.1

## 2.0.0

### Major Changes

- App 2.0 layout: the information-architecture rebuild.
  
  - **Kinds replace categories.** Every vault item is an ID, a card, a pass, a photo or a file (`kind`, sealed in its index entry). Items sealed before 2.0 are classified on read and the kind is written back lazily on the next rename or pin, never in bulk. The old categories live on as optional **tags** (same ids), suggested from the name, shown as small labels and filterable from a "More filters" row that appears only once something carries a tag. The Vault's chip row is All · IDs · Cards · Passes · Photos · Files, for the kinds that exist.
  - **One Add flow, camera first.** The + button opens the camera at once. The photo routes itself: a card with a license barcode or a page with an MRZ to the ID flow, a card with a payment number to the card review, anything else to the photo review; a live label says what the camera sees, with "It's something else" for the picker. File (a `.pkpass` is checked as a Wallet pass), Type a card and Tap a card sit on the camera's own bar. Every kind goes through one shared Review (name, kind with Change, the kind's fields, tags, location stamp, Seal). The Add, ID and payment-card sheets are gone.
  - **Item detail is a pushed screen**, preview first (one Open = one check; a card's masked number with "Show the number"; a pass's summary), then the facts, then a ··· menu: Rename · Pin · Show in decoy · Export sealed · Delete. Save a copy lives in the opened Viewer.
  - **Onboarding**: "You're all set" becomes "Your recovery card" (Print / Save, type-back check, "I've saved it") then "You're in". The sole-biometric checkbox becomes the one-line statement "Only I use Face ID / fingerprint on this phone" with a "What does this mean?" disclosure, still required and still recorded in the ledger.
  - Android Back steps one level inside Add and the item screen before closing them.
  
  No security property changes: every check stays; envelope v1, HUMID-PQ1 and HTP/1 are untouched. The identity record's schema stays at 4.

### Minor Changes

- Information architecture and vocabulary pass ("Safe. Secure. Simple."):
  
  - Three tabs: Vault · Activity · **You**. Settings and Security merge into You, in the order they matter: protection checklist, devices, recovery (witnesses · ID chip · recovery card), duress with an inline decoy picker, help others, preferences, a collapsed "About this HumID" with the diagnostics, then Lock now and Close HumID once. The start-tab preference is gone; the app always opens on the vault.
  - One word per concept everywhere a person reads: **Check** (the biometric prompt; the overlay says "Checking it's you"), **Seal / Sealed**, **Open**, **Save a copy**, **Export sealed**, **Recovery card**, **Witnesses**, **ID chip**, **Device / Witness / Recovery / Match code**, **Your vault server**, **Location stamp**. Crypto names, HTP/1, "step-up", "anchor", "seal card" and "biological interrupt" no longer appear in the UI; the plain facts live in one "How HumID protects you" sheet linked from You and from the seal screens.
  - Photo choice shows one preview of the suggested version; "Looks wrong?" reveals the other versions, turning and retake.
  - Wizards (ID, payment card, add device, ID chip, help) get a Back step that Android Back uses before closing the sheet. Terminal lock issues lead straight to "Set up HumID again". An expired witness offer gets "Make a new code".
  - Delete, Remove this device and Cancel the recovery go straight to the check from the row itself; only Close HumID & erase keeps a confirm sheet.
  - Empty states for Vault, Activity, Devices and Witnesses; a11y fixes (44 px text links, legible eyebrows, tablist roles, reduced-motion default, focus on the check overlay); no text selection or copy in the viewer, code boxes and card number; the recovery card sheet no longer shares a sheet type with the payment card sheet.
- The access pass is sealed at rest. Before enrolment there is no seed-derived key, so the
  pass draft (the access code and the blinded request) and the finished blind-signed pass
  used to be stored in IndexedDB as they were. `@humid/pass/atrest` now seals the wallet
  record under a per-install 256-bit AES-GCM key (a non-extractable WebCrypto `CryptoKey`
  kept in its own IndexedDB database, apart from the wallet; AAD `HUMID-PASS-v1`, fresh IV
  per write). A clear record from an older build is re-sealed on the first read and the
  plaintext overwritten; a record that doesn't open is dropped. The RFC 9474 code is
  unchanged. Limits and what remains are in docs/SECURITY.md (*The access pass at rest*).
  
  Also: `npm run test:pen`, a penetration regression pack against the in-process stack
  (tests/pen), run in CI next to the end-to-end tests.
- 2.0 security pass. The duress setting is sealed on the device under a key derived from
  the account seed (@humid/crypto `settingsKey`, `sealSetting`, `openSetting`) and the
  decoy-or-real decision is made after the live check, so nothing on disk says whether
  duress is on or which gesture triggers it. The file-picker exemption from lock-on-hide
  is bounded (60 s, cleared on `pagehide`, a long hidden span locks anyway). Item names
  are forgotten on lock and erase, and a decoy session keeps only decoy names. A chip
  photo's declared size is capped before decoding and no portrait is shown from a chip
  that fails its own hash list. Every HTP request has a 45 s timeout. `openExternal(url)`
  hands https:, tel: and mailto: links to the system (Tauri opener plugin, scoped), and
  the native shell refuses navigation away from the app's own origin. Release builds no
  longer contain the simulated server or demo code (checked by a test), and a simulation
  build is a separate app, `app.humid.vault.sim`. The seal card sheet is `recoveryCard`,
  no longer colliding with the payment-card sheet. iOS excludes the WebView data store
  from backups.

### Patch Changes

- Web build: the browser-tab favicon, home-screen icon and install icons now use the peace-sign HumID logo. Tab sizes (16–48 px and favicon.svg) show the hand without the wordmark so it stays legible; 180 px and up show the full logo. A dedicated maskable icon keeps the logo inside the safe zone on Android. Native app icons are unchanged.
- Updated dependencies
- Updated dependencies
  - @humid/pass@1.1.0
  - @humid/crypto@1.5.0
  - @humid/htp@1.4.1
  - @humid/gate@2.0.3

## 1.14.0

### Minor Changes

- Check-in (docs/CHECKIN.md): a holder arms a timer before a high-stakes situation and checks in with a live check before each deadline; a missed check-in locks the vault, and the end of the grace window (or a duress unlock, or a keyshare restart) erases it for good, vault data only. keyshare keeps the armed account's split keys under a per-account fuse key held in memory only and runs the countdown on the monotonic clock; the gateway relays `/checkin`, `/checkin/arm`, `/checkin/check` and `/checkin/disarm` (`HUMID_CHECKIN=on`, off by default), keeps duress sessions looking ordinary and sweeps erased envelopes from the vault (`DELETE /internal/objects`, keeping decoys); the ledger records `checkin.armed`, `checkin.disarmed` and `checkin.erased`, never a check-in; `@humid/htp` reads the `checkin` policy hint; `@humid/api` gets `checkin`, `armCheckin`, `checkIn` and `disarmCheckin`; the app gets Security ▸ Check-in and a Check-in bar on every tab, and seals the duress setting on the device (2.0 review F1); the Windows server gets `HUMID_CHECKIN` and its admin console warns before any change that stops the server while vaults are armed.

### Patch Changes

- Updated dependencies
  - @humid/htp@1.4.0
  - @humid/api@1.6.0

## 1.13.0

### Minor Changes

- Server administration (docs/ADMIN.md). The gateway relays requests from a local admin console and an administrator's step-up approval of exactly one request (`/admin/requests/:code`, `/admin/summary`); the ledger records `admin.approved`; `@humid/api` gets `adminRequest`, `approveAdmin` and `adminSummary`; `@humid/recovery` gets the `HUMID-ADMIN-v1` admin check and the `ADMIN` QR kind; the app gets Security ▸ Manage this server and a This server card for administrators.

### Patch Changes

- Updated dependencies
  - @humid/api@1.5.0
  - @humid/recovery@1.3.0

## 1.12.0

### Minor Changes

- **Smarter capture.** The camera is calmer and finds what it needs by itself.
  
  - **Barcodes, like a store's scan-and-go**: the back of a license no longer has to
    be lined up. The camera finds the barcode anywhere in view (sideways, upside down,
    small and far off, slightly tilted), highlights it, and reads just that spot at
    full resolution, turned exactly upright. Only a license's barcode is taken: a
    store card's barcode beside it is passed over. While a barcode is in view it never
    takes a fallback photo; it says "Move a little closer" or "Hold steady" instead.
  - **Calmer document photos**: a page or card must hold steady for about a second,
    and the camera's focus must have settled (as sharp as it has been), before the
    photo is taken. A side with a code that won't read is photographed after twelve
    seconds, not nine.
  - **Clean scan**: Take a photo now offers a third version, suggested when the page
    looks like paper: straightened, turned upright, and evened out like a flatbed
    scanner (shadows gone, paper white, ink crisp, a light colour cast taken off,
    coloured forms kept coloured). The straightened photo with its true light, and the
    original, are still one tap away.

## 1.11.0

### Minor Changes

- **Payment cards** are back, and **Apple Wallet passes** can be added.
  
  - **Cards** (credit and debit): scan the front for the number, expiry and name; scan
    the back for the security code and the bank's phone number; tap a contactless card
    on Android or a USB reader; or type it. Everything is read on the device by the
    camera's text reader (Tesseract's English model, now in the app). A card held
    upside down is read turned round. The security code is kept only when you switch
    it on or scan the back; the PIN, chip and stripe data, and any photo of the back
    are never stored. Opening a card takes your face or fingerprint; the number and
    code stay masked until you tap Show, and hide again after 30 seconds. Nothing is
    copied to the clipboard.
  - **Wallet passes**: add a boarding pass, ticket or membership card shared from
    Apple Wallet as a `.pkpass` file. HumID checks it before keeping it: every file
    against the signed manifest, the issuer's signature, and the chain to Apple's
    root certificates (pinned by fingerprint). A changed or forged pass is refused,
    with the reason. Opened, a pass shows its fields and its QR code, and can be saved
    back into Wallet. Google Wallet has no file to export.
  - Pinned items now show a pushpin, not the map pin used for location stamps.

## 1.10.0

### Minor Changes

- f3eb0b1: The camera finds the document by itself, straightens it and turns it upright; documents can be stamped with where they were sealed.
  
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

## 1.9.0

### Minor Changes

- A **Settings** tab: how HumID looks and behaves on this device.
  
  - **Appearance:** Night (default), Day, or match the device; larger text; animations
    on or off; haptics on or off.
  - **Locking:** auto-lock after 1, 2 or 5 minutes of no activity. 5 minutes is the
    longest allowed, and leaving the screen always locks; unlocking is always a face
    or fingerprint. These are shown in Settings but can't be changed.
  - **Vault:** which tab HumID opens on, and how items are sorted (newest, oldest,
    name, or IDs expiring first). **Pin** any item to the top from its details; the
    pin is sealed inside the item's encrypted index entry, so it shows on all your
    devices and the server can't see what's pinned.
  - **Reminders:** how early an ID counts as expiring (30 days to 6 months).
  - **This device** and **Connection** moved here from Security.
  
  Settings are kept on each device; stored values are checked on load, so a tampered
  setting can't stretch the lock beyond 5 minutes. `@humid/idscan`: `status()` takes the
  warning window as an optional third argument (default 90 days).

### Patch Changes

- Updated dependencies
  - @humid/idscan@1.0.2

## 1.8.0

### Minor Changes

- 1a1eecc: Security hardening, P1: the hardware key, attestation and approvals.
  
  - **Android release builds only.** The release workflow never builds a debug APK
    again (debuggable, remotely inspectable, signed with a key anyone had). It
    requires the release signing key, checks the APK is signed with it and not
    debuggable, and prints the certificate digest. The committed test key is gone.
    Phones with an earlier test build must uninstall it before installing this one
    (a different signing key).
  - **Android keys** also need an unlocked phone (`setUnlockedDeviceRequired`).
    iOS checks never reuse a recent unlock.
  - **Attestation, server side:** both security levels must be TEE or StrongBox
    (keymaster level now recorded); the key may only sign; every certificate above
    the leaf must be in date and a CA; Google's revocation and suspension list is
    checked (refreshed every 6 hours); an optional minimum security patch
    (`HUMID_ANDROID_MIN_PATCH`); and the app must be signed with the official HumID
    certificate (or one the operator adds), so a re-signed copy can't join.
    An attestation must come from a session under 5 minutes old and enrols one
    device only. Malformed attestation data is a refusal, never a server error.
  - **Sign the action, not just a nonce (step-up v2).** Before each approval the
    server issues a single-use approval for exactly one action (method and path with
    its target ids, this device, a nonce, an expiry within 60 s). The device key and
    the phone's secure chip both sign it; it's refused if reused, expired, for a
    different action or a different device, or dated in the future. Apps older than
    this release can't approve actions on an updated server: update both.
- f5c066b: Security hardening, P2: QR codes, ID chips, the screen.
  
  - **QR codes** are versioned (`HUMID:2:KIND:CODE:EXPIRY`), say what they're for and
    when they expire, and must be exactly that: no bare codes, old formats, URLs or
    extra fields from the camera, and a scanner only takes the kind it asked for.
    Older apps' QR codes aren't scanned; type the code instead.
  - **The device showing a code checks it too**: a server that answers with a code
    for keys of its own is caught before anything is shown (adding a device, asking
    for recovery help, offering to be a witness).
  - **Adding a device** ends with an account check on both screens: the new device
    joins only once the person confirms they match. The new device's name for itself
    is shown as its own claim, without control or direction-changing characters.
  - **ID chips**: every length and tag from a chip is bounds-checked; a chip can't
    chain answers forever or send malformed secure-messaging fields; session keys
    and the keys derived from the MRZ are wiped after reading.
  - **Passive authentication** (server) now requires the content-type attribute,
    verifies with the certificate the SOD names, requires a document-signing
    certificate, and requires one country throughout: the CSCA's, the document
    signer's, and the issuer in the MRZ. Every data group sent is checked, and the
    MRZ's overall and personal-number check digits too.
  - **Stations**: a chip that can prove it's present (it has an Active Authentication
    key) must answer a fresh challenge at the station too. Stations read chips; they
    no longer load chip files.
  - **The screen** (Android): no screenshots, recording or recents thumbnail; other
    apps can't draw over HumID; taps through an overlay are ignored. No hand-off to
    camera apps. (iPhone, with the next signed build: a cover in the app switcher and
    while the screen is recorded or mirrored; third-party keyboards refused.)
  - **No clipboard**: the seal card and ID numbers can't be copied. Keyboard
    suggestions and learning are off in every field.
  - **Server logs** record each request's route, never the codes or ids in its path.

### Patch Changes

- Updated dependencies [1a1eecc]
- Updated dependencies [f5c066b]
  - @humid/htp@1.3.0
  - @humid/recovery@1.2.0
  - @humid/api@1.4.0
  - @humid/emrtd@1.2.0
  - @humid/idscan@1.0.1
  - @humid/gate@2.0.2

## 1.7.6

### Patch Changes

- 03c9c2e: Scan an ID: details fill in again in the phone and desktop apps, and auto-capture
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

## 1.7.5

### Patch Changes

- ed70c34: Scan an ID: the camera takes the photo by itself, for every side of every document.
  
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

## 1.7.4

### Patch Changes

- 29e7f50: Reconnecting costs nothing while the connection is fine: the 30-second heartbeat is
  gone, so a healthy, idle HumID sends no requests at all. A drop is still noticed the
  moment any request fails, when the phone goes offline or back online, or when HumID
  comes back to the screen; retries run only while it's disconnected. The bar's button
  is now "Reconnect now".

## 1.7.3

### Patch Changes

- da192db: The app notices when the vault server can't be reached, and reconnects by itself.
  
  - Every request reports whether the server answered; the phone's online/offline
    events, HumID coming back to the screen, and a light 30-second heartbeat while
    the server is in use do too, so a drop is noticed even when nothing is tapped.
  - After a drop it retries with backoff (1, 2, 4, 8, 15, then every 30 s, with
    jitter) for as long as it takes, pausing only while HumID is off the screen;
    coming back online or back to the screen tries at once.
  - A bar at the top says what's happening ("Can't reach your vault · Trying again
    in 8 s", with Try now; or "No internet connection"). It waits 1.5 s, so blips
    don't flash it, and replaces the stack of "can't reach" error toasts.
  - On recovery the screen reloads in the same session. If the server restarted and
    forgot the session, the app locks once with "Your session ended" (one live check
    signs back in), instead of three raw "Unknown session" errors.
  - An unreachable server is no longer reported as "Public log check failed … your
    history may have been altered": the public-log check waits until it's back.

## 1.7.2

### Patch Changes

- 1f7c706: Android: "biometric key is gone" no longer leaves you stuck.
  
  - Android never backs up or transfers HumID's data (`allowBackup="false"` and data
    extraction rules for Android 12+). The Keystore keys that unlock a HumID can't
    leave the phone, so a restored copy, after a reinstall or on a new phone, was a
    HumID nothing could open. A reinstall now starts cleanly at Welcome.
  - When the phone has deleted the key anyway (its fingerprints or face changed), the
    app says so on its own screen, with "Set HumID up again", instead of failing
    every unlock with the same message. The gate reports it as `key_invalidated`.
  - The Android gate notices an invalidated key before showing the fingerprint prompt.
- Updated dependencies [1f7c706]
  - @humid/gate@2.0.1

## 1.7.1

### Patch Changes

- d19bba2: Android: taking a document photo is confirmed, and back never leaves HumID.
  
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

## 1.7.0

### Minor Changes

- b6e32b8: Offline mode, read only. With no connection (or the vault server down), Unlock still
  works: the same live face or fingerprint check opens a copy kept on the device of the
  document list, Activity and Security as of the last time it was online. Documents
  themselves never open offline: the document and its key stay in the vault, so split
  keys and the per-hour cap protect exactly as before. The copy is sealed under a key
  derived from the account seed (@humid/crypto `offlineKey`, `sealOffline`,
  `openOffline`), isn't written during a duress session, and is erased with the device's
  vault or when the server says the device was removed. The duress gesture works offline
  and shows only the decoy documents. "Reconnect" signs back in with one live check.

### Patch Changes

- Updated dependencies [b6e32b8]
  - @humid/crypto@1.4.0
  - @humid/store@1.4.0

## 1.6.0

### Minor Changes

- ab3747b: Setup and first-run fixes from the user flow review. Each step's main button stays
  on screen on small phones; the seal card is confirmed by typing back one group of it
  (printable in browsers and on Windows and Linux); the vault shows "Finish protecting
  your HumID" with a button for each step left (seal card, a second proof, a second
  device, and optional duress) until it's done; app builds with a pinned server skip
  the "trust this server" step; new documents get a suggested category instead of
  always "Identity"; toasts sit at the bottom; every control is at least 44 px; the
  step indicator is a labelled progress bar; Android gives a short buzz when a check
  passes or fails.

## 1.5.0

### Minor Changes

- 5910975: Anonymous payment for registration. New `@humid/pass` module (1.0.0) (RFC 9474 blind
  signatures, RSABSSA-SHA384-PSS-Randomized, and access codes) and a new `access`
  service (1.0.0) that sells nothing it can link to an account: access codes are swapped
  for blind-signed passes, and registration spends a pass. The gateway requires a
  pass to create a HumID unless `HUMID_REGISTRATION=open`. The app gains an access
  step in onboarding, keeps unspent passes in a new `wallet` store (IndexedDB v2)
  so a paid code survives a crash, and the HTP client reads the new
  `registration` / `passBuyUrl` policy hints. See docs/ANONYMITY.md.
- a885c7d: Split keys, against spyware that reads a phone's memory during a biometric check.
  Every new document is encrypted under its own random 256-bit key before it is
  sealed to the account's keys; that key lives only in the new `keyshare` service
  (1.0.0) and is released one document at a time, inside the same live chip-signed
  step-up that releases the envelope, under a per-account hourly cap. The gateway
  strips the key from uploads before the vault sees them and undoes an upload whose
  key can't be stored. Copied account keys, even with a full copy of the vault,
  open nothing alone. Older documents keep opening as before. The app splits only
  when the server says it can (`policy.splitKeys`). See docs/SECURITY.md#a-compromised-phone.

### Patch Changes

- Updated dependencies [5910975]
- Updated dependencies [a885c7d]
  - @humid/api@1.3.0
  - @humid/htp@1.2.0
  - @humid/store@1.3.0
  - @humid/crypto@1.3.0
