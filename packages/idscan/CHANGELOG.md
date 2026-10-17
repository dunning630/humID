# @humid/idscan

## 1.0.2

### Patch Changes

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

## 1.0.1

### Patch Changes

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
