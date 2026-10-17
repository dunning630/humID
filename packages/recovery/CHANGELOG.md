# @humid/recovery

## 1.3.0

### Minor Changes

- Server administration (docs/ADMIN.md). The gateway relays requests from a local admin console and an administrator's step-up approval of exactly one request (`/admin/requests/:code`, `/admin/summary`); the ledger records `admin.approved`; `@humid/api` gets `adminRequest`, `approveAdmin` and `adminSummary`; `@humid/recovery` gets the `HUMID-ADMIN-v1` admin check and the `ADMIN` QR kind; the app gets Security ▸ Manage this server and a This server card for administrators.

## 1.2.0

### Minor Changes

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

## 1.0.0

- First release: key codes (link, contact offer, recovery request), recovery
  card format and sealing, Shamir secret sharing over GF(2^8), contact share
  payload.
