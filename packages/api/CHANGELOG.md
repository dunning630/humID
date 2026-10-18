# @humid/api

## 1.6.0

### Minor Changes

- Check-in (docs/CHECKIN.md): a holder arms a timer before a high-stakes situation and checks in with a live check before each deadline; a missed check-in locks the vault, and the end of the grace window (or a duress unlock, or a keyshare restart) erases it for good, vault data only. keyshare keeps the armed account's split keys under a per-account fuse key held in memory only and runs the countdown on the monotonic clock; the gateway relays `/checkin`, `/checkin/arm`, `/checkin/check` and `/checkin/disarm` (`HUMID_CHECKIN=on`, off by default), keeps duress sessions looking ordinary and sweeps erased envelopes from the vault (`DELETE /internal/objects`, keeping decoys); the ledger records `checkin.armed`, `checkin.disarmed` and `checkin.erased`, never a check-in; `@humid/htp` reads the `checkin` policy hint; `@humid/api` gets `checkin`, `armCheckin`, `checkIn` and `disarmCheckin`; the app gets Security ▸ Check-in and a Check-in bar on every tab, and seals the duress setting on the device (2.0 review F1); the Windows server gets `HUMID_CHECKIN` and its admin console warns before any change that stops the server while vaults are armed.

### Patch Changes

- Updated dependencies
  - @humid/htp@1.4.0

## 1.5.0

### Minor Changes

- Server administration (docs/ADMIN.md). The gateway relays requests from a local admin console and an administrator's step-up approval of exactly one request (`/admin/requests/:code`, `/admin/summary`); the ledger records `admin.approved`; `@humid/api` gets `adminRequest`, `approveAdmin` and `adminSummary`; `@humid/recovery` gets the `HUMID-ADMIN-v1` admin check and the `ADMIN` QR kind; the app gets Security ▸ Manage this server and a This server card for administrators.

### Patch Changes

- Updated dependencies
  - @humid/recovery@1.3.0

## 1.4.0

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

### Patch Changes

- Updated dependencies [1a1eecc]
- Updated dependencies [f5c066b]
  - @humid/htp@1.3.0
  - @humid/recovery@1.2.0

## 1.3.0

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
  - @humid/htp@1.2.0

## 1.1.0

- Devices: `register` enrols the first device, `enrollDevice` adds one, `removeDevice`.
- Device links, recovery card, recovery contacts, recovery requests and alerts.
- Every typed code (device link, contact, recovery request) is recomputed from the keys the server returns; a mismatch throws `code_mismatch`.
- Live checks: `register`, `enrollDevice` and `login` carry the liveness key's signature (and, when a device joins, its attestation); `ticket(op, …args)` for step-ups; `register` can save a recovery card under the same check.

## 1.0.0

- First release: register, sign in, vault, verified ledger over HTP/1.
