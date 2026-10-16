# @humid/mobile

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
