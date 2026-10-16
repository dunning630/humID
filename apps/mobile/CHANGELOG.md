# @humid/mobile

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
