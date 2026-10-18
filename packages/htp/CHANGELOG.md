# @humid/htp

## 1.4.1

### Patch Changes

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

## 1.4.0

### Minor Changes

- Check-in (docs/CHECKIN.md): a holder arms a timer before a high-stakes situation and checks in with a live check before each deadline; a missed check-in locks the vault, and the end of the grace window (or a duress unlock, or a keyshare restart) erases it for good, vault data only. keyshare keeps the armed account's split keys under a per-account fuse key held in memory only and runs the countdown on the monotonic clock; the gateway relays `/checkin`, `/checkin/arm`, `/checkin/check` and `/checkin/disarm` (`HUMID_CHECKIN=on`, off by default), keeps duress sessions looking ordinary and sweeps erased envelopes from the vault (`DELETE /internal/objects`, keeping decoys); the ledger records `checkin.armed`, `checkin.disarmed` and `checkin.erased`, never a check-in; `@humid/htp` reads the `checkin` policy hint; `@humid/api` gets `checkin`, `armCheckin`, `checkIn` and `disarmCheckin`; the app gets Security ▸ Check-in and a Check-in bar on every tab, and seals the duress setting on the device (2.0 review F1); the Windows server gets `HUMID_CHECKIN` and its admin console warns before any change that stops the server while vaults are armed.

## 1.3.0

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

## 1.2.0

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

## 1.1.0

- Accounts with many devices: `deviceId`, `deviceMessage` (signed by the account key and the device key); sign-in proofs name `<account>/<device>` and are signed by the device key.
- Client keeps the server's `policy` hint (`devicePolicy`) from `/htp/v1/keys`.
- Liveness proofs: `liveMessage` (step-ups) and `sealLiveMessage` (sealed files), signed by the phone's hardware liveness key.
- `ticket(method, path)` reserves a request slot before the biometric prompt, so the liveness key signs exactly that request; `call` accepts `{ ticket, sign }`.

## 1.0.0

- HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, replay window, register / login / step-up proofs, server key pinning.
