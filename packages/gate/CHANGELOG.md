# @humid/gate

## 2.0.1

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

## 2.0.0

- Gate contract v2: every check signs a challenge with the device's hardware liveness key (`live`), and can attest a fresh key to the session (`attest`).
- Removed the WebAuthn passkey gate: passkeys can fall back to a device PIN or password.
- Demo gate only in builds made with HUMID_ALLOW_DEMO=1.

## 1.0.0

- Initial release, split out of the single-file HumID Vault. Biometric interrupt gates: native OS key stores, WebAuthn PRF, demo.
