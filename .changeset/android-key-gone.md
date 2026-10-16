---
"@humid/mobile": patch
"@humid/gate": patch
---

Android: "biometric key is gone" no longer leaves you stuck.

- Android never backs up or transfers HumID's data (`allowBackup="false"` and data
  extraction rules for Android 12+). The Keystore keys that unlock a HumID can't
  leave the phone, so a restored copy, after a reinstall or on a new phone, was a
  HumID nothing could open. A reinstall now starts cleanly at Welcome.
- When the phone has deleted the key anyway (its fingerprints or face changed), the
  app says so on its own screen, with "Set HumID up again", instead of failing
  every unlock with the same message. The gate reports it as `key_invalidated`.
- The Android gate notices an invalidated key before showing the fingerprint prompt.
