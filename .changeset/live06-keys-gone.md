---
"@humid/api": minor
"@humid/identity-service": minor
"@humid/gateway-service": minor
"@humid/ledger-service": minor
"@humid/mobile": patch
---

The server learns when a device's biometric keys are gone (audit LIVE-06). When Android or iOS destroys them (fingerprints or face changed, HumID reinstalled), the app reports it with `HumidApi.reportKeysGone({ id, device })` (`POST /auth/key-invalidated`, no sign-in: there's nothing left to sign with). Identity marks the device `needsSetup` in `/me` until its next live sign-in; the ledger records `device.keys_invalidated` (new event type, at most once a day per device) and Activity shows it. The answer is the same whether or not the account or device exists; a signed-in session can report only its own account's devices; a duress session sends nothing.
