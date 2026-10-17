# @humid/identity-service

## 1.2.0

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

### Patch Changes

- Updated dependencies [1a1eecc]
- Updated dependencies [f5c066b]
  - @humid/attest@1.2.0
  - @humid/htp@1.3.0
  - @humid/svc@1.1.1
