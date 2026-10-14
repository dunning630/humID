# @humid/gate

## 2.0.0

- Gate contract v2: every check signs a challenge with the device's hardware liveness key (`live`), and can attest a fresh key to the session (`attest`).
- Removed the WebAuthn passkey gate: passkeys can fall back to a device PIN or password.
- Demo gate only in builds made with HUMID_ALLOW_DEMO=1.

## 1.0.0

- Initial release, split out of the single-file HumID Vault. Biometric interrupt gates: native OS key stores, WebAuthn PRF, demo.
