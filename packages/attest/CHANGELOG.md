# @humid/attest

## 1.0.0

- Android key attestation: chain to pinned Google roots (RSA root and Key Attestation CA1), KeyDescription parsing, HumID policy (secure hardware, ECDSA P-256, biometric-only, per-use, locked verified boot, app package).
- Apple App Attest: chain to Apple's root, nonce, app id, environment, key id.
- Liveness signature checks (ECDSA P-256 / SHA-256).
