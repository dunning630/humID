---
"@humid/attest": patch
---

Refuse Android liveness keys from apps signed with the leaked test key (`tools/android-test.keystore`, certificate SHA-256 `b066cd45…928c`), even when a server lists it in `HUMID_ANDROID_CERT_DIGESTS` or sets `HUMID_ANDROID_ALLOW_ANY_SIGNER=1`. New export `REVOKED_ANDROID_CERTS`; new error code `revoked_signer`.
