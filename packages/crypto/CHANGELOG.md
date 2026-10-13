# @humid/crypto

## 1.2.0

- `prepareSeal` / `finishSeal`: seal in two steps (encrypt with public keys, then sign), so the device's liveness key can sign the ciphertext hash inside the same biometric check. Envelope format unchanged.

## 1.0.0

- Initial release, split out of the single-file HumID Vault. HumID sealing suites behind a registry. Ships HUMID-PQ1.
