# @humid/crypto

## 1.4.0

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

## 1.3.0

### Minor Changes

- a885c7d: Split keys, against spyware that reads a phone's memory during a biometric check.
  Every new document is encrypted under its own random 256-bit key before it is
  sealed to the account's keys; that key lives only in the new `keyshare` service
  (1.0.0) and is released one document at a time, inside the same live chip-signed
  step-up that releases the envelope, under a per-account hourly cap. The gateway
  strips the key from uploads before the vault sees them and undoes an upload whose
  key can't be stored. Copied account keys, even with a full copy of the vault,
  open nothing alone. Older documents keep opening as before. The app splits only
  when the server says it can (`policy.splitKeys`). See docs/SECURITY.md#a-compromised-phone.

## 1.2.0

- `prepareSeal` / `finishSeal`: seal in two steps (encrypt with public keys, then sign), so the device's liveness key can sign the ciphertext hash inside the same biometric check. Envelope format unchanged.

## 1.0.0

- Initial release, split out of the single-file HumID Vault. HumID sealing suites behind a registry. Ships HUMID-PQ1.
