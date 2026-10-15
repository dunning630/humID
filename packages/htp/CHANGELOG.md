# @humid/htp

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
