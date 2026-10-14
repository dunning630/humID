# @humid/htp

## 1.1.0

- Accounts with many devices: `deviceId`, `deviceMessage` (signed by the account key and the device key); sign-in proofs name `<account>/<device>` and are signed by the device key.
- Client keeps the server's `policy` hint (`devicePolicy`) from `/htp/v1/keys`.
- Liveness proofs: `liveMessage` (step-ups) and `sealLiveMessage` (sealed files), signed by the phone's hardware liveness key.
- `ticket(method, path)` reserves a request slot before the biometric prompt, so the liveness key signs exactly that request; `call` accepts `{ ticket, sign }`.

## 1.0.0

- HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, replay window, register / login / step-up proofs, server key pinning.
