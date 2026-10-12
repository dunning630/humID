# @humid/htp

## 1.1.0

- Accounts with many devices: `deviceId`, `deviceMessage` (signed by the account key and the device key); sign-in proofs name `<account>/<device>` and are signed by the device key.
- Client keeps the server's `policy` hint (`minAssurance`) from `/htp/v1/keys`.

## 1.0.0

- HTP/1: hybrid ML-KEM-1024 + X25519 handshake, AES-256-GCM frames, replay window, register / login / step-up proofs, server key pinning.
