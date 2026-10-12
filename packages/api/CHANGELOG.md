# @humid/api

## 1.1.0

- Devices: `register` enrols the first device, `enrollDevice` adds one, `removeDevice`.
- Device links, recovery card, recovery contacts, recovery requests and alerts.
- Every typed code (device link, contact, recovery request) is recomputed from the keys the server returns; a mismatch throws `code_mismatch`.

## 1.0.0

- First release: register, sign in, vault, verified ledger over HTP/1.
