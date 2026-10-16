---
"@humid/mobile": minor
"@humid/crypto": minor
"@humid/store": minor
---

Offline mode, read only. With no connection (or the vault server down), Unlock still
works: the same live face or fingerprint check opens a copy kept on the device of the
document list, Activity and Security as of the last time it was online. Documents
themselves never open offline: the document and its key stay in the vault, so split
keys and the per-hour cap protect exactly as before. The copy is sealed under a key
derived from the account seed (@humid/crypto `offlineKey`, `sealOffline`,
`openOffline`), isn't written during a duress session, and is erased with the device's
vault or when the server says the device was removed. The duress gesture works offline
and shows only the decoy documents. "Reconnect" signs back in with one live check.
