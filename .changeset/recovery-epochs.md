---
"@humid/recovery": minor
"@humid/api": minor
"@humid/recovery-service": minor
"@humid/mobile": minor
---

Recovery pieces rotate (CRYPTO-02). Before, every piece sat on one fixed line through the seed, so two removed witnesses plus any current piece rebuilt it.

- An account's recovery epoch is part of its signed recovery-mode statement. `quorumParts(seed, epoch)` parts carry `epoch`, and the card and key AAD and the witness share carry it too from epoch 2 on. `combineQuorum` refuses to combine parts from different epochs.
- Signing a new epoch ("Make new recovery pieces" on the Recovery screen, and every mode switch) makes the recovery service delete every stored piece from older sets and cancel any recovery under way. It also refuses new pieces for an older set (`stale_epoch`), or with no epoch once the account is past epoch 1 (`update_required`).
- `setCard`, `setContacts`, `addKey` and `setAnchor` take an `epoch`. Released recoveries say which `epoch` their pieces are from.
- The app no longer says a removed witness's or card's piece "no longer works". It says the piece no longer counts on this server, and that new pieces stop it fitting anything new. Two old pieces still fit each other, because the account seed doesn't change (V74-04).
