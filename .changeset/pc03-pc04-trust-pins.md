---
"@humid/crypto": minor
"@humid/audit": minor
"@humid/api": minor
"@humid/mobile": patch
---

What a malicious server can't make the phone believe (audit PC-03, PC-04). `open(envelope, keys, { signer })` refuses an envelope signed by anyone but `signer` (`wrong_signer`); the app's read path passes the account key, so a server can't plant a forged document. `verifyCheckpoint` counts only cosigners from a `cosigners` map (new `parseCosigners`), checked under the built-in key, never one the server sends; the app builds the list in from `HUMID_TLOG_COSIGNERS` and pins the ledger key it first verifies (`ledgerKeyFp`).
