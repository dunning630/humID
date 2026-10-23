---
"@humid/audit": minor
"@humid/api": minor
"@humid/ledger-service": minor
"@humid/mobile": patch
---

The ledger page and the public log must describe one history (audit CRYPTO-01). `api.continuity({ head })` asks the log about the head of the page the phone verified and fails with `mismatch: true` unless the log holds that same seq and hash; `verifyLedger(page, { previousHead })` refuses a page that dropped or changed the head the phone confirmed last time, and `api.ledger({ previousHead })` links a page that starts later back to it through the new `GET /ledger/events?from=&to=` range (checked with the new `verifyBridge`). Activity shows a mismatch as a failed check. Release builds can carry the ledger key's fingerprint (`HUMID_LEDGER_KEY_FP`, logged by the ledger and printed by `deploy/setup.sh`), so a new install doesn't trust the first key it sees.
