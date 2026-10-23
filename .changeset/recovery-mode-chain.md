---
"@humid/recovery": major
"@humid/api": patch
"@humid/identity-service": minor
"@humid/recovery-service": minor
"@humid/gateway-service": minor
"@humid/mobile": minor
---

The recovery mode can't be deleted or rolled back below what each device has seen (V74-01, V74-02).

- Each mode statement now names the hash of the one before it: `recoveryModeMessage(account, mode, version, epoch, prev)`. Version 1 names `RECMODE_GENESIS`. `followsMode` decides whether a statement may replace another.
- Identity accepts only statements that follow its own and is the source of truth.
- The recovery service keeps a high-water mark that only goes up. A missing, older or forked row reads as holder-only.
- Before every recovery route, the gateway brings whichever service is behind up to the newest statement (`syncMode`). Recoveries started on a stale row are refused.
- The phone pins the newest statement it has checked (`modePin`, in its sealed identity record, written through `core/identity.js` `updateIdentity`). It also checks the served statement against identity's copy and the ledger's latest `recovery.mode_set`. A missing, lower or forked statement makes it warn and act as holder-only: it makes no recovery piece.
- A device that joins by link gets the approving device's pin inside the sealed hand-over.

Breaking: version 2 and later statements need `prev`.
