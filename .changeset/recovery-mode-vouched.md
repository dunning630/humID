---
"@humid/mobile": minor
"@humid/identity-service": patch
"@humid/recovery-service": patch
"@humid/gateway-service": patch
---

A phone makes recovery pieces only for a recovery choice it can vouch for itself (V74B-01).

- `mayMakePieces` now needs the shown hardened statement to be `vouched`: equal to or after this phone's pin, or the pin it got from the device that added it, or (on a phone recovered with two-proof pieces and no pin yet) hardened at exactly the epoch of the pieces it combined. `judgeMode` takes that floor; `finishJoin` stores it as `modeFloor` (`recoveredEpoch`).
- A signed statement the phone can't vouch for (no pin and no floor, or an older server with no modes) is shown but never pinned, and `partOf` refuses with the reason. Recovery and Protection ask the holder to **Check and confirm**. `confirmModeHere` shows the mode history from the verified ledger, then signs the next statement under a live check and pins it.
- `loadRecoveryMode` loads the ledger itself when this session hasn't verified a page, and refuses a statement when the ledger's `recovery.mode_set` at the same version names a different one.
- `recovery.mode_set` ledger entries now carry `hash`, the statement's `recoveryModeHash`. Identity's and the recovery service's `POST /internal/recovery-mode` return it.
- A cosigned public-log checkpoint is not counted as a vouch: it proves an entry is in the log, not that nothing newer exists. docs/RECOVERY.md "When a phone makes recovery pieces" states the rule and the per-device limit that remains.
