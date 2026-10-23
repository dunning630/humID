---
"@humid/recovery": minor
"@humid/api": minor
"@humid/identity-service": minor
"@humid/recovery-service": minor
"@humid/gateway-service": minor
"@humid/ledger-service": minor
---

Two recovery modes, chosen at setup (docs/RECOVERY.md#two-recovery-modes). **Holder-only**: only the holder's own enrolled devices open anything. No card, witnesses, ID anchor or security key is ever stored, and the recovery service refuses every escrow write and every recovery for the account. **Hardened**: two proofs, a wait and a veto, as before. The mode is a statement signed by the account key (`recoveryModeMessage`: `HUMID-RECMODE-v1 ‖ lp(account, mode, version, epoch)`). It is kept by identity (shown in `/me`) and by recovery (`GET /recovery/mode`), checked again on every escrow route, and recorded as `recovery.mode_set`. A stored statement that no longer verifies counts as holder-only. Switching: `POST /recovery/mode` with a step-up. Switching to holder-only is refused (`escrow_remains`) until every piece has been deleted, each one under its own step-up; `DELETE /recovery/keys` (all keys) is now reachable through the gateway. Accounts with no statement on file are hardened.
