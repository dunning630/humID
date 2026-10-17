# @humid/keyshare-service

## 1.1.0

### Minor Changes

- Check-in (docs/CHECKIN.md): a holder arms a timer before a high-stakes situation and checks in with a live check before each deadline; a missed check-in locks the vault, and the end of the grace window (or a duress unlock, or a keyshare restart) erases it for good, vault data only. keyshare keeps the armed account's split keys under a per-account fuse key held in memory only and runs the countdown on the monotonic clock; the gateway relays `/checkin`, `/checkin/arm`, `/checkin/check` and `/checkin/disarm` (`HUMID_CHECKIN=on`, off by default), keeps duress sessions looking ordinary and sweeps erased envelopes from the vault (`DELETE /internal/objects`, keeping decoys); the ledger records `checkin.armed`, `checkin.disarmed` and `checkin.erased`, never a check-in; `@humid/htp` reads the `checkin` policy hint; `@humid/api` gets `checkin`, `armCheckin`, `checkIn` and `disarmCheckin`; the app gets Security ▸ Check-in and a Check-in bar on every tab, and seals the duress setting on the device (2.0 review F1); the Windows server gets `HUMID_CHECKIN` and its admin console warns before any change that stops the server while vaults are armed.

### Patch Changes

- Updated dependencies
  - @humid/htp@1.4.0
