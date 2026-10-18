# @humid/ledger-service

## 1.3.1

### Patch Changes

- dac25fd: Hardening from the October 2026 security audits. A malformed request target (`GET //`, `GET http://[`) is a 400 and can no longer exit a service; an unexpected error in one request is a 500 for that request only. Body caps are enforced before anything is buffered: a declared Content-Length over the cap is refused unread, streamed bodies are cut off at the cap, and the gateway picks the frame cap from the frame header (unknown session refused at once, 512 KiB before sign-in, large frames only after sign-in) with per-address and global caps on uploads in flight. Sign-in throttling no longer lets a stranger who knows an account id lock the holder out: only failed proofs are counted, a valid proof is never refused, and per-address and global failure budgets limit ledger noise. JSON bodies that are not objects are a 400 instead of a 500.
- Updated dependencies [dac25fd]
  - @humid/svc@1.2.0

## 1.3.0

### Minor Changes

- Check-in (docs/CHECKIN.md): a holder arms a timer before a high-stakes situation and checks in with a live check before each deadline; a missed check-in locks the vault, and the end of the grace window (or a duress unlock, or a keyshare restart) erases it for good, vault data only. keyshare keeps the armed account's split keys under a per-account fuse key held in memory only and runs the countdown on the monotonic clock; the gateway relays `/checkin`, `/checkin/arm`, `/checkin/check` and `/checkin/disarm` (`HUMID_CHECKIN=on`, off by default), keeps duress sessions looking ordinary and sweeps erased envelopes from the vault (`DELETE /internal/objects`, keeping decoys); the ledger records `checkin.armed`, `checkin.disarmed` and `checkin.erased`, never a check-in; `@humid/htp` reads the `checkin` policy hint; `@humid/api` gets `checkin`, `armCheckin`, `checkIn` and `disarmCheckin`; the app gets Security ▸ Check-in and a Check-in bar on every tab, and seals the duress setting on the device (2.0 review F1); the Windows server gets `HUMID_CHECKIN` and its admin console warns before any change that stops the server while vaults are armed.

### Patch Changes

- Updated dependencies
  - @humid/htp@1.4.0

## 1.2.0

### Minor Changes

- Server administration (docs/ADMIN.md). The gateway relays requests from a local admin console and an administrator's step-up approval of exactly one request (`/admin/requests/:code`, `/admin/summary`); the ledger records `admin.approved`; `@humid/api` gets `adminRequest`, `approveAdmin` and `adminSummary`; `@humid/recovery` gets the `HUMID-ADMIN-v1` admin check and the `ADMIN` QR kind; the app gets Security ▸ Manage this server and a This server card for administrators.
