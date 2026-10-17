# @humid/ledger-service

## 1.2.0

### Minor Changes

- Server administration (docs/ADMIN.md). The gateway relays requests from a local admin console and an administrator's step-up approval of exactly one request (`/admin/requests/:code`, `/admin/summary`); the ledger records `admin.approved`; `@humid/api` gets `adminRequest`, `approveAdmin` and `adminSummary`; `@humid/recovery` gets the `HUMID-ADMIN-v1` admin check and the `ADMIN` QR kind; the app gets Security ▸ Manage this server and a This server card for administrators.
