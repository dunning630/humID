---
"@humid/gateway-service": patch
"@humid/identity-service": patch
"@humid/mobile": patch
---

Registering creates an account and never adds a device to one that already exists (pre-audit REC-01, a bypass of PC-02). `POST /auth/register` with an existing account's keys used to fall through to "add a device": the account seed plus any attested phone joined the account with no device link, no recovery, no wait and no alert, even during a duress lockdown, and could open split documents. Identity now answers `409 identity_exists` for an existing account, the gateway binds a session only for a newly created account, and the access pass is given back. Later devices join only through an approved device link or a released recovery (`POST /auth/device`). The simulation server follows the same rule.
