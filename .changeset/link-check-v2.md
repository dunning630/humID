---
"@humid/recovery": major
"@humid/api": patch
"@humid/recovery-service": patch
"@humid/gateway-service": patch
"@humid/mobile": minor
---

Codes a server can't precompute (CRYPTO-08).

- The match code for adding a device is `accountCheck(account, linkKemPk, linkXPk)` (`HUMID-ACCOUNT-CHECK-v2`). It commits to the new device's link keys, not just the public account id, so it can't be ground ahead of time. Breaking: `accountCheck` now needs the link's keys.
- Recovery-request codes have 16 characters (80 bits), because they live up to a week. Link, witness and admin codes keep 12 (60 bits). `parseCode`, QR codes and the gateway routes accept both lengths.
