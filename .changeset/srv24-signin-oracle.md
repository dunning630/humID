---
"@humid/identity-service": patch
"@humid/gateway-service": patch
---

Sign-in no longer tells an unknown account, an unknown device and a wrong key apart (audit SRV-24): all three are `401 bad_proof` with one message, after the same signature check (a throwaway key stands in for a device that doesn't exist), and the ledger note for a real account is written after the reply. A closed account or a removed device is still named, but only to a caller who has just signed with that device's own key.
