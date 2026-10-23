---
"@humid/recovery-service": patch
---

`HUMID_STATION_ACCOUNTS="*"` (every account is a verification station) is refused at start-up unless `HUMID_ALLOW_ANY_STATION=dev` is also set, and logs an error line when it is (audit VAULT-08). Local dev servers set the flag; a production server can no longer become an every-account station by one setting.
