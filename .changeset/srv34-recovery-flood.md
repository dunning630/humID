---
"@humid/recovery-service": patch
"@humid/gateway-service": patch
---

Anonymous recovery requests are bounded (audit SRV-34): the gateway lets one network (IPv4 address or IPv6 /64) start `HUMID_RECOVERY_STARTS_PER_HOUR` (20) an hour; the recovery service keeps at most `HUMID_RECOVERY_MAX_UNBOUND` (20,000) requests with no proof yet and refuses more as busy; and one that gets no first proof within `HUMID_RECOVERY_UNBOUND_TTL_MS` (24 h) ends and is deleted, instead of staying a week.
