---
"@humid/msg": minor
"@humid/api": minor
"@humid/htp": patch
"@humid/svc": patch
"@humid/relay-service": minor
"@humid/access-service": minor
"@humid/gateway-service": minor
---

Messaging review fixes (4.1 preview). Stamps only for a hardware-proven phone, whatever the device policy (MSG-03). Hourly stamp keys: the issuer signs only with this hour's key and phones count a stamp only for a time inside its key's hour, so stamps can't be stockpiled (MSG-01); request stamps cover their time; a stamp under a key not fetched yet waits for a refetch instead of being discarded (MSG-07). Delete-for-both stamps and encrypts everything before erasing, works in steps within the 2-stamps-per-check cap, and each conversation keeps its unposted messages in its own sealed save (PC-28). Backfill after days away and missing-message notices (MSG-04); a relay session per deposit and per conversation, no "tomorrow" in polls (MSG-02). Relay limits that never fail closed, quotas per IPv4 /24 and IPv6 /32, fair share near full (MSG-05). One person per invite (PC-26). Safety-code "Different" everywhere, approval that doesn't spend the invite on failure, request-flood handling, stamped challenges (MSG-06/08/09/11). Stamped media and releases verify against retired stamp keys (MSG-10). Quiet relay and issuer logs, thresholded /msg/stats, sealed outbox records, honest copy (MSG-13). New settings: HUMID_STAMP_EPOCH_MINUTES (60), HUMID_STAMP_ACCEPT_DAYS now defaults to 15, HUMID_RELAY_MAX_BLOCK_BYTES_DAY, HUMID_RELAY_FAIR_ABOVE, HUMID_MSG_STATS_MIN. HUMID_STAMP_ISSUE_DAYS is gone. See docs/MESSAGING.md.
