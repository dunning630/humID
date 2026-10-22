---
"@humid/msg": minor
"@humid/api": minor
"@humid/htp": patch
"@humid/store": minor
"@humid/relay-service": minor
"@humid/access-service": minor
"@humid/gateway-service": minor
---

HumID 4.1 preview (non-production): person-to-person messaging in the app, under one rule: nobody interacts without a live check. Strict mode in @humid/msg (requests, acceptances and every message must carry a live stamp; anything without one is discarded unread and nothing it says is applied), stamps bound to their send time and counted once, the mutual "both here" state (live.js), "I'm here" receipts, one check per action (at most two stamps). New relay service (no accounts, no addresses, per-network daily quota); a separate stamp key and daily totals in access; /msg/keys, /msg/stats, /msg/stamp and the relay routes on the gateway (relay only from sessions that never sign in). Messaging is off unless the server turns it on (HUMID_RELAY_URL with Docker, HUMID_MESSAGING=on on Windows). See docs/MESSAGING.md.
