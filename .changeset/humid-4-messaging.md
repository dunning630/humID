---
"@humid/msg": minor
---

HumID 4.0 (provisional): new module for person-to-person messaging between HumID holders. Per-contact persona IDs (unlinkable across contacts), invites sealed under the invite secret, contact approval with a live check, hybrid ML-KEM-1024 + X25519 handshake dual-signed with ML-DSA-87 and SLH-DSA-SHA2-256f, a hybrid post-quantum double ratchet, blind live stamps (a live human approved this message, unlinkable to the account), fixed-size padded wire objects on daily-rotating mailboxes, a relay contract with IPv6 /64 rate keys, rollback-proof sealed state, drop detection and a swappable crypto backend for the platform's constant-time code. See docs/MESSAGING.md.
