---
"@humid/htp": minor
"@humid/gateway-service": patch
---

Handshakes and the session table hold up under a flood (audit CRYPTO-04, SRV-25). `HtpServer.hello(wire, now, { group })` refuses a hello whose client nonce it has already answered (409 `replay`), lets each group (the gateway passes the client's IPv4 address or IPv6 /64) hold 20 sessions that haven't signed in, drops those after 2 idle minutes, and when the table is full evicts the least recently used unsigned session instead of answering `busy` to everyone. Frames refuse meta JSON over 64 KiB (`MAX_META_BYTES`, 413 `too_large`) before parsing it. Gateway: handshake, cosign and failed sign-in limits are per IPv4 address or IPv6 /64, and the limiters forget their least recently used key instead of clearing every counter at 100,000 keys (`Buckets` is exported).
