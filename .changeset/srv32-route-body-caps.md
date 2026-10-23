---
"@humid/gateway-service": patch
"@humid/htp": patch
---

Per-route body caps (audit SRV-32, the SRV-25 residue). A signed-in session's frame may still be as large as a vault upload, but once it is open the gateway holds the body to the route's own cap before anything parses it: 64 KiB for JSON and control routes, a few hundred KiB for recovery routes that carry envelopes or ID-chip reads, the full `GATEWAY_MAX_CALL_BYTES` only for `POST /vault/objects`. HTP frame meta is capped at 64 KiB (`MAX_META_BYTES`), since it is parsed before the route is known.
