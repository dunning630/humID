---
"@humid/crypto": minor
"@humid/store": minor
"@humid/api": minor
"@humid/vault-service": minor
"@humid/gateway-service": patch
"@humid/mobile": patch
---

Index entries can't be rolled back or moved (audit CRYPTO-05). `sealIndex(key, entry, { id, rev })` makes a v2 entry (`"HIX2"` prefix, AAD `"HUMID-INDEX-v2" ‖ lp(id)`, `rev` inside); `openIndex(key, blob, { id })` opens it only as that item's and returns its `rev` (v1 entries open as rev 0). The app picks each new item's id (`api.upload(…, id)`, header `x-humid-object-id`; the vault refuses a duplicate or a non-UUID-v4), re-seals every rename, pin and decoy change at a newer rev, and keeps the highest rev it has seen per item sealed on the device (`sealIndexRevs`, `store.putIndexRevs`). An older entry than that is shown as "Changed on the server" and its flags aren't believed. Existing v1 entries move to v2 the next time they are changed, never in bulk.
