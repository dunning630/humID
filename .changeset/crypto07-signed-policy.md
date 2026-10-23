---
"@humid/htp": minor
"@humid/gateway-service": patch
"@humid/mobile": patch
---

The policy hint in `GET /htp/v1/keys` is signed (audit CRYPTO-07, PC-13, VAULT-04). `HtpServer.signedPolicy(policy)` returns `{ policy, policySig }`, signed with the server's static ML-DSA-87 key over `"HTP/1 policy" ‖ lp(kid, canonical JSON, at)` and cached for an hour; `HtpClient.serverKeys()` believes the hint only when it verifies under the pinned key and is under 7 days old (`server.policySigned`), and otherwise uses the strict defaults. New exports: `policyMessage`, `verifyPolicy`, `canonicalJson`. A pinned release app refuses to seal unsplit even on its first run. Older apps ignore the new field; a new app against an older gateway sees the strict defaults, so upgrade the gateway first.
