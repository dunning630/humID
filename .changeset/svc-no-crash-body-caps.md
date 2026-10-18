---
"@humid/svc": minor
"@humid/gateway-service": minor
"@humid/recovery-service": patch
"@humid/identity-service": patch
"@humid/ledger-service": patch
---

Hardening from the October 2026 security audits. A malformed request target (`GET //`, `GET http://[`) is a 400 and can no longer exit a service; an unexpected error in one request is a 500 for that request only. Body caps are enforced before anything is buffered: a declared Content-Length over the cap is refused unread, streamed bodies are cut off at the cap, and the gateway picks the frame cap from the frame header (unknown session refused at once, 512 KiB before sign-in, large frames only after sign-in) with per-address and global caps on uploads in flight. Sign-in throttling no longer lets a stranger who knows an account id lock the holder out: only failed proofs are counted, a valid proof is never refused, and per-address and global failure budgets limit ledger noise. JSON bodies that are not objects are a 400 instead of a 500.
