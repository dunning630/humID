---
"@humid/htp": minor
"@humid/api": patch
"@humid/mobile": patch
---

A replayed older signed policy is never used (CRYPTO-07 round 2). `HtpClient.policySeen` holds the newest signed policy the client has accepted; `serverKeys()` uses whichever of it and the served one is newer (`policyReplayed`, `policyAt`), re-checking the stored signature. `verifyPolicy` takes `{ maxAgeMs }`. The app keeps `policySeen` in the identity record and hands it to the client at boot.
