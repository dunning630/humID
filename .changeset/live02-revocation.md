---
"@humid/attest": minor
"@humid/identity-service": minor
---

Attestation revocation that works in Docker, and fails closed (PC-14 / LIVE-02 / SRV-33). `revocationList` reads a copy another process fetched (`file`) as well as fetching one itself (`url`), and `required` now also refuses a copy older than `maxAgeMs` (48 h, `status_stale`), not only a missing one. New `fetchStatusToFile` / `runStatusFetcher` / `readStatusFile`: the identity image runs as an `attestation-status` sidecar (`server.mjs status-fetch`), the only container with a route out, which writes Google's list to a volume identity reads (`HUMID_ATTESTATION_STATUS_FILE`). `HUMID_ATTESTATION_STATUS_REQUIRED` defaults to 1 for the attested policy (unset = by policy; 0 = explicit opt-out).

Identity logs one `live-human posture` line at start, a warning naming every weakened setting (LIVE-04), and refuses to start with `HUMID_ANDROID_ALLOW_ANY_SIGNER=1` and the attested policy unless `HUMID_INSECURE_TEST=1`.
