---
"@humid/attest": minor
"@humid/identity-service": minor
"@humid/gateway-service": patch
---

Google's attestation revocation list and the 48 h staleness rule apply at every sign-in, not only at enrolment (V76-02). `verifyLiveKey` returns the chain's certificate `serials`; identity keeps them with the device (`att_serials`) and checks them on every `/internal/verify`. A listed certificate removes the device (`attestation_revoked`, recorded as `device.removed`); a missing or stale list under a required policy refuses the sign-in (503 `status_unavailable` / `status_stale`); an Android device enrolled before serials were kept is refused with `reattest_required` under a required list.
