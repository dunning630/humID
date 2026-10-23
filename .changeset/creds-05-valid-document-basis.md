---
"@humid/creds": minor
---

`minimise(..., { share: ["valid_document"] })` no longer asserts `valid_document: true` from the expiry date alone (review finding CREDS-05). `true` now needs a revocation check that came back valid and a holder-bound credential; otherwise it's refused with `unchecked`, unless the caller passes `allowUnchecked: true`, and the claim then carries `basis.valid_document` (`expiry`, `revocation`, `holder`) inside its commitment. An expired, revoked or suspended credential is still simply `false`.
