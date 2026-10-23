---
"@humid/idscan": minor
"@humid/mobile": patch
---

A chip read on the phone no longer earns the green "Read from the chip" label (review finding CREDS-04). The phone checks the chip's files against the chip's own list of hashes, which a cloned or made-up chip satisfies, so `provenance` now gives such a record the level `chip-issuer-unverified` ("Read from the chip, issuer not verified on this phone"), shown in amber. The `chip` level needs a fresh issuer check passed as `provenance(rec, { chip: { ok, chain } })`; a failed one is `chip-mismatch`.
