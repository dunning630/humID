---
"@humid/msg": minor
---

HumID 4.0 (provisional): proving it's you against cloned voices and deepfakes, without HumID ever handling biometrics. "Is this really you?": a contact sends a challenge over the pinned conversation; the real holder answers yes or no with a live check, and on a yes both phones show a 40-bit spoken code to read aloud on the call (verdicts confirmed / denied / unverified / expired; a duress answer is never confirmed). Stamped media: a `media` message kind whose live stamp covers the bytes, and a portable media credential dual-signed (ML-DSA-87 + SLH-DSA-SHA2-256f) by a public persona plus a live stamp. Evidence locker: voice and photo originals sealed on the device under a key from the account seed, opened after a live check, and released with a signed, stamped, expiring release statement. Nothing compares one voice or face with another. See docs/MESSAGING.md, "Proving it's you".
