---
"@humid/creds": minor
"@humid/anchor": minor
---

Master lists only move forward (review finding CREDS-06). `readMasterList` now returns the list's signed `signingTime`; `applyMasterList` passes it to the store, and `setCscas(source, entries, { signedAt, sha256 }, { now })` refuses (`rollback`) a list signed before the one already applied for that source, one signed at the same time with different contents, or one with no signing time once one was seen, so replaying an older, still validly signed list can no longer drop CSCAs. A list dated more than a day ahead is refused; the same list again changes nothing (`unchanged: true`).
