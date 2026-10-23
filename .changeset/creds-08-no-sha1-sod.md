---
"@humid/anchor": minor
"@humid/creds": minor
---

Passive authentication refuses a passport or ID card chip whose SOD uses SHA-1 (review finding CREDS-08): the data group hashes, the signer's digest or the signature algorithm. Doc 9303 has allowed only SHA-2 since its 7th edition (2015). For older, still valid passports a caller can pass `allowSha1: true` to `passiveAuth` or `verifyPassportChip`; the result then carries `weakHash: true` (and a note). The recovery service keeps the default, so a SHA-1 chip can no longer anchor or recover an account.
