---
"@humid/crypto": minor
---

Vault-index entries are padded to 64-byte buckets before sealing (`sealIndex`), so the size of a sealed entry, and the size change when one is re-sealed for a pin or a decoy flag, says nothing about what it holds. `openIndex` strips the padding; entries sealed by earlier releases still open.
