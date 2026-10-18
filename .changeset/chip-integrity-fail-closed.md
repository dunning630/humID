---
"@humid/mobile": patch
"@humid/idscan": patch
---

Fail closed on passport and ID chips. Chip data is used (and the chip photo decoded) only when its files match the chip's own signed list of hashes; a malformed SOD, an unchecked result or a hash mismatch now shows "Chip couldn't be verified", uses none of the chip's data, and offers to continue with the printed details, marked "Not verified". A chip that does match is now described as "Chip data integrity-checked" rather than verified, because the issuing country's signature isn't checked on the phone.
