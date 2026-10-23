---
"@humid/htp": patch
---

A step-up ticket sends exactly one frame (audit CRYPTO-06). The ticket's sequence number is also the frame's AES-GCM nonce, so passing the same ticket to `call()` twice (a retry wrapper, a refactor) would have encrypted two requests under one key and nonce. The client now refuses the second use with `ticket_used` before anything is sent; a retry needs a new ticket and a new live check.
