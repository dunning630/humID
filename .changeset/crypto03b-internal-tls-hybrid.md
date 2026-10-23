---
"@humid/svc": minor
---

Internal TLS between roles uses the hybrid X25519MLKEM768 key exchange only (audit CRYPTO-03 b): `serverTls` and `clientTls` set it on both ends, a peer offering X25519 alone is refused, and a split role won't start on a Node whose OpenSSL lacks the group. New export `INTERNAL_TLS_GROUPS`.
