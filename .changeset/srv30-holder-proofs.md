---
"@humid/svc": minor
"@humid/htp": minor
"@humid/api": minor
"@humid/gateway-service": minor
"@humid/vault-service": minor
"@humid/keyshare-service": minor
"@humid/identity-service": minor
"@humid/ledger-service": minor
"@humid/mobile": patch
---

The gateway's internal key alone no longer releases or deletes anything (audit SRV-30 / H-1, with CRYPTO-03 a).

- Vault, keyshare and identity check the holder's own step-up proof (the device key's ML-DSA-87 signature over the exact request, and the liveness key's) against the device keys identity vouches for, once each, instead of trusting `claims.stepUp`. New `@humid/svc/holder` (`holderProofs`, `checkReceipt`) and `signStatement`/`verifyStatement`/`newStatementKeys`.
- The open is written to the ledger first; the vault releases an envelope only against the ledger's signed receipt for it.
- Check-in: the vault's sweep delete needs keyshare's signed erase token; a duress erase needs the duress sign-in itself, checked by keyshare and acted on once.
- Split-document keys travel sealed (ML-KEM-1024 + X25519) to a one-time key the phone puts in the body it signs (`shareReceiver`/`sealShare`/`openShare` in `@humid/htp`), so the gateway forwards ciphertext only. Older apps get `426 update_required` for split documents.
- New settings: `HUMID_CORE_STATEMENT_SK`/`_PK` (identity, ledger) and `HUMID_KEYS_STATEMENT_SK`/`_PK` (keyshare). `deploy/setup.sh` adds them to an existing `.env`; `humid init` adds them on Windows; `humid pki issue` carries each role's own to its machine. Services and gateway must be upgraded together.
