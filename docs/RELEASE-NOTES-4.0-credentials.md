# HumID 4.0 — Public Credentials (provisional)

**Branch:** `v4/credentials` (on top of `v4/p2p-comms`) · **Track:** 4.0, provisional · **Date:** 2026-10-21

HumID can now ask for a government credential the way a bank or an airline does, check it on the phone or on a server, and keep only what the question needed. One request works with every current browser and wallet. One verifier handles every format. Every answer says how far it was proved.

## What's new

### Ask any wallet, from one request
- `credentialRequest()` builds a single `navigator.credentials.get({ digital })` request that offers both protocols browsers use today:
  - **OpenID4VP 1.0** (`openid4vp-v1-unsigned`) with a DCQL query, answered encrypted to a one-time key (`dc_api.jwt`). Chrome 141+ on Android, and on desktop with a phone nearby.
  - **ISO/IEC 18013-7 Annex C** (`org-iso-mdoc`), answered HPKE-encrypted. Safari 26 / iOS 26 and Apple Wallet, and Chrome 141+.
- Asks name a purpose (`age_over_21`, `identity`, `vault`, …), so HumID requests only the elements that purpose needs, and the wallet shows the holder exactly that.
- Optional ISO 18013-5 **ReaderAuth** signing. Apple Wallet requires a reader certificate from Apple Business Connect.

### Check any credential, into one result
`verifyCredentialResponse()` opens either protocol, checks the issuer's chain and the device's proof, and returns one shape: `type`, `assurance`, `issuer`, `claims`, `validUntil`, `statusRef`.

| Credential | Issuer proven | Holder proven |
|---|---|---|
| US mobile driver's licenses and state IDs (Apple, Google, Samsung Wallet; state apps) | ✓ state IACA root | ✓ device signature |
| EU digital identity (PID), mdoc | ✓ | ✓ |
| EU digital identity (PID), SD-JWT VC | ✓ x5c chain or issuer metadata | ✓ key binding (nonce + `origin:` audience) |
| Wallet photo IDs (ISO/IEC 23220) | ✓ | ✓ |
| Passports and ID cards with a chip (server) | ✓ CSCA | ✓ with Active Authentication |
| Physical license barcode | ✗ (reported as `printed`) | ✗ |

Assurance levels: `issuer+holder`, `issuer`, `signature-only` (only when explicitly allowed, for a holder filing their own ID before trust lists are loaded), `printed`.

### Revocation
- IETF **Token Status List** checks for SD-JWT (JWT lists) and mdoc (CWT lists): signature under the issuer's trust, `sub` must equal the credential's `uri`, freshness, a decompression cap. A revoked or suspended credential can't back a "valid document" claim.

### Keep only what the question needs
- `minimise()` reduces a verified credential to facts: `age_over_18/21/25/65` (derived from the birth date when not stated), `valid_document`, issuing country and state. Names, numbers and addresses need `identifying: true`; a photo never goes into a claim.
- With a 4.0 persona, the claim carries a **commitment** (SHA3-256, canonical form), ready to ride inside a live-stamped message: "a live human approved sharing: over 21, valid US-IL license," with neither the credential nor the person in it.

### SSN, honestly
- There is no SSN credential to verify. `checkSsnFormat()` checks structure only. `ecbsvVerifier()` is an adapter for SSA's **eCBSV**, usable only by permitted entities (financial institutions and their service providers), with the holder's signed consent per check. It refuses to run otherwise, and never returns, logs or echoes the number.

### Trust lists
- `iacaFromVical()` reads AAMVA's Digital Trust Service list of US and Canadian issuer roots: VICAL signer under the provider's root, fresh, no rollback.
- `cscasFromMasterList()` / `readMasterList()` read ICAO CSCA master lists: master list signer under the publisher's own CSCA, no SHA-1.
- SD-JWT issuers: certificate-backed ones must chain to a configured root and be named in their certificate; keys without a certificate only for issuers the operator lists with their credential types.

### In the app
- `apps/mobile/src/core/credentials.js`: detects support, asks the wallet from a tap, verifies on the phone, and files a mobile ID into the existing ID record with the issuer-signed bytes kept for a later re-check. (The screen and native plugins come next.)

## Modules

| Module | Version | Change |
|---|---|---|
| `@humid/mdoc` | 1.0.0 → 1.1.0 | Ported from `lane/core/mobile-id`; Annex C, HPKE, OpenID4VP transcripts, ReaderAuth; stricter issuer chains and VICALs |
| `@humid/sdjwt` | new, 0.1.0 | SD-JWT VC, JOSE, token status lists |
| `@humid/creds` | new, 0.1.0 | Requests, one verifier, revocation, minimisation, SSN, trust loaders; `/server` for passports |
| `@humid/idscan` | minor | `applyMdoc` |
| `@humid/anchor` | minor | `mdocAuth` (full name, birth date and country required), `readMasterList` |

No changes to the envelope format, the sealing suites, HTP/1 or any service's API. No migration. Change detection marks `sdjwt` and `creds` as not shipped yet, so no app or image rebuilds for them alone.

## Security
An independent reviewer who hadn't seen the code being written went through the whole change and confirmed each finding with a test. All are fixed, each with a regression test that fails on the old code and passes now.

| # | Severity | Finding | Fixed by |
|---|---|---|---|
| F3 | **High** | An SD-JWT signed with a key from issuer metadata on any domain verified as an EU PID | Keys without a certificate are used only for issuers the operator lists, each with the credential types it may issue; results show `keySource` |
| F1 | Medium | Any signing certificate under a publisher's CSCA could sign a master list and add a CSCA for any country | Master list signer key usage (2.23.136.1.1.3) required |
| F4 | Medium | An SD-JWT's `iss` and `issuing_country` weren't tied to its certificate | `iss` must match the certificate's SAN; the country must be the certificate's |
| F6 | Medium | VICAL signer validity, key usage, freshness and issue order unchecked | All checked; `minIssueId` refuses rollbacks |
| F9 | Medium | A photo ID's country wasn't compared with its root | Compared in each document type's own namespace; reported country comes from the root |
| F2 | Low | Master lists accepted SHA-1 signatures | Refused |
| F7 | Low | Mobile-ID intermediates and Document Signers checked loosely | Validity, signing rights, key usage and signing bit required |
| F8 | Low | Status-list chains loose and not tied to the credential's issuer | Same chain rules as issuers; pinned to the credential's own root |
| F5 | Low | Some malformed answers threw raw exceptions | Coded refusals only |
| F10 | Low | Claim commitments unsalted (a committed birth date was brute-forced in 0.7 s) | 32-byte random salt |
| I1 | Info | Annex C decryption used the tag-24-wrapped transcript; real wallets use the plain one, so every real answer would have failed to decrypt | Plain CBOR, checked byte for byte against the OpenWallet Foundation's `@owf/mdoc` |

Also hardened: a mobile ID anchoring recovery must share full name, birth date and issuing country.

## Testing
- 426 unit tests and 112 end-to-end tests pass (1 skipped: needs a PC/SC virtual reader); the app bundle and the recovery service image build.
- New: `tests/creds.test.js` (17), `tests/sdjwt.test.js` (12), `tests/wallet-id.test.js` (4), `tests/review-fixes.test.js` (7), plus the ported `tests/mdoc.test.js` (14).
- Every simulated wallet and issuer uses independent cryptography (`node:crypto`, `@hpke/core`, `jose`), so HumID's code is checked against code it doesn't share. HPKE and JWE interoperate both ways; RFC 7638 and the status-list bit-order example vectors pass; session transcripts match `@owf/mdoc` byte for byte.
- Attacks covered: phishing-site relay, replay, timeout, tampered ciphertext, copied data on another phone, unchecked MACs, wrong nonce / origin / key / handover, injected or duplicated disclosures, alg `none`, untrusted or broken chains, expiry, unasked document types, forged / stale / mismatched status lists, compression bombs, tampered master lists.
- Fuzzing with a fresh seed each run. Soak runs (about 25,000 SD-JWT and 2,500 Annex C mutations in all) found and fixed one crash on malformed base64url; none since the review fixes.

## Known limits
- Not yet tested against real wallets: Apple's sample responses, the EU reference wallet, Google's test wallet and a state test mDL come before launch.
- EU PID claim names follow the PID Rulebook as published; confirm against the wallets in use.
- ECDSA and EdDSA only; RSA-signed SD-JWTs or IACAs are refused. Issuer certificate CRL/OCSP isn't checked (credential revocation is).
- Request state holds private keys; keep it on the verifying side.
- A verified ID proves a document, not a face.

## Not built yet
Native plugins (Android Credential Manager, iOS IdentityDocumentServices), the *Add from a wallet* screen, a server verifier route, scheduled trust-list refresh, the Apple reader certificate, sending a minimised claim as a live-stamped message, zero-knowledge age proofs, Aadhaar Secure QR and AAMVA DLDV.

## Before real IDs go through it
Independent review of the protocol code, real-wallet interop, trust lists from the official publishers, and counsel on eCBSV, DPPA and state license-data rules, BIPA and GDPR. Details: `docs/CREDENTIALS.md`.
