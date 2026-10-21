---
"@humid/fido": minor
"@humid/recovery": minor
"@humid/api": minor
"@humid/svc": patch
"@humid/recovery-service": minor
"@humid/gateway-service": minor
"@humid/ledger-service": minor
"@humid/mobile": minor
---

HumID 4.0 (provisional): a FIDO2 security key as the fourth recovery proof. New module `@humid/fido` (CTAP 2.1 over NFC on any APDU transport: canonical CBOR with limits, command and response chaining, NFCCTAP_GETRESPONSE, PIN/UV auth protocols 1 and 2, `hmac-secret`, `credProtect` level 3, a relying party no website can claim). The account seed gets a fourth part (x = 4) locked under the key's PIN-gated `hmac-secret`; the recovery service counts a key only when the key itself signs a fresh challenge with its PIN verified, refuses counters that go backwards (copied keys), and withdraws a removed key (or a replaced card) from recoveries under way. App: You → Recovery → Security key (name, PIN, one tap, one live check), Prove it's me → Security key, Activity events. No biometric is stored anywhere. See docs/SECURITY-KEY.md.
