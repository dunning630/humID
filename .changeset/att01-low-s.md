---
"@humid/attest": minor
"@humid/gate": patch
"@humid/mobile": patch
---

Liveness signatures are low-S only (audit ATT-01 / LIVE-03). `verifyLiveSig` now refuses the high-S form (r, n − s) of an ECDSA P-256 signature, so a captured sign-in, step-up, seal or admin approval can't be re-encoded into a second valid signature with a different proof hash. The native gate normalises whatever the Keystore or Secure Enclave returns to low-S before it leaves the app (`packages/gate/src/lows.js`), so apps and servers must be upgraded together: an older app's signature is refused about half the time. New exports `isLowS`, `ecdsaRS`, `P256_N`; `packages/attest/src/ecdsa.js` lists which ECDSA checks require low-S (HumID's own liveness keys) and which don't (mdoc, SD-JWT, passports, X.509, FIDO keys: their standards allow either form).
