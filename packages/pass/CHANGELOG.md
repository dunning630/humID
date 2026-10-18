# @humid/pass

## 1.1.0

### Minor Changes

- The access pass is sealed at rest. Before enrolment there is no seed-derived key, so the
  pass draft (the access code and the blinded request) and the finished blind-signed pass
  used to be stored in IndexedDB as they were. `@humid/pass/atrest` now seals the wallet
  record under a per-install 256-bit AES-GCM key (a non-extractable WebCrypto `CryptoKey`
  kept in its own IndexedDB database, apart from the wallet; AAD `HUMID-PASS-v1`, fresh IV
  per write). A clear record from an older build is re-sealed on the first read and the
  plaintext overwritten; a record that doesn't open is dropped. The RFC 9474 code is
  unchanged. Limits and what remains are in docs/SECURITY.md (*The access pass at rest*).
  
  Also: `npm run test:pen`, a penetration regression pack against the in-process stack
  (tests/pen), run in CI next to the end-to-end tests.
