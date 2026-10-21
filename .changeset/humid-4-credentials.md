---
"@humid/mdoc": minor
"@humid/sdjwt": minor
"@humid/creds": minor
"@humid/idscan": minor
"@humid/anchor": minor
---

HumID 4.0 (provisional): ask for and check public identity credentials. `@humid/mdoc` (mobile IDs, ISO 18013-5, ported from lane/core/mobile-id) gains online requests through the Digital Credentials API: ISO 18013-7 Annex C (`org-iso-mdoc`) with HPKE responses, OpenID4VP session transcripts, and ReaderAuth. New `@humid/sdjwt`: SD-JWT VC verification with key binding, the JOSE a verifier needs (JWS, x5c, JWK thumbprints, ECDH-ES JWE), and IETF Token Status List revocation (JWT and CWT). New `@humid/creds`: one request for every current browser and wallet (OpenID4VP DCQL + Annex C), one verifier and result shape across mobile licenses and IDs, EU PID (mdoc and SD-JWT), wallet photo IDs, passport chips (`@humid/creds/server`) and license barcodes, with an honest assurance level, revocation checks, minimised claims committed to a 4.0 persona, SSN structure checks and an eCBSV adapter for permitted entities. `@humid/idscan`: `applyMdoc`. `@humid/anchor`: `mdocAuth` and ICAO CSCA master lists (`readMasterList`). See docs/CREDENTIALS.md. Includes the fixes from the independent security review (2026-10-21): explicit issuer allowlists for keys without certificates, SD-JWT issuer bound to its certificate's SAN and country, VICAL signer / freshness / rollback checks, master list signer key usage and no SHA-1, photo ID country bound to its root, stricter mobile-ID and status-list chains, coded errors for hostile input, salted claim commitments, and Annex C HPKE info as plain CBOR (checked against @owf/mdoc).
