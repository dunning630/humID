---
"@humid/mdoc": minor
"@humid/sdjwt": minor
"@humid/creds": minor
"@humid/idscan": minor
"@humid/anchor": minor
---

HumID 4.0 (provisional): ask for and check public identity credentials. `@humid/mdoc` (mobile IDs, ISO 18013-5, ported from lane/core/mobile-id) gains online requests through the Digital Credentials API: ISO 18013-7 Annex C (`org-iso-mdoc`) with HPKE responses, OpenID4VP session transcripts, and ReaderAuth. New `@humid/sdjwt`: SD-JWT VC verification with key binding, the JOSE a verifier needs (JWS, x5c, JWK thumbprints, ECDH-ES JWE), and IETF Token Status List revocation (JWT and CWT). New `@humid/creds`: one request for every current browser and wallet (OpenID4VP DCQL + Annex C), one verifier and result shape across mobile licenses and IDs, EU PID (mdoc and SD-JWT), wallet photo IDs, passport chips (`@humid/creds/server`) and license barcodes, with an honest assurance level, revocation checks, minimised claims committed to a 4.0 persona, SSN structure checks and an eCBSV adapter for permitted entities. `@humid/idscan`: `applyMdoc`. `@humid/anchor`: `mdocAuth` and ICAO CSCA master lists (`readMasterList`). See docs/CREDENTIALS.md.
