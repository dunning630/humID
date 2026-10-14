---
"@humid/idscan": minor
"@humid/anchor": minor
---

Mobile IDs (ISO/IEC 18013-5). New `@humid/mdoc` 1.0.0: reader session (engagement QR, ECDH/HKDF session keys, AES-256-GCM), DeviceRequest, issuer data authentication (MSO signature, IACA chain, digests, validity) and device authentication (signature or MAC), VICAL. `@humid/idscan`: `applyMdoc` maps a verified US mobile license / state ID, EU PID or ISO 23220 photo ID into the record (source `mdoc`, ranked with the chip). `@humid/anchor`: `mdocAuth`, `mdocAnchorOf`, `loadIacas` so a live mobile ID can anchor a HumID.
