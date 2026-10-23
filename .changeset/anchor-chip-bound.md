---
"@humid/recovery": minor
"@humid/anchor": minor
"@humid/api": major
"@humid/recovery-service": major
"@humid/gateway-service": minor
"@humid/mobile": minor
---

The ID-chip recovery anchor is now bound to one chip (CREDS-01, CREDS-02). The anchor part is no longer stored in a form the server's files and the holder's details open (VAULT-01 and CREDS-03, at rest only).

- The phone seals the anchor part under `anchorPartKey(DG15)` before sending it (`sealAnchorPart`). The server doesn't store DG15, so its secret, its database and the holder's name and birth date together don't open the part.
- **Limit (V74-03):** DG15 is public chip data, and the server sees it at every link and recovery. An operator that records one request can open the part, so in hardened mode the passport plus any one other stolen proof is enough for a hostile operator. The app and the docs say so. The fix, a split wrap with an independent cosigner, is an open decision (docs/CONTINUITY.md).
- The anchor is `chipAnchorOf(DG15)`, a fingerprint of that chip's own key. An old passport or a namesake's passport doesn't match; a renewed passport is linked again.
- Linking needs the live chip: `POST /recovery/anchor/challenge`, then `PUT /recovery/anchor { chip, sealedPart, signature }`. A plain `part` is refused (`update_required`), and so is a chip with no Active Authentication key (`no_chip_proof`).
- Recovery returns `anchorSealed`, which the recovering device opens with the chip it reads live. After a station, the station's phone seals the chip's DG15 to the recovering device's keys (`stationVerify({ chipKey })`; `stationRequest` now returns those keys, checked against the code), so the device gets `anchorKey`.
- Anchors linked before this (v1) keep working, and the app asks the holder to re-link them on the next chip read.

Breaking: `api.setAnchor({ chip, part })` is now `api.setAnchor({ chip, sealedPart, signature })`.
