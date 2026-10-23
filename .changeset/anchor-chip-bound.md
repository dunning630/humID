---
"@humid/recovery": minor
"@humid/anchor": minor
"@humid/api": major
"@humid/recovery-service": major
"@humid/gateway-service": minor
"@humid/mobile": minor
---

The ID-chip recovery anchor is now bound to one chip, and the server can't open it (VAULT-01, CREDS-01, CREDS-02, CREDS-03).

- The phone seals the anchor part under `anchorPartKey(DG15)` before sending it (`sealAnchorPart`). The server never stores DG15, so its secret, its database and the holder's name and birth date together no longer open the part.
- The anchor is `chipAnchorOf(DG15)`, a fingerprint of that chip's own key. An old passport or a namesake's passport doesn't match; a renewed passport is linked again.
- Linking needs the live chip: `POST /recovery/anchor/challenge`, then `PUT /recovery/anchor { chip, sealedPart, signature }`. A plain `part` is refused (`update_required`), and so is a chip with no Active Authentication key (`no_chip_proof`).
- Recovery returns `anchorSealed`, which the recovering device opens with the chip it reads live. After a station, the station's phone seals the chip's DG15 to the recovering device's keys (`stationVerify({ chipKey })`; `stationRequest` now returns those keys, checked against the code), so the device gets `anchorKey`.
- Anchors linked before this (v1) keep working, and the app asks the holder to re-link them on the next chip read.

Breaking: `api.setAnchor({ chip, part })` is now `api.setAnchor({ chip, sealedPart, signature })`.
