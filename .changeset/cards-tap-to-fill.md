---
"@humid/cards": minor
"@humid/mobile": minor
---

Payment cards are back in the vault (they were built in PR #4 but never reached `main`), and tapping a card fills in its details by itself.

- `@humid/cards`: the contactless read now returns everything a chip can fill in: number, expiry, name (5F20 or 9F0B), the issuer's name from the card's own label (9F12 / 50), credit / debit / prepaid, valid-from date (5F25) and issuing country (5F28, also as ISO alpha-2). Still a read, not a payment: amount zero, no GENERATE AC, never the security code or track discretionary data. The record gains optional `funding`, `validFrom` and `country` fields (schema `humid.card/1`, additive); the encrypted index adds `funding`. `filledBy(rec, "nfc")` lists what a read filled; typed values always win over a later read. `@humid/cards/sim` holds the simulated cards for tests and development builds (release builds stub it out).
- App: on Android, and on Windows or a Mac with a USB contactless reader, the "Add a payment card" sheet waits for a card from the moment it opens; the chip's details land in the form, each marked "From chip", including while you're typing. iPhone keeps the camera (Apple doesn't let apps read payment cards over NFC). The wait stops when the sheet closes (humid-nfc 1.1 `cancel`). Development builds offer "Tap a demo card".
