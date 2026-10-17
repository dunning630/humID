---
"@humid/mobile": major
---

App 2.0 layout: the information-architecture rebuild.

- **Kinds replace categories.** Every vault item is an ID, a card, a pass, a photo or a file (`kind`, sealed in its index entry). Items sealed before 2.0 are classified on read and the kind is written back lazily on the next rename or pin, never in bulk. The old categories live on as optional **tags** (same ids), suggested from the name, shown as small labels and filterable from a "More filters" row that appears only once something carries a tag. The Vault's chip row is All · IDs · Cards · Passes · Photos · Files, for the kinds that exist.
- **One Add flow, camera first.** The + button opens the camera at once. The photo routes itself: a card with a license barcode or a page with an MRZ to the ID flow, a card with a payment number to the card review, anything else to the photo review; a live label says what the camera sees, with "It's something else" for the picker. File (a `.pkpass` is checked as a Wallet pass), Type a card and Tap a card sit on the camera's own bar. Every kind goes through one shared Review (name, kind with Change, the kind's fields, tags, location stamp, Seal). The Add, ID and payment-card sheets are gone.
- **Item detail is a pushed screen**, preview first (one Open = one check; a card's masked number with "Show the number"; a pass's summary), then the facts, then a ··· menu: Rename · Pin · Show in decoy · Export sealed · Delete. Save a copy lives in the opened Viewer.
- **Onboarding**: "You're all set" becomes "Your recovery card" (Print / Save, type-back check, "I've saved it") then "You're in". The sole-biometric checkbox becomes the one-line statement "Only I use Face ID / fingerprint on this phone" with a "What does this mean?" disclosure, still required and still recorded in the ledger.
- Android Back steps one level inside Add and the item screen before closing them.

No security property changes: every check stays; envelope v1, HUMID-PQ1 and HTP/1 are untouched. The identity record's schema stays at 4.
