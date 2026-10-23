---
"@humid/mobile": patch
---

The recovery-mode pin only goes forward (V74B-03).

- `core/identity.js` `updateIdentity` never writes a record whose `modePin` is at a lower version or epoch than the stored one, or that has none. A writer working from an older copy keeps its own change, but the pin stays where it was.
- `interrupt.js` `keepGateHandle` (a gate that moved its secret to a new key, LIVE-01) now writes through `updateIdentity`, instead of putting back the record as it was when the live check began. No module in `core/` writes the identity record itself any more.
- Also: `withKeys` called `gateLabel` without importing it (a regression from the one-vocabulary change), so every live check threw `ReferenceError: gateLabel is not defined`. Fixed.
