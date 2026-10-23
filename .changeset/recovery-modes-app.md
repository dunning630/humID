---
"@humid/mobile": minor
---

Setup now asks "If you lose every device" before the first check. The choices are "A safe way back in" (recommended, and selected) and "Only my own devices". Holder-only skips the recovery card, signs the mode into registration, and asks for a second device straight away. Protection then counts devices only, and warns while the account has just one. The Recovery screen shows the mode, checks the server's statement against the account key, and switches modes; switching to holder-only deletes every proof first, each with its own check. For a holder-only HumID, the join screen offers only the device link. Activity names `recovery.mode_set`.
