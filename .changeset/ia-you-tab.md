---
"@humid/mobile": minor
---

Information architecture and vocabulary pass ("Safe. Secure. Simple."):

- Three tabs: Vault · Activity · **You**. Settings and Security merge into You, in the order they matter: protection checklist, devices, recovery (witnesses · ID chip · recovery card), duress with an inline decoy picker, help others, preferences, a collapsed "About this HumID" with the diagnostics, then Lock now and Close HumID once. The start-tab preference is gone; the app always opens on the vault.
- One word per concept everywhere a person reads: **Check** (the biometric prompt; the overlay says "Checking it's you"), **Seal / Sealed**, **Open**, **Save a copy**, **Export sealed**, **Recovery card**, **Witnesses**, **ID chip**, **Device / Witness / Recovery / Match code**, **Your vault server**, **Location stamp**. Crypto names, HTP/1, "step-up", "anchor", "seal card" and "biological interrupt" no longer appear in the UI; the plain facts live in one "How HumID protects you" sheet linked from You and from the seal screens.
- Photo choice shows one preview of the suggested version; "Looks wrong?" reveals the other versions, turning and retake.
- Wizards (ID, payment card, add device, ID chip, help) get a Back step that Android Back uses before closing the sheet. Terminal lock issues lead straight to "Set up HumID again". An expired witness offer gets "Make a new code".
- Delete, Remove this device and Cancel the recovery go straight to the check from the row itself; only Close HumID & erase keeps a confirm sheet.
- Empty states for Vault, Activity, Devices and Witnesses; a11y fixes (44 px text links, legible eyebrows, tablist roles, reduced-motion default, focus on the check overlay); no text selection or copy in the viewer, code boxes and card number; the recovery card sheet no longer shares a sheet type with the payment card sheet.
