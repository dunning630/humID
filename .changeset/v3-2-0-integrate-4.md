---
"@humid/mobile": minor
---

**Apps 3.2.0: the 3.x apps now carry the HumID 4.0 foundations.** The 4.0 track (person-to-person messaging, `@humid/msg`, and public credentials, `@humid/mdoc` online requests, `@humid/sdjwt`, `@humid/creds`, with the fixes from their independent reviews) is merged onto the 3.1.1 apps. Nothing changes on screen yet: the new modules are provisional and not wired into any screen (`NOT_SHIPPED` in `tools/affected.mjs`), so the apps behave exactly as 3.1.1 does. This release puts every line of work on one base, so the next screens (Messages, Add from a wallet) build on what's published. See docs/MESSAGING.md and docs/CREDENTIALS.md.
