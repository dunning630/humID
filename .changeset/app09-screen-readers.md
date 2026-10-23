---
"@humid/gate": minor
"@humid/mobile": patch
---

Android: an app that can read the screen is named first (APP-09). `@humid/gate` exports `enabledAccessibilityServices()` (the native plugin's new `enabled_accessibility_services`, Android only; `[]` elsewhere, never throws). Before a document or card opens, a recovery card is made, or messages open, the app checks for an enabled accessibility service that can read window content and, if one is on, names it and asks; "Not now" shows nothing. A yes holds for that session and that set of services. Needs a device to confirm the native list.
