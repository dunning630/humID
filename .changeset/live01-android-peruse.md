---
"@humid/gate": minor
"@humid/mobile": patch
---

Android: the seed-unwrap secret opens only inside a prompt HumID asked for (audit LIVE-01, humid-gate 2.1.0). The gate's `release` may now return `handle`, a replacement for the one passed in (a 2.0 time-bound key moved to a per-use key); the app stores it at once (`withKeys`). Needs a device to confirm.
