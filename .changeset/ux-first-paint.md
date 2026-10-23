---
"@humid/mobile": patch
---

A lighter start. Setting up, joining, recovery and the operator tools (`core/enroll.js`, `join.js`, `recovery.js`, `recmode.js`, `seckey.js`, `operators.js`, with `@humid/recovery`'s app-side code) moved behind a second kernel barrel, `core/setup.js`, that loads with the screens that use it; the first paint keeps only recovery alerts and the kept recovery card (`core/alerts.js`). First paint of a release build: 311 KB → 276 KB raw (117 → 107 KB gzip). Boot reads the gate probe, the identity record, the wallet and the offline copy at the same time. The viewer's "Open for N s" line ticks on its own instead of re-rendering the document every second, and Activity describes its entries once per page. The web favicon is a 2.4 KB vector of the same mark (was a 55 KB trace).
