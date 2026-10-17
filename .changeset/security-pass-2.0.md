---
"@humid/mobile": minor
"@humid/crypto": minor
"@humid/htp": patch
"@humid/gate": patch
---

2.0 security pass. The duress setting is sealed on the device under a key derived from
the account seed (@humid/crypto `settingsKey`, `sealSetting`, `openSetting`) and the
decoy-or-real decision is made after the live check, so nothing on disk says whether
duress is on or which gesture triggers it. The file-picker exemption from lock-on-hide
is bounded (60 s, cleared on `pagehide`, a long hidden span locks anyway). Item names
are forgotten on lock and erase, and a decoy session keeps only decoy names. A chip
photo's declared size is capped before decoding and no portrait is shown from a chip
that fails its own hash list. Every HTP request has a 45 s timeout. `openExternal(url)`
hands https:, tel: and mailto: links to the system (Tauri opener plugin, scoped), and
the native shell refuses navigation away from the app's own origin. Release builds no
longer contain the simulated server or demo code (checked by a test), and a simulation
build is a separate app, `app.humid.vault.sim`. The seal card sheet is `recoveryCard`,
no longer colliding with the payment-card sheet. iOS excludes the WebView data store
from backups.
