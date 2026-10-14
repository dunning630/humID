---
"@humid/api": minor
"@humid/htp": minor
"@humid/store": minor
"@humid/gateway-service": minor
"@humid/mobile": minor
---

Anonymous payment for registration. New `@humid/pass` module (1.0.0) (RFC 9474 blind
signatures, RSABSSA-SHA384-PSS-Randomized, and access codes) and a new `access`
service (1.0.0) that sells nothing it can link to an account: access codes are swapped
for blind-signed passes, and registration spends a pass. The gateway requires a
pass to create a HumID unless `HUMID_REGISTRATION=open`. The app gains an access
step in onboarding, keeps unspent passes in a new `wallet` store (IndexedDB v2)
so a paid code survives a crash, and the HTP client reads the new
`registration` / `passBuyUrl` policy hints. See docs/ANONYMITY.md.
