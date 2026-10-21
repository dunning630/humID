---
"@humid/htp": minor
"@humid/api": minor
"@humid/identity-service": patch
"@humid/gateway-service": minor
"@humid/mobile": patch
---

Duress is reported inside the signed sign-in, never as a request of its own (audit PC-01). New `loginPresenceMessage(th, id, challenge, d)`: the liveness key signs the plain challenge, the device key (released by the same live check) signs it with the duress flag. `api.login`'s `sign` callback now gets `{ presence }` and may return `d`. The gateway ignores the flag in `POST /auth/presence`, so a bare request from a signed-in session can no longer lock down an account or erase an armed Check-in vault. Apps older than this release no longer signal duress and should update.
