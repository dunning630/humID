---
"@humid/api": minor
"@humid/gateway-service": minor
"@humid/identity-service": minor
"@humid/recovery-service": minor
"@humid/mobile": patch
---

A device joins an account only with evidence (audit PC-02): a link one of the account's devices approved for that exact device key (`startLink({ devicePk })`, `enrollDevice({ linkCode })`; single use), or a released recovery of the same route. The account seed alone no longer lets a phone in, and `via: "register"` is refused on `/auth/device`. Links without a device key are refused (`update_required`). New internal routes: recovery `POST /internal/links/:code/consume|restore`, `POST /internal/requests/:id/check`; identity `GET /internal/devices/:id`, `POST /internal/devices/:id/revoke`.
