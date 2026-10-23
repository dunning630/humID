---
"@humid/recovery-service": minor
"@humid/gateway-service": patch
"@humid/identity-service": patch
"@humid/svc": patch
"@humid/htp": minor
"@humid/api": minor
"@humid/mobile": patch
---

The recovery service checks the holder's own proof (audit SRV-30 follow-up). Every route that changes or releases recovery material verifies the holder's step-up itself, against the device key identity vouches for and against the body it received, once. That covers seal card, contacts, anchor, security keys, settings, link approval, a witness's help, cancelling, station verification and the new `DELETE /escrow` the gateway uses on account close. The setup recovery card is signed by the account key in the registration's live check (`setupCardMessage`), and identity issues a short-lived `created` statement for a new account. The recovery service needs `HUMID_CORE_STATEMENT_PK`. `holderProofs().check` takes the received `body`.
