---
"@humid/msg": minor
---

Delete, built in: delete a message for yourself or for both of you (only your own messages on the contact's phone); unsend at the relay before delivery; a delete for an undelivered message destroys the contact's key for it, so a kept copy can never be opened; disappearing messages (30 s to a year); delete a whole conversation and its keys, for you or for both; cancel an invite or withdraw a request. The message history is re-sealed under a new key on every save, so deleted messages can't be recovered from storage. Superseded ratchet states are now overwritten. See "Deleting" in docs/MESSAGING.md.
