# Devices and recovery

Status: POC. Code: `packages/recovery`, `services/recovery`, `services/identity`,
`apps/mobile/src/core/controller.js`. Tests: `tests/recovery.test.js`,
`tests/e2e/recovery.test.js`.

## The problem

The vault server never holds a key that can open a document. That is the
product's promise, and it means that if the only copy of the key lives on one
phone, losing that phone loses the vault. A face or fingerprint cannot
rebuild the key on a new phone either: the biometric only unlocks a key held
by that phone's secure hardware, and the biometric itself never leaves it.

So the key has to exist in more than one place, and every place has to be
protected by something other than the lost phone, without HumID ever
holding it.

## Keys

Every HumID account has one **account seed** `A` (64 random bytes), created
on the first device. It derives:

| From `A` | Used for |
|---|---|
| ML-KEM-1024 + X25519 key pair | every document is sealed to it, so any device holding `A` can open it |
| ML-DSA-87 key pair | signs envelopes; authorises new devices; its hash is the account id (`hid_…`) |
| index key | encrypts item names and types |

Every device also has its own **device seed** `D` (64 random bytes). It
derives the device's ML-DSA-87 key, used only to sign in and to sign step-up
proofs. Its hash is the device id (`dev_…`). The server can refuse one device
without touching the others.

On each device, the biometric gate releases one secret that unwraps `A ‖ D`.
Both exist in memory only during a biological interrupt.

**Server rule: a device joins an account only with two ML-DSA-87 signatures
over the same statement,** one by the account key (only a holder of `A` can
make it) and one by the device key (proof of possession), both bound to the
HTP session transcript:

```
deviceMessage = "HTP/1 device" ‖ lp(th, accountId, SHA3-256(device dsaPk))
```

Every way of getting a new device therefore comes down to getting `A` to that
device safely. There are three.

## 1. Another device you still have (instant)

```
New device N                         Server (recovery)               Your device E (signed in)
link keys L <- ephemeral ML-KEM + X25519
POST /links {L.pk}           ----->  code = base32(SHA3("HUMID-LINK-v1" ‖ L.pk))[0:12]
shows XXXX-XXXX-XXXX                                         <-----  user types the code
                                     GET /links/:code        ----->  recompute code from L.pk; must match
                                                                     biometric: seal A to L.pk, signed by account key
                                     <-----  POST /links/:code/approve + step-up proof
poll, open envelope with L.sk -> A
check: envelope signer == account key derived from A
biometric bind; wrap A ‖ D_N; join with deviceMessage signatures
```

The code is a hash of N's public keys, so a server that swapped in its own
keys would also have to find a 60-bit second preimage within the 10-minute
window. Approval needs a fresh biometric check on E.

## 2. Recovery card (72-hour wait)

At setup the app shows a card code: 120 random bits as 24 Crockford base32
characters plus a check character (`HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).

```
tag  = HKDF-SHA3-256(card, "HUMID-CARD-v1 tag")[0:16]      the server looks the card up by this
key  = HKDF-SHA3-256(card, "HUMID-CARD-v1 key")
blob = AES-256-GCM(key, A, aad = "HUMID-CARD-v1" ‖ accountId)
```

The server stores `(account, tag, blob)`. It cannot open the blob, and the tag
reveals nothing about the card.

To recover, the new device binds its biometric first, then sends the tag. The
server opens a recovery request with **release time = now + 72 hours** and
records `recovery.requested` in the account's ledger. Every signed-in device
of that account sees an alert and can cancel with a biometric check. After
the release time the server hands the blob to the requesting device, which
needs the card again (held behind its own biometric while it waits) to
decrypt it.

A stolen card is not enough on its own: the owner has three days to notice
and cancel.

## 3. Recovery contacts (any 2 of 3, then 72 hours)

The owner picks 2–5 people who also use HumID. `A` is split with Shamir secret
sharing over GF(2⁸): any majority (2 of 2, 2 of 3, 3 of 4, 3 of 5) rebuilds it,
and fewer reveal nothing. Each share is sealed to one contact's account key
and signed by the owner's account key.

Adding a contact needs the contact's **contact code**, which they show from
Security → Be a recovery contact. Like the link code, it is a hash of their
public keys, so the server cannot substitute keys.

To recover, the new device binds its biometric, makes a recovery key pair `R`,
and shows a code (a hash of `R`'s public keys) to send to the contacts. Each
contact:

1. enters the code (verified against the keys the server returns);
2. confirms with a biometric check to see who is asking (opens the shares they hold);
3. confirms again to release their share, re-sealed to `R`.

When the threshold is met the 72-hour wait starts, with the same alert and
cancel as a card. Then the device opens the shares, rebuilds `A`, checks that
`A` derives the expected account id, and joins.

The contacts never see `A`, and neither does the server.

## Losing a device

Any other device can remove it (Security → Devices, biometric check). The
identity service marks it revoked; the gateway drops its sessions and refuses
its sign-ins. Nothing on a lost device opens without its owner's live
biometric, and a removed device can no longer reach the vault even then.

## Limits in this POC

- Alerts appear when the owner opens HumID. There are no push or email alerts yet.
- Removing a device does not rotate `A`. A thief who defeated a lost phone's
  secure hardware would hold `A`, but could not sign in, because the device is
  revoked and adding a new one shows up in the ledger. Rotating `A`
  (re-sealing every document) is the follow-up.
- The 72-hour delay is a server setting (`RECOVERY_DELAY_MS`). The server
  enforces it, so it only holds while the server is honest about time and
  state. The cryptography alone guarantees confidentiality, not the delay.
- Contacts could collude, or be coerced together, to recover an account.
  That is why the wait and the cancel apply to contacts too.
