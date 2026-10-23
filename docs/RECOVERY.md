# Devices and recovery

> **Two recovery modes.** Each holder picks one at setup: **only my own
> devices** (holder-only) or **a safe way back in** (hardened, two proofs + a
> wait + a veto, the recommended default). See
> [Two recovery modes](#two-recovery-modes) below.
>
> **Two-proof recovery (v2)** is what hardened mode uses: the seed is split
> into witness, ID-anchor and seal-card parts (and, in 4.0, a security-key
> part: [SECURITY-KEY.md](SECURITY-KEY.md)), and any recovery needs two
> different kinds of proof, with waits set by the evidence. See
> [CONTINUITY.md](CONTINUITY.md). The v1 card and contacts below still work
> for accounts that set them up earlier, and the app offers to upgrade them.

Status: POC. Code: `packages/recovery`, `services/recovery`, `services/identity`,
`apps/mobile/src/core/` (`enroll.js`, `join.js`, `recovery.js`, `recmode.js`).
Tests: `tests/recovery.test.js`, `tests/e2e/recovery.test.js`,
`tests/e2e/recovery-modes.test.js`, `tests/recovery-modes-app.test.js`,
`tests/e2e/recovery-epochs.test.js`.

## Two recovery modes

At setup, before the first face or fingerprint check, the app asks **"If you
lose every device, how do you want to be able to get back in?"**

| | Only my own devices (holder-only) | A safe way back in (hardened, recommended) |
|---|---|---|
| Who can open the vault | a live check on a device you already set up | the same, plus a new device after two proofs and a wait |
| What HumID's servers keep for recovery | **nothing** | a recovery card blob, witness pieces and security-key parts, each locked so the server can't open it on its own; and, if you link a passport, a passport piece **the server can open** (see below) |
| Lose one device | add a new one from another of your devices | the same, or recover |
| Lose every device | **the vault is gone for good. No one can bring it back, not HumID** | any two proofs, then a wait any surviving device can cancel |
| What setup asks for next | a second device, at once (it's your only safety net) | your recovery card, then a second proof and a second device |

Hardened is selected when the screen opens. Choosing holder-only needs an
explicit "I understand". Either way the choice can be changed later under
You → Recovery.

### What makes holder-only true, not a setting

- **No recovery part is made.** A holder-only setup makes no recovery card,
  and the app never calls the card, witness, ID-chip or security-key APIs.
- **The choice is signed by the account key.** The app signs the statement
  `HUMID-RECMODE-v1 ‖ lp(account id, mode, version, epoch)` with the
  account's ML-DSA-87 key. That key is derived from the account seed, which
  only the holder's devices have. Identity keeps the statement and shows it
  in `/identity/me`; the recovery service keeps it with the account's public
  key. Setup and every change are recorded as `recovery.mode_set` in the
  ledger, so they're in the public log.
- **The recovery service refuses, itself.** For a holder-only account it
  refuses `409 holder_only` to: storing a card, witnesses, an ID chip or a
  security key; starting or adding to any recovery that names the account (a
  card, witnesses, a chip, a key, a witness releasing a piece); releasing a
  recovery; and letting a device join through one. Adding a device from
  another of your own devices (section 1) still works.
- **A server can't flip it quietly.** The recovery service checks the
  stored signature again on every one of those routes. A row someone changed
  on disk no longer verifies, and then the account is treated as holder-only:
  nothing more is stored or released. The holder's own phone checks the
  statement against its account key too, and says so if it doesn't verify.

### Switching

- **Holder-only → hardened** adds ways back in. It needs a fresh live check,
  signs a new statement, and is recorded. Then you set up your proofs.
- **Hardened → holder-only** removes them, so it's destructive and runs in
  order. First every recovery piece the server holds is deleted (card,
  witnesses, ID chip, security keys), each with its own live check. Only then
  is the new statement signed and sent. The recovery service refuses the
  switch (`escrow_remains`) while anything is left, and cancels any recovery
  under way when it happens. Pieces already in other people's hands (a printed
  card, a witness's phone) can't be deleted from here. The switch also starts
  a new set of pieces (a new epoch, below), so those pieces can never be
  combined with anything again.

### Recovery epochs: making old pieces useless

All recovery parts of a set lie on one line through the account seed, and any
two of them rebuild it. Removing a witness or replacing a card only stops that
piece counting **on this server**: the piece itself still fits with the
others. So hardened mode has **Make new recovery pieces** (You → Recovery).
One live check signs a new epoch into the mode statement. Then:

- every new part comes from a different line (`quorumParts(seed, epoch)`), and
  the epoch is bound into the card and key encryption and the witness piece;
- the recovery service deletes every piece it held from older epochs, cancels
  any recovery under way, and refuses pieces made for an older epoch;
- `combineQuorum` refuses to mix parts from two epochs.

A removed witness's piece, an old card, or its blob in an old server backup
then opens nothing, anywhere. You set up your proofs again. Every mode switch
also starts a new epoch.

### What the operator can and can't do

| | Holder-only | Hardened |
|---|---|---|
| Open a document | no | no |
| Rebuild the account seed from what it stores | no: it stores no recovery parts | no: one part is never enough, and the card, witness and key parts are locked by something it doesn't have (the card code, a witness's key, a security key) |
| …with one more thing stolen from the holder | no | **without a passport link: no**, it needs two of the holder's proofs like anyone else. **With a passport link: yes.** The passport piece is locked with a key made from the chip's public data, which the server sees whenever the passport is linked or used. So an operator who records that once holds the passport piece, and the passport plus any ONE other stolen proof (a photo of the card, say) rebuilds the account key, with no wait and no veto. Holders who don't want to trust the operator that far should use witnesses or a security key, not a passport, or choose holder-only. The real fix is an open decision ([CONTINUITY.md](CONTINUITY.md#the-anchor-and-the-operator)) |
| Skip the wait or the veto | no recovery to skip | the waits and the veto are server rules: a dishonest server that also had two of the holder's proofs could release early. The cryptography guarantees confidentiality, not the clock |
| Turn recovery on behind the holder's back | no: the mode is signed by the holder's account key, and each of the holder's devices checks it | n/a |
| Turn recovery off, or deny one | yes: it can refuse service. That's availability, not access | yes, same |
| Learn who you are | nothing beyond the account | if you link an ID chip: document type and country, and your name and birth date while they pass through (not kept) |

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

On a phone, the same live check also makes a new hardware liveness key,
attested to `th`, which signs `deviceMessage` too. With the default device
policy the server adds the device only if that attestation checks out
([SECURITY.md](SECURITY.md#live-biometric-checks)), so even a recovered seed
can only join from a real phone with a live face or fingerprint.

Every way of getting a new device therefore comes down to getting `A` to that
device safely: another device, two-proof recovery
([CONTINUITY.md](CONTINUITY.md#layer-3--two-proof-recovery)), or the older
single-proof routes below.

## 1. Another device you still have (instant)

```
New device N                         Server (recovery)               Your device E (signed in)
biometric bind; D_N and link seed L
  wrapped under N's gate
POST /links {L.pk}           ----->  code = base32(SHA3("HUMID-LINK-v1" ‖ L.pk))[0:12]
shows XXXX-XXXX-XXXX                                         <-----  user types the code
                                     GET /links/:code        ----->  recompute code from L.pk; must match
                                                                     biometric: seal A to L.pk, signed by account key
                                     <-----  POST /links/:code/approve + step-up proof
poll; biometric: open envelope with L.sk -> A
check: envelope signer == account key derived from A
wrap A ‖ D_N; join with deviceMessage signatures
```

N also shows the code as a QR code (`HUMID:LINK:<code>`); scanning it on E is
the same as typing it. The code is a hash of N's public keys, so a server that swapped in its own
keys would also have to find a 60-bit second preimage within the 10-minute
window. Approval needs a fresh biometric check on E.

Before N joins, both screens show a **match code** and the person compares
them: `accountCheck = SHA3("HUMID-ACCOUNT-CHECK-v2" ‖ lp(accountId, L.kemPk,
L.xPk))`, 8 characters. It commits to the account **and this link's keys**,
so a server that sealed some other account's seed to N would show a different
code, and it couldn't prepare a look-alike account in advance (the link keys
don't exist until the link starts).

This route works in both recovery modes: it needs a device you already have.

## 2. Recovery card, v1 (72-hour wait)

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

## 3. Recovery contacts, v1 (any 2 of 3, then 72 hours)

The owner picks 2–5 people who also use HumID. `A` is split with Shamir secret
sharing over GF(2⁸): any majority (2 of 2, 2 of 3, 3 of 4, 3 of 5) rebuilds it,
and fewer reveal nothing. Each share is sealed to one contact's account key
and signed by the owner's account key.

Adding a contact needs the contact's **contact code**, which they show from
Security → Be a recovery contact. Like the link code, it is a hash of their
public keys, so the server cannot substitute keys.

To recover, the new device binds its biometric, makes a recovery key pair `R`,
and shows a code (a hash of `R`'s public keys, 16 characters, because a request
can stay open for a week) to send to the contacts. Each contact:

1. enters the code (verified against the keys the server returns);
2. confirms with a biometric check to see who is asking (opens the shares they hold);
3. confirms again to release their share, re-sealed to `R`.

When the threshold is met the 72-hour wait starts, with the same alert and
cancel as a card. Then the device opens the shares, rebuilds `A`, checks that
`A` derives the expected account id, and joins.

The contacts never see `A`, and neither does the server.

## In the app

| Where | What |
|---|---|
| Setup | Choose the recovery mode. Hardened: the first device makes a recovery card under the same biometric check and asks you to store it before opening the vault. Holder-only: no card; setup asks you to add a second device straight away. |
| Welcome → I already have HumID | Choose another device, or two proofs (or an older card or contacts). For a holder-only HumID only "from another device" is offered. This device binds its biometric first, so a long wait survives closing the app. |
| You → Devices | Add a device (type its code, then compare the match code), remove a lost one. |
| You → Recovery | The recovery mode and the switch. Hardened: make or replace your card, choose 2–5 witnesses, link your ID chip, add security keys, make new recovery pieces. |
| You → Protection | What's left to do. Holder-only: a second and a third device, and a warning while you have only one. |
| Vault and You | An alert while any recovery of your HumID is in progress, with a cancel button. |

`npm run dev` shortens the wait to 2 minutes (`RECOVERY_DELAY_MS`) so you can
try every path on one machine.

## Losing a device

Any other device can remove it (Security → Devices, biometric check). The
identity service marks it revoked; the gateway drops its sessions and refuses
its sign-ins. Nothing on a lost device opens without its owner's live
biometric, and a removed device can no longer reach the vault even then.

## After a Check-in erase

Check-in (docs/CHECKIN.md) erases vault data only: the identity, its devices
and its recovery proofs stay. A later recovery restores the HumID, but the
erased documents' keys are gone, so there is nothing of them to open. Recovery
also can't save an armed vault from a lost phone: it waits 24 hours or more,
longer than any check-in window.

## Limits in this POC

- Holder-only means what it says. Lose every device and every holder-held
  backup, and the vault is gone. HumID can't help, and setup says so plainly.
- Making new recovery pieces makes old pieces useless for **recovery**. It
  doesn't change the account seed. Someone who already rebuilt the seed (from
  two old pieces, before the change) keeps it. Rotating the seed itself is the
  follow-up below.

- Alerts appear when the owner (or a witness) opens HumID. There are no push or email alerts yet.
- Removing a device does not rotate `A`. A thief who defeated a lost phone's
  secure hardware would hold `A`, but could not sign in, because the device is
  revoked and adding a new one shows up in the ledger. Rotating `A`
  (re-sealing every document) is the follow-up.
- The 72-hour delay is a server setting (`RECOVERY_DELAY_MS`). The server
  enforces it, so it only holds while the server is honest about time and
  state. The cryptography alone guarantees confidentiality, not the delay.
- Contacts could collude, or be coerced together, to recover an account.
  That is why the wait and the cancel apply to contacts too.
