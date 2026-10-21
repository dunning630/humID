# Security key: a fourth recovery proof

Status: 4.0 (provisional). Code: `packages/fido` (CTAP 2 over NFC), `packages/recovery`
(the key part), `services/recovery`, `services/gateway`, `apps/mobile`. Tests:
`tests/fido.test.js` (the client), `tests/fido-sim.test.js` and `tests/fido-crosscheck.test.js`
(the simulated key, and the simulated key against Yubico's python-fido2), `tests/seckey-part.test.js`
(the key part), `tests/e2e/seckey.test.js` (real services), `tests/browser/seckey.mjs` (two phones).

## What it adds

Two-proof recovery ([CONTINUITY.md](CONTINUITY.md#layer-3--two-proof-recovery)) splits the
account seed `A` so that any two different kinds of proof rebuild it on a new phone:
witnesses, the ID chip, the recovery card. 4.0 adds a fourth kind: a **FIDO2 security key**
(a YubiKey 5 NFC, a Feitian or Token2 NFC key, any CTAP 2 key with NFC and `hmac-secret`).

A security key is a convenient strong proof: its secrets never leave it, no website can ask
it for HumID's credential, and it locks itself after eight wrong PINs. It is the physical
proof a person keeps on a keyring, and a natural pair for any of the other three.

## What it is not

**HumID still stores no biometrics.** The key holds no face or fingerprint, and HumID
receives none; the phone's own secure chip still does every biometric match, and
[ANONYMITY.md](ANONYMITY.md#registration-collects-nothing-personal) still holds: no image,
template or measurement ever leaves the phone. The key is a *thing you have* protected by a
*PIN only it checks*.

**HumID doesn't hold the key's secret either.** The secret comes out of the key only when
the key is present and its PIN is right, and only on the phone that asked.

## The parts, now four

`A` is split by the same degree-1 polynomial as before (`A + c·x` over GF(2⁸), coefficients
from `HKDF-SHA3-256(A, "HUMID-QUORUM-v1 coefficient epoch e")`), now evaluated at four
points. Any two different points rebuild `A`; one reveals nothing. Every part already in use
is unchanged, so existing cards, witnesses and anchors keep working and fit with a key part
made later.

| Part | x | Protected by | Released when |
|---|---|---|---|
| Witness | 1 | split among 2–5 witnesses | a majority approve, each with a live check |
| Anchor | 2 | the passport or ID chip | the chip is proven again (station or live) |
| Card | 3 | the recovery card code | the card is presented |
| **Key** | **4** | **a security key's `hmac-secret`, behind its PIN** | **the key signs a fresh challenge from the server with its PIN verified, and the phone holds the key's secret** |

## How the key protects its part

The key never stores the part. HumID uses the key as a keyed one-way function that only
works with the key present and its PIN entered.

**On the key (once, when adding it):** a discoverable credential for the relying party
`recovery.humid.invalid`, made with:

- `rk: true` — the key remembers it, so a new phone can find it without being told anything;
- `credProtect: 3` (*userVerificationRequired*) where the key supports it — without the PIN
  the key won't even admit the credential exists;
- `hmac-secret: true` — the key keeps a random 32-byte `CredRandomWithUV` for it, inside.

`.invalid` is a top-level domain reserved never to exist (RFC 2606), so **no website can ever
ask a browser for this credential**: WebAuthn only lets a site use its own domain. Only an app
talking CTAP directly to the key (as HumID does, over NFC) can reach it, and then only with
the PIN.

**The secret:** a `getAssertion` with the PIN verified and the `hmac-secret` extension, salt

```
salt = SHA-256("HUMID-KEY-v1 hmac-secret salt")
S    = HMAC-SHA-256(CredRandomWithUV, salt)        computed inside the key
```

`S` reaches the phone encrypted under the PIN protocol's shared secret (an ECDH between the
phone and the key for this one exchange), so nothing on the radio link carries it in the
clear. From `S` the phone derives:

```
tag  = base32(HKDF-SHA3-256(S, "HUMID-KEY-v1 tag")[0:16])     the server finds the part by this
key  = HKDF-SHA3-256(S, "HUMID-KEY-v1 key")                   32 bytes
blob = nonce(12) ‖ AES-256-GCM(key, encode(part x=4), aad = "HUMID-KEY-v1|" ‖ accountId)
```

The server stores `(account, tag, blob, the credential's public key, its credential id, its
signature counter, a label sealed under the index key)`. It cannot open the blob: `S` is 256
bits it never receives.

Where `S` lives: inside the key; in the adding phone's memory for the one live check that
seals the part; and on a recovering phone, under that phone's own lock (its secure chip and
your face or fingerprint), for the length of the wait, so the vault can open when the wait
ends. The salt is fixed, so `S` doesn't change while the credential exists: if you ever
suspect a phone that held it, remove the key from HumID and add it again, which makes a new
credential and a new `S`.

### The key proves itself to the server, too

The tag alone is not the proof. Every time a key is used, the server sends a fresh 32-byte
challenge, and the key signs it, with the PIN verified, in the same `getAssertion` that
yields `S`:

```
clientDataHash = SHA-256("HUMID-KEY-v1 " ‖ purpose ‖ " " ‖ challenge)       purpose: add | recover
the key signs   authenticatorData ‖ clientDataHash  (ECDSA P-256, ES256)
```

The server checks, against the public key stored when the key was added: the signature;
`rpIdHash = SHA-256("recovery.humid.invalid")`; the **UP** and **UV** flags (present, PIN
verified); that the **BE/BS** flags are clear (a credential that can be backed up or synced,
like a cloud passkey, isn't a physical key and is refused); and the signature counter, which
must move forward unless the key keeps it at zero. A counter that goes backwards is refused:
it's the sign of a cloned key. (A key that keeps its counter at zero gets no clone check; a
key used so often that its counter wraps past 2³² must be added again.)

So a recovery counts the key as a proof only when **the key itself** answered the server's
challenge, with its PIN, in that recovery, like the ID chip's Active Authentication. Knowing a
tag is worth nothing; holding a copy of the blob is worth nothing.

## Waits

A security key is something you have, like the card. The waits keep the rule they had
(the formula in `quorumDelay` didn't change; the key is one more kind):

| Proofs | Wait (production) |
|---|---|
| ID chip at a **station** + anything | 24 h |
| **Witnesses** + key (or card, or live chip) | 72 h |
| Any two of key, card, live chip (no people) | 7 days |
| any of the above within 14 days of a duress signal | × 2 |

During the wait every device of the account sees the alert, naming the evidence
("security key + recovery card"), and any of them vetoes with one live check. **Removing the
key during the wait also voids it as a proof** for every recovery under way.

## The PIN

You type the PIN into HumID on your phone; the app hands it straight to the key and forgets
it. It never reaches HumID's server and is never stored. It travels from the phone to
the key encrypted under the PIN protocol's shared secret (protocol 2, or 1 for older keys),
and only as a hash prefix (`LEFT(SHA-256(PIN), 16)`, encrypted) when unlocking. The key
counts wrong tries itself: three in a row until it is touched again, eight in total before it
blocks for good. HumID shows how many are left.

A key without a PIN gets one while it's added (6 or more characters; the key's own minimum
may be higher). A key that can't do PIN-verified `hmac-secret` is refused with a plain
reason, before anything is stored.

## Holes closed, and what is left

| Attack | Why it fails |
|---|---|
| Steal the key | Needs its PIN; eight wrong tries block it forever. With the PIN, it's still one proof: a second kind, a wait, and a veto from any of your devices. |
| Steal the key and the recovery card together | Two proofs, no people: the 7-day wait, alerts on every device, a veto. Keep them apart, as with the card and your passport. |
| Copy the key | FIDO keys don't export credentials. A clone would have to keep the counter moving forward on both copies. |
| Phishing site asks the key | The relying party is `recovery.humid.invalid`: no site can ever claim it. |
| Malicious app (on your phone or a computer you plug into) | A native app can talk CTAP to the key directly. With the key and its PIN typed into it, it could read the key's answer: one proof, never a vault on its own. Type the PIN only into HumID. |
| A software "key" (a modified app registers keys made in memory) | Adding a key takes a live check on one of your devices, and a synced passkey is refused by its flags. The server can't yet tell a hardware key from a well-made software one: that needs attestation checked against the FIDO Metadata Service, which is next. Until then, a software key is as good as the device it was made on. |
| Compromised server | Holds a public key, a counter, a tag and a blob under a 256-bit secret it never sees. It can deny service, or skip the wait (as for every proof: the waits are server rules), never open a vault alone. |
| Tag guessed or leaked | Not accepted without the key's own signature over a fresh challenge. |
| Replay a captured key answer | Each challenge is used once, lasts 5 minutes, and is bound to one recovery. |
| Duress: someone forces you to add their key | Adding or removing keys is a guarded change: in a duress session it fails like a busy server. |
| Lost key | Remove it from any device (one live check). Its part stays useless without the key. Add a new one. |

**Left, and said plainly:**

- *Attestation.* The server doesn't check which make and model a key is (see above).
- *Which accounts share a key.* Every recovery tap sends the tags of every HumID credential
  on the key, so a server sees that two HumIDs share one physical key if they do.
- *Recording.* Adding and removing a key are recorded in Activity, but like the recovery
  card, the ID chip and witnesses, the change isn't refused when the record can't be
  written (fail-closed recording for every recovery setting is a follow-up).
- *Older keys.* A CTAP 2.0 key without `credProtect` shows, without its PIN, that it holds a
  HumID credential (it still can't be used without the PIN). The app says so when it's added.

- *Where it works.* iPhone (7 or later) and Android phones with NFC, and computers with a
  USB contactless card reader (the same reader as for ID chips). A key **plugged into a
  computer's USB port** isn't supported yet: Windows only lets apps reach USB security keys
  through its own WebAuthn service, which needs a native integration that's next.
  Lightning and USB-C keys on phones need the key maker's accessory protocol, also next.
- *Built-in fingerprint keys* (YubiKey Bio) are USB-only today; their PIN works when they
  support NFC.
- The server keeps the wait honest only while it's honest about time (as for every proof).

## In the app

| Where | What |
|---|---|
| You → Recovery → Security key | Add a key (name it, PIN, hold it to the phone once, one live check). See your keys; remove one with a live check. Up to four keys, so you can keep a spare. |
| I already have HumID → Prove it's me | *Security key*: type its PIN, hold it to the phone. One more live check keeps its secret, under this phone's lock, for the end of the wait. |
| Activity | `recovery.key_added`, `recovery.key_removed`, and `recovery.evidence · security key` |

`npm run dev` simulates a security key in the browser (PIN `123456`), the way it simulates
an ID chip.

## Wire details

`@humid/fido` implements CTAP 2.1 over NFC (ISO 7816-4), sharing the app's existing NFC
transport (`tauri-plugin-humid-nfc`: Core NFC, Android `IsoDep`, PC/SC):

- SELECT `A0000006472F0001`; the key answers `FIDO_2_0` (or `U2F_V2` only: refused, CTAP 1
  has no `hmac-secret`).
- `NFCCTAP_MSG` (`80 10 80 00`, P1 `0x80`: the key may answer `9100` while it works, and the
  phone polls `NFCCTAP_GETRESPONSE` `80 11 00 00`), command chaining (CLA `0x90`) above 255
  bytes, `61xx` response chaining with GET RESPONSE.
- CTAP2 canonical CBOR, decoded with limits (depth 8, 64 KiB, 512 items).
- `authenticatorGetInfo`, `authenticatorClientPIN` (getRetries, getKeyAgreement, setPIN,
  getPinToken, getPinUvAuthTokenUsingPinWithPermissions with `mc|ga`), `authenticatorMakeCredential`,
  `authenticatorGetAssertion`, `authenticatorGetNextAssertion`.
- PIN/UV auth protocols 2 and 1, preferring 2.
- `hmac-secret` with one salt, `credProtect` level 3 when offered.

Tests run the client against a simulated authenticator written separately from it with
`node:crypto` (`tests/support/fido-sim.js`), and the simulator itself against Yubico's
`python-fido2` client, so the two sides of every exchange are checked by code that didn't
write the other side.
