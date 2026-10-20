# Person to person (HumID 4.0, provisional)

> **Status:** 4.0 track, on branch `v4/p2p-comms`. The protocol, formats,
> delete and relay rules are built and tested (`packages/msg`, `tests/msg.test.js`,
> `tools/timing-msg.mjs`); the relay service, the gateway's stamp route and the
> app screens are not. Like the rest of HumID, it needs an independent
> cryptographic review before real conversations go through it.

Two HumID holders approve each other and talk directly. Each knows the other
only by an ID. Every message is end-to-end encrypted with post-quantum keys,
and can carry proof that a live human sent it, without saying which human.

## The promise, stated exactly

| What people want | What HumID 4.0 does | The honest limit |
|---|---|---|
| "They only know my ID" | Each contact sees a different **persona ID** (`HC-XXXX-XXXX-XXXX-XXXX-XXXX`), made just for them. Two contacts comparing notes can't tell they know the same person. No name, number or email exists anywhere. | Whatever you choose to tell them in a message. |
| "Zero chance of interception" | Interception is always *possible*: anyone on the network, or the relay itself, can copy the bytes. What they get is padded ciphertext, in one of a few fixed sizes, posted to a random mailbox that changes every day. | The relay sees when a phone deposits or fetches and from which address (use a VPN or Tor to hide that). |
| "Not crackable" | Every key needs **both** ML-KEM-1024 and X25519 broken, and handshakes need **both** ML-DSA-87 and SLH-DSA (hash-based) forged. Keys change every time the conversation changes direction, so copying ciphertext now and decrypting it with a quantum computer later gains nothing. | "Not crackable" means no known attack, classical or quantum, comes close. No one can promise more than that for any system; the weak point in practice is a compromised phone, not the maths. |
| "I can delete it" | Delete one message or a whole conversation, for you or for both of you; turn on disappearing messages; unsend a message the contact hasn't fetched yet. Deletes destroy keys, so deleted data can't be read back from the phone's storage or from a copy of the ciphertext. | Nothing can reach into the contact's phone against their will: a screenshot, a modified app or a second camera keeps what it saw. "For both" deletes *your* messages from *their* phone; what they sent stays theirs. |
| "Validated as a live human" | A **live stamp** in a message proves a live face or fingerprint check on a proven phone approved those exact bytes. The server signs it blind, so it can't connect the stamp to anyone. | It proves *a* human approved the message, not *which* one; the ratchet proves it came from your contact. A person could still approve messages written by someone else (see "Limits"). |

## How two people meet

```
 A (inviter)                       relay (sees: random box ids, fixed-size blobs)          B (invitee)
 ──────────                        ─────                                                    ──────────
 createInvite ── bundle ─────────► box = SHA3(invite secret)
 shows HI-XXXX-… (QR, in person) ───────────────────── invite code, out of band ────────────► openInvite
                                                                                               checks it with the secret
                                   reply box ◄──────────── request + live stamp ──────────── requestContact
 readRequest:                                                                                  (new persona for A)
  "HC-7F3K-… wants to connect
   live human ✓  ·  note: 'from the workshop'
   safety code QM4T-…"
 live check → acceptRequest
 encrypt("accept") ─────────────►  conversation box (rotates daily)  ───────────────────────► session opens: connected
 ◄──────────────────────────────── messages both ways, each optionally stamped ─────────────►
```

- **The invite code is the only secret that moves outside HumID.** It carries
  128 random bits (what opens the invite) and an 80-bit pin of the inviter's
  persona (what the invite must contain), plus two check characters: `HI-` and
  eleven groups, best shown as a QR code. It lasts 24 hours by default (7 days at most) and admits one
  person by default. Show it in person when you can: the audit's warning about
  cloned voices applies to anything read over the phone.
- **No one can read, swap or impersonate an invite.** The bundle is encrypted
  under a key from the invite secret, which the relay never sees, and the phone
  that opens it checks the persona inside against the code's pin. So even
  someone who learns the code (another invitee, a shoulder-surfer) can't post a
  bundle of their own under it and pose as the inviter. A request is bound to
  the same secret, so someone without the code can't produce one that opens.
- **Approval takes a live check** on A's side, and a live stamp shows A that a
  live human made the request. A sees the requester's persona ID, the short
  note they chose to write, and the safety code. Nothing else exists to see.
- **The safety code** (20 characters, 100 bits) commits to both personas' full
  key sets. Comparing it in person, or scanning each other's screens, proves no
  one substituted keys anywhere, even if the invite travelled over a channel
  someone controls.

## Personas: an ID per contact

```
personaSeed = HKDF-SHA3-256(account seed, random 32-byte salt, "HUMID-MSG-v1 persona", 64)
keys        = ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256f, X25519 — each from its own HKDF label
persona ID  = "HC-" + Crockford-base32(SHA3-256(label ‖ lp(public keys)))[0:20]
```

The salt lives in the holder's sealed contact list. Any of their devices can
re-derive the persona from the account seed (which a live check releases);
forgetting the salt forgets the persona for good. A persona has no link to the
account's keys or to any other persona: the vault server, the relay and other
contacts can't connect them.

## The conversation: a hybrid post-quantum double ratchet

```
handshake root  = HKDF(ss_onetime ‖ ss_persona ‖ dh1 ‖ dh2 ‖ dh3 ‖ invite-bind, salt = transcript)
each direction change:
  RK', CK = HKDF(X25519(new, peer) ‖ ML-KEM-1024 shared secret, salt = RK, "ratchet step")
each message:
  message key, next CK = HMAC-SHA3-256(CK, 1), HMAC-SHA3-256(CK, 2)
  AES-256-GCM(message key, payload, aad = conversation id ‖ header)
then the whole thing, header included, is sealed again under the direction's wire key and padded
```

| Property | How |
|---|---|
| Confidentiality, now and against quantum computers | Each step needs ML-KEM-1024 **and** X25519 broken. |
| Forward secrecy | Used keys are erased; a phone seized tomorrow can't read today's messages. `tests/msg.test.js` steals a copy of the state and shows it can't reopen a message it already read. |
| Healing | After one exchange in each direction, a stolen copy of the state can't read the conversation any more. Tested. It can still recognise the conversation's mailboxes and outer layer, whose keys are fixed at the handshake: a thief keeps the metadata, not the content. (Rotating those keys with the root key is on the list below.) |
| Deniability | Messages are authenticated by shared keys, not signatures. Your contact knows you sent it; they can't prove it to anyone else. (A stamp proves *a* live human, not you.) |
| Order, loss, replay | Messages open out of order (up to 1,000 skipped); a replay or old message is refused; a tampered message changes nothing. A gap that stays open is reported as a missing message, so a relay that drops traffic is noticed. |
| Duress | A message sent from a duress unlock carries an encrypted duress flag that only the contact's app sees. Every payload carries the flag at a fixed width and reserves room for a stamp, so duress, stamped and ordinary messages of the same length are the same size on the wire. Tested. |
| Saved before sent | `persist` runs before a message is handed out; if saving fails, the step is undone. A per-message random salt in each header means even a device restored from an old backup never repeats an AES key and nonce. Tested. |

Sizes: every message is at least 8 KiB on the wire: each header carries a
fresh ML-KEM-1024 public key and ciphertext (about 3.2 KB), and every payload
reserves room for a stamp so stamped and unstamped messages look alike. An invite
is 64 KiB and a request 128 KiB, mostly the SLH-DSA signature (49,856 bytes),
made once per contact.

## Live stamps

```
phone:  commitment = SHA3-256("stamp message" ‖ lp(conversation id, sender persona, nonce, kind, body))
        blinded    = Blind(commitment)                 RFC 9474, RSABSSA-SHA384-PSS-Randomized
server: inside a live step-up (secure-chip-signed face or fingerprint check), one stamp per check:
        blind signature = BlindSign(stamp key, blinded)
phone:  stamp = Finalize(...)  → put INSIDE the encrypted message
contact: verify(stamp, commitment recomputed from what arrived)
```

- **Unlinkable, forever.** Blindness is information-theoretic: the server can't
  connect a stamp to the check that bought it, whatever it computes, quantum or
  not. It never sees the message, the conversation or the recipient.
- **Bound to one message.** A stamp copied onto another message fails.
- **Separate key.** The stamp key must never be the access-pass key: a blind
  signer signs whatever it's handed, so a shared key would let a "stamp" request
  carry a blinded access pass. The app refuses a stamp key that appears among
  the pass keys, and stops counting a key's stamps after its `acceptUntil` day.
- **Forgery after quantum computers** rests on RSA, as for passes. A future
  quantum computer could forge stamps then; it couldn't unmask anyone, and a
  stamp only matters when it's received.

### A new signal about human activity, with nothing about any human

The stamp issuer can count stamps per day and publish the total: how many
messages, anywhere on the network, a live human approved. That is a measure of
real human activity no bot farm can inflate without real people passing real
checks, and it reveals nothing about who talked to whom. (What it does learn,
see the table below: how many stamps each account asked for.)

## Deleting

Every kind of delete is in one object the app uses, `Conversation`
(`packages/msg/src/conversation.js`).

| You choose | What happens on your phone | What happens on the contact's phone | At the relay |
|---|---|---|---|
| **Delete for me** | The message is overwritten and left out of the next save. | Nothing. | Nothing. |
| **Delete for both** (your own messages) | As above. | Their app erases it. If it hasn't arrived yet, their phone destroys the one key that would have opened it, so it can **never** be opened, even from a copy someone kept. | If the contact hasn't fetched it yet, it's **unsent**: removed, and you're told it was never delivered. |
| **Disappearing messages** (either of you sets it, 30 s to a year, or off) | Each message is deleted when its time is up, counted from when it was sent. | Deleted when its time is up, counted from when it arrived. | Messages are kept at most 14 days anyway. |
| **Delete conversation, for me** | Every message and every key for this contact is overwritten; the contact's ID for you is forgotten for good. | Nothing; they aren't told. | — |
| **Delete conversation, for both** | As above. | Their app erases every message you sent, then the conversation ends. | Anything not yet fetched is unsent. |
| **Cancel an invite / withdraw a request** | The invite's one-time keys are destroyed; requests to it can never be read. | — | The invite or request is taken down, so no one else can fetch it with the code. |

### Why a deleted message really is gone

- **Keys, not files.** Erasing a file on a phone's flash storage doesn't
  reliably erase its bytes: the storage chip moves data around and old copies
  survive. So the history is sealed under a **new random key every time it's
  saved**, and the app keeps only the newest key, in the phone's secure storage
  (Keychain / Keystore), overwriting the old one. A deleted message is absent
  from the new save, and every older save that still held it is sealed under a
  key that no longer exists. Tested: the old save doesn't open with the new key.
- **The ratchet already forgets.** Every message key is erased the moment it's
  used, so the conversation's own state never holds anything that could reopen
  past messages. Each step works on a copy of the state, and the copy it
  replaces is overwritten, not left in memory for the garbage collector. Tested.
- **Unsent means never readable.** A delete for a message that hasn't arrived
  names its place in the ratchet, and the contact's phone destroys the key it
  had set aside for it. A relay or a network tap that kept the ciphertext holds
  bytes nobody can ever open. Tested, including across a ratchet step.
- **Unsend tokens.** Each thing a phone posts has a random token only that
  phone holds; the relay stores a hash of it. Showing the token removes the
  object if it's still there. No one else can unsend it, and the token links
  nothing. Tested.
- **Deleting a conversation** overwrites every key in it (root, chain, ratchet,
  mailbox and wire keys, keys held for late messages); the session refuses any
  further use. Tested.

### What delete can't do

- **It can't force another phone.** "Delete for both" asks the contact's
  HumID app to erase, and an unmodified app always does. A screenshot, a photo
  of the screen, or a modified app keeps what it already showed. That's true of
  every messaging system; HumID says so instead of implying otherwise.
- **You delete what you sent.** A contact can never delete your messages from
  your phone, and you can't delete theirs from theirs: each person controls
  their own words on the other's phone, and their own copy of everything.
  Tested: a delete naming someone else's message is refused.
- **After a conversation has ended**, a delete for both can't be delivered; the
  app says so and keeps your copy so you can delete it for yourself.
- **Wiping memory in JavaScript** is best effort: key material is overwritten,
  but text shown on screen is a JavaScript string, which can't be. The storage
  promise (keys, not files) doesn't depend on this.

## Who can know what

| Party | Sees | Never sees |
|---|---|---|
| **Your contact** | your persona ID for them, your messages, the safety code, which messages were stamped live | your account, your other personas, your other contacts |
| **The relay** | random box ids (rotating daily per direction), objects of fixed sizes, deposit and fetch times, the address that connected; from the size class, roughly what kind of object it is (an invite is 64 KiB, a request 128 KiB, a message usually 8 KiB) | who you are, who you talk to, any persona key or ID, any message content |
| **The stamp issuer (vault server)** | that an account passed a live check and asked for a stamp, and how many per day | the message, the conversation, the recipient, the finished stamp |
| **Someone on the network** | that a phone talked to the relay, when, how much | anything inside |
| **A thief with your unlocked phone** | your conversations, as they are on screen | anything already erased by the ratchet |

## Applying the security audit

The 2026 audit ("HumID Security Audit: Tests, Coverage and Beyond-Standard
Threats") lists threats and open findings across HumID. Everything below is
built into 4.0 and tested unless marked otherwise. An independent review of the
first cut found no critical or high issues; its ten medium and low findings are
fixed or stated as limits here.

| Audit item | What 4.0 does |
|---|---|
| Timing leaks in the PQ code (T3–T4) | All primitives sit behind one swappable backend (`backend.js`). The app replaces the JS maths with the platform's own (iOS 26 CryptoKit ML-KEM-1024 / ML-DSA-87) via `useBackend`, which first proves the replacement agrees byte for byte. The relay runs no cryptography, so there's no server-side timing oracle at all. `npm run test:timing` (Welch's t-test, valid vs invalid ML-KEM ciphertexts, X25519 scalars) runs in CI, informational on shared runners. |
| A lattice break (T5) | Every key needs X25519 as well as ML-KEM; every handshake needs SLH-DSA (hash-based) as well as ML-DSA. **Next:** HQC as a third KEM in the ratchet step once its standard is final (2027): one more secret in the step's input, under a new message-format version. |
| Signatures that must outlive their algorithm (T5) | Handshakes are dual-signed ML-DSA-87 + SLH-DSA-SHA2-256f, both required. Messages deliberately aren't signed (deniability), so nothing long-lived depends on lattice signatures. |
| Kernel spyware (T4) | Keys are erased as soon as used (forward secrecy), the ratchet heals after one exchange, and conversation state is sealed at rest. **Next:** keep persona signing keys in the Secure Enclave where the platform supports ML-DSA. |
| Forged attestation (T2–T4) | Stamps are issued only inside a step-up that already enforces the device policy. **Depends on** SEC-S-04 (fetch the Android revocation list) for stamps to mean what they say. |
| Fake faces (T2) | Stamps come only from the phone's hardware-gated check; there is no camera path and must never be one. |
| Coercion (T4) | Encrypted duress flag; constant-size wire objects so a duress session looks like any other; nothing on the relay to compel. |
| Rogue operator (T3) | The relay can't read, forge or substitute anything; safety codes catch key substitution; dropped messages show up as gaps. |
| AI-scale social engineering (T2) | Invites expire in 24 h and admit one person by default; requests carry a live stamp; approval takes a live check; the safety code is the defence against a cloned voice. |
| SEC-S-13 (reveals whether an account exists) | The relay answers an empty box and a never-used box identically. Tested. |
| SEC-S-02, -03, -08 (DoS) | Every relay dimension is capped (object size and count per box, bytes per box and in total, expiry), and rate limits key IPv6 by its /64. Tested. |
| H-1 (signer not pinned) | A contact's persona keys are pinned at the handshake; every later message is authenticated by keys only that persona could hold. |
| SEC-A-04 (swapped or replayed index) | Sealed conversation state binds its conversation id and a version number; an older copy is refused, because rolling back a ratchet would re-open used keys. Tested. |
| A-10 (40-bit match code) | Safety codes are 100 bits; invite codes pin the inviter's persona with 80 bits. |
| Malformed peer keys | Every ML-KEM key that arrives is checked (FIPS 203 modulus check) before use, so a bad one is refused at the door instead of breaking the conversation later. Tested. |
| "Unlinkability checked by string search only" | Tested by the protocol: personas share no key material, box ids differ by direction and day, every relay object is a fixed size class with no persona keys or IDs inside, the issuer sees only blinded values, the same message blinds differently each time. |
| Relay rate-limit table | Bounded; when full it drops past windows and then refuses new addresses, so a flood of addresses can't reset a busy client's limit. Tested. |
| "Fuzzing: one fixed seed, any error type accepted" | `tests/msg.test.js` fuzzes messages, requests, invites, stored state and codes with a fresh seed each run (printed on failure, rerun with `MSG_FUZZ_SEED`), and accepts only `MsgError` with a code. |

**Prerequisites before the relay and stamp route go live** (server-wide
findings outside this module, in the audit's order): SEC-S-01 (bind internal
requests to method, path and body, and refuse replays: the stamp route is a new
internal call), SRV-05, SEC-S-09, SEC-S-04, and the supply-chain items SC-01–06.

## Limits

- **A human can approve someone else's words.** A stamp proves a live check
  approved these bytes; a person paid to approve a bot's messages would produce
  valid stamps. Each stamp costs one live check, which caps it at human speed.
- **The issuer learns volume per account.** It knows account X asked for 14
  stamps today, never for what or for whom.
- **Network metadata.** Timing and addresses are visible to the relay and the
  network, and size classes tell invites, requests and messages apart. A
  request also carries its ephemeral X25519 key in the clear (it has to: it's
  how the inviter derives the keys); Elligator encoding would make it look
  random. Cover traffic is not built.
- **Skipped message keys** (for messages a relay withholds) are kept until the
  message arrives or for 14 days, the relay's retention, then erased.
- **One messaging device per account, for now.** The ratchet state lives on one
  device; multi-device sessions come later.
- **The endpoints.** Encryption ends on the two phones. A compromised phone, a
  screenshot or a contact who forwards your words is outside what any protocol
  can stop.

## What is not built yet

1. **`services/relay`**: the reference relay as a service (same rules as
   `memoryRelay`), no accounts, behind the edge.
2. **Gateway stamp route**: `POST /msg/stamp` inside a live step-up, one blinded
   value per check, a separate stamp key, daily totals published.
3. **App screens**: Contacts tab (invite by QR or code, requests with the live
   badge and safety code, approve with a check), conversations, missing-message
   notices, duress alerts opt-in per contact.
4. **Contact list and conversation storage**, sealed under keys from the
   account seed, with the rollback counter and the newest history key kept in
   the device's secure storage; Check-in and the duress erase extended to
   messaging (destroying those keys erases every conversation at once).
5. **Attachments**: sealed with a random key, uploaded as padded objects, key
   sent in a `file-key` message.
6. **HQC** as a third KEM, once standardised.
7. **Multi-device**, cover traffic, delivery receipts, rotating the mailbox
   and wire keys with the root key, Elligator-encoded request keys, one size
   class for invites and requests.
8. **Independent review** of the handshake and ratchet, and a machine-checked
   model (Tamarin or ProVerif), as the audit recommends for the rest of HumID.

## Try it

```bash
node --test tests/msg.test.js                    # 46 tests: meeting, ratchet, stamps, delete, relay, rollback, fuzz
MSG_FUZZ_CASES=3000 node --test tests/msg.test.js
npm run test:timing                              # timing check of the current backend
```
