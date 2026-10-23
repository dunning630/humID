# Person to person (HumID 4.0, provisional)

> **Status:** 4.0 track. Built and tested: the protocol and formats (`packages/msg`,
> `tests/msg.test.js`, `tests/msg-live.test.js`), the human-to-human rule below, the relay
> service (`services/relay`), the gateway's stamp and relay routes, and the app's Messages tab
> (`apps/mobile/src/core/messaging.js`, `screens/messages`), end to end
> (`tests/e2e/messaging.test.js`, `tests/browser/messages.mjs`). Like the rest of HumID, it
> needs an independent cryptographic review before real conversations go through it.

Two HumID holders approve each other and talk directly. Each knows the other
only by an ID. Every message is end-to-end encrypted with post-quantum keys,
and carries proof that a live human sent it, without saying which human.

## The human-to-human rule

Nobody interacts on HumID without a live check. The rule lives in the protocol
(`packages/msg/src/live.js`, the `requireLive` option), so an app can't skip it by accident,
and the app turns it on for every conversation.

| Step | What it takes | What happens without it |
|---|---|---|
| Make an invite | the inviter's live check (it releases the account seed the persona is made from) | no invite |
| Ask to connect | a live check; the request carries a live stamp | `readRequest` refuses it (`not_live`): never shown |
| See who's asking | the inviter's live check (the request opens only with the invite's persona keys) | it stays sealed |
| Approve | a live check; the "accept" carries a live stamp | the requester's phone discards it and stays unconnected |
| Every message (text, media, delete, timer, end, "I'm here") | a live check; a stamp over its exact bytes | discarded unread; nothing it says is applied; its key is still used up |
| Read | the reader's own live check within the freshness window | the app doesn't open what arrived: it stays ciphertext on the phone, counted. (While the phone is unlocked, the keys that open it are in memory, so this is the app's rule, not a cryptographic lock: malware on an unlocked phone could read it.) |

**Only a proven phone gets stamps.** The gateway signs stamps only for a step-up made with a
hardware liveness key (a phone whose secure chip proves the face or fingerprint check), whatever
the server's device policy lets sign in. A desktop admitted under `HUMID_DEVICE_POLICY=biometric`,
or anything under `demo`, is refused (`stamp_needs_proven_phone`), so a script with a desktop
account can't mint stamps. Such a device can read what's already on it; the app says it can't
send and hides inviting, asking and sending. (The development server alone lets demo devices
stamp, so the flow can be tried in a browser; no deployed server can turn that on.)

One action is one check: deleting a whole conversation for both sends a delete and an end,
and both are stamped in the same check (`stamper.many`; the gateway signs 1 or 2 blinded
values per step-up, and its signature covers exactly those values). A delete names at most 500
messages, so with more than 500 of yours to recall it takes more stamps than one check gives:
the app says so ("2 live checks, one after the other") and does it in steps, each its own check.

**One stamp, one message, once.** A stamp commits to the conversation, the sender's persona,
the message id, kind and body, and also to when it was sent, its disappearing time and (for a
timer change) the change's time. A receiver counts a stamp only if its message is dated no
later than a couple of minutes after it came off the relay and no earlier than the relay could
still be holding it (15 days), and only once: the ids of stamps already seen are kept, sealed
with the conversation, for that long. So nobody can keep one old check "live" by re-sending it,
or replay an old timer change. Freshness counts from when the message came off the relay, not
when the phone got round to opening it.

**Stamps can't be bought ahead (MSG-01).** The issuer signs blind, so it never sees the time a
stamp's message carries. Instead it uses a new stamp key every hour and signs only with the key
of the hour it's in (give or take 2 minutes). Each key is published with its hour, and a phone
counts a stamp only if its message, request or receipt is dated inside that hour. So someone who
passes a burst of checks now can date their stamps no later than the end of the hour whose
key signed them. Because the issuer starts using the next hour's key 2 minutes early, a burst
just before the hour turns can be dated to the end of the *next* hour: a modified app can make
a holder look "here" for at most about 64 minutes after their last check, plus one freshness
window (5 minutes), not for as long as they like. The issuer publishes this hour's
key and the next one (so phones switch on time), and the public halves of retired keys for as
long as their stamps can still arrive; a retired key's private half is erased when its hour ends.

**Key changes don't drop messages (MSG-07).** The next hour's key is published an hour before
it's used, and phones fetch keys before their list runs out, at least daily, and whenever the
server answers `key_changed`. A message stamped under a key the phone hasn't fetched yet isn't
opened (and its ratchet key isn't used up): the phone fetches the keys and opens it then. Only a
key that's still unknown after a fresh fetch, one the server never published, gets the message
discarded as not live.

**Here, away, and both here.** A conversation is validated human to human ("Both here")
only while, within one freshness window (5 minutes):

1. this phone has verified a live stamp from the contact (their latest message, acceptance,
   request, or an empty "I'm here"), and
2. this phone's own holder has passed a live check.

Either lapsing ends it: the app shows the contact as "away", and when the holder's own window
ends the conversation locks itself on the phone until the next check. The contact's time is
the moment their message says it was sent, never later than it arrived, so a fast clock can't
stretch it. "I'm here" is a stamped receipt with no content, sent when someone opens a
conversation with a live check (per contact, on by default), so reading counts as being here,
not only writing.

What it proves, exactly: a face or fingerprint on a proven phone approved those bytes (the
stamp), and only the contact's persona could have sent them (the ratchet). It does not prove
who wrote the words, or that the person wasn't coerced, or that they're there right now (only
that they were within the last few minutes, and within the stamp key's hour). The app says
"confirmed by a live face or fingerprint check on a proven phone", never "verified human" or
"live human ✓".

## In the app

```
 Alice                                                   Bob
 Messages → Invite someone → [live check]
 QR on screen, "Waiting for Bob to scan it…"   ──scan──► I have their code → name, note → [live check]
                                                         "Waiting for Alice", safety code shown
 the same screen becomes "Bob is asking"  ◄── request (stamped) ──
 See who's asking → [live check]
 note, safety code: Same / Different
 Approve → [live check]  ───────────── accept (stamped) ──► opens the conversation by itself
 conversation: "You · here  Bob · here  Both here"         same, on his phone
 Send → [compact live check] per message
 away 5 min → "Locked" → Open with a live check (sends "I'm here" to that contact)
```

- Two people together never leave the screen they're on: the invite turns into the request,
  the asker's screen opens the conversation when approved (both poll every few seconds while
  one waits on the other).
- The safety code is on both phones while they connect, compared out loud. "Different", on
  either phone or later in Details, raises a warning that someone may be in between, is recorded
  on the contact and shown at the top of the conversation, and offers the safe way out
  (withdraw the request, or delete the conversation without telling anyone). On the approver's
  phone it also blocks approval. What's recorded is what one person can know: "you marked this
  the same (in person)", or "different".
- A failed approval (the check cancelled, the server busy, the stamp key just changed) leaves
  the invite and the request as they were, so approving again works.
- Anyone who saw an invite code can post junk to it. One "See who's asking" check opens every
  request waiting for that invite; anything not made with a live check, or not for this invite,
  is dropped without being shown, and if several real people asked, the app says so. At most 20
  requests are kept per invite.
- Remote invites: the code sits behind "Not together?", with a share option and a warning that
  anyone who sees it can use it once.
- Storage: the contact list is sealed under a key derived from the account seed inside the
  unlock check; each conversation under a new random key every save, kept wrapped under that
  key; ciphertext from the relay waits unread for a fresh check; anything a conversation posts
  waits in that conversation's own sealed save until the relay has it (an invite bundle waits
  in a record sealed under the account-derived key), so a dropped connection or a crash loses
  nothing. Locking forgets everything decrypted.
- The relay is reached from a separate session that never signs in. Stamps come from the
  signed-in session inside a live step-up, so the issuer learns that an account asked for a
  stamp, never for what.
- A duress unlock opens nothing real: Messages shows an ordinary empty inbox, nothing is
  fetched, decrypted or sent, and anything tried there answers like a busy server, as the
  vault's decoy does. What arrives meanwhile waits at the relay for the next real unlock.
  (Messages from an older app that carry the encrypted duress flag still raise the quiet
  warning for a contact who turned on "Tell me if they may be under duress".)
- What the server can still put together: the address that asks for a stamp and the address
  that posts to a mailbox. Posts go out a few seconds later, each from a relay session of its
  own; each conversation is polled from its own session, in a random order, but only a VPN or
  Tor hides the address. See "Who can know what" for the rest.
- A phone that was closed for days fetches every day it missed (up to the relay's 14), so
  nothing sent meanwhile is lost; a message that still never arrives (a later one did) is
  shown in the thread as missing.
- The Messages tab appears only when the server runs a relay. Servers keep messaging off
  until the operator turns it on: `HUMID_RELAY_URL=http://relay:8087` in `deploy/.env` with
  Docker, `humid set HUMID_MESSAGING=on` on HumID Server for Windows (3.2.0 and later).

### How the flow was arrived at

Three rounds, each reviewed by someone who hadn't seen it built, each checked in a real
browser with two phones (`tests/browser/messages.mjs`, screenshots with `SHOTS=dir`):

| Round | Found | Changed |
|---|---|---|
| v1 → v2 | The mutual state didn't read as mutual right after connecting; "live" unexplained; an empty inbox asked for a check; the composer floated; every bubble said "live" (redundant under strict mode); people standing together had to go back to the list between steps; two lines claimed more than the cryptography proves | presence pips with an explanation; the contact's request or acceptance counts as their check; together flow on one screen per person; safety code on both phones; copy limited to what's proven |
| v2 → v3 | The invite screen didn't update when the request arrived (a bug); a one-tap "it matches" was recorded as "compared in person"; "live" read as alarming to a non-technical user; the reader was invisible to the contact | Same / Different with how it was compared; "here / away"; "I'm here" receipts; locked placeholders; compact check card for sending |
| v3 | each message is still one check | the check is a card over the composer, gone in a moment; on a phone it's the system's face or fingerprint prompt, so a glance or a touch. The rule stays |
| v4 (security review) | a stamp wasn't tied to its time or to one use (one old check could keep a bot "here"); a duress unlock opened the real conversations; the relay could be filled by a few networks; one check could stamp up to four unrelated messages; some metadata sat unsealed; ratchet keys stayed in memory after lock | stamps cover time and count once; a duress unlock opens nothing real; per-network daily quota per IPv6 /48 in a fixed-size sketch; at most two stamps per check; waiting records sealed with opaque ids; conversations wiped from memory on lock; posts jittered |

## The promise, stated exactly

| What people want | What HumID 4.0 does | The honest limit |
|---|---|---|
| "They only know my ID" | Each contact sees a different **persona ID** (`HC-XXXX-XXXX-XXXX-XXXX-XXXX`), made just for them. Two contacts comparing notes can't tell they know the same person. No name, number or email exists anywhere. | Whatever you choose to tell them in a message. |
| "Zero chance of interception" | Interception is always *possible*: anyone on the network, or the relay itself, can copy the bytes. What they get is padded ciphertext, in one of a few fixed sizes, posted to random-looking mailbox ids that change every day. | The relay sees when a phone deposits or fetches and from which address (use a VPN or Tor to hide that), and can tie a conversation's mailboxes together from one day to the next (see "Who can know what"). |
| "Not crackable" | Every key needs **both** ML-KEM-1024 and X25519 broken, and handshakes need **both** ML-DSA-87 and SLH-DSA (hash-based) forged. Keys change every time the conversation changes direction, so copying ciphertext now and decrypting it with a quantum computer later gains nothing. | "Not crackable" means no known attack, classical or quantum, comes close. No one can promise more than that for any system; the weak point in practice is a compromised phone, not the maths. |
| "I can delete it" | Delete one message or a whole conversation, for you or for both of you; turn on disappearing messages; unsend a message the contact hasn't fetched yet. Deletes destroy keys, so deleted data can't be read back from the phone's storage or from a copy of the ciphertext. | Nothing can reach into the contact's phone against their will: a screenshot, a modified app or a second camera keeps what it saw. "For both" deletes *your* messages from *their* phone; what they sent stays theirs. |
| "Validated as a live human" | A **live stamp** in a message proves a live face or fingerprint check on a proven phone approved those exact bytes. The server signs it blind, so it can't connect the stamp to anyone. | It proves *a* human approved the message, not *which* one; the ratchet proves it came from your contact. A person could still approve messages written by someone else (see "Limits"). |
| "Prove it's really me, not a deepfake" | Anyone you've connected with can ask your phone **"Is this really you?"**; you answer with a live check and read a spoken code on the call. Your media can carry a live stamp, and your real voice and photo sit sealed in an **evidence locker** HumID can't open. | Nothing ever compares a voice or a face. It works with people you connected with beforehand. |

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
   asked with a live check  ·  note: 'from the workshop'
   safety code QM4T-…"
 live check → acceptRequest
 encrypt("accept") ─────────────►  conversation box (rotates daily)  ───────────────────────► session opens: connected
 ◄──────────────────────────────── messages both ways, each optionally stamped ─────────────►
```

- **The invite code is the only secret that moves outside HumID.** It carries
  128 random bits (what opens the invite) and an 80-bit pin of the inviter's
  persona (what the invite must contain), plus two check characters: `HI-` and
  eleven groups, best shown as a QR code. It lasts 24 hours by default (7 days at most) and admits one
  person, always: every contact must get a persona of their own, and an invite
  that admitted several would give them all the same one (precert PC-26). Show
  it in person when you can: the audit's warning about cloned voices applies to
  anything read over the phone.
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
phone:  commitment = SHA3-256("stamp message" ‖ lp(conversation id, sender persona, nonce, kind, body, at|x|ta))
        (a request: SHA3-256("stamp request" ‖ lp(handshake, sender persona, at)))
        blinded    = Blind(commitment) for the key of the hour that holds `at`
                                                       RFC 9474, RSABSSA-SHA384-PSS-Randomized
server: inside a live step-up (secure-chip-signed face or fingerprint check on a proven phone),
        1 or 2 stamps per check, only with this hour's key:
        blind signature = BlindSign(stamp key of this hour, blinded)
phone:  stamp = Finalize(...)  → put INSIDE the encrypted message
contact: verify(stamp, commitment recomputed from what arrived), and `at` inside the key's hour (± 2 min)
```

- **Unlinkable, forever.** Blindness is information-theoretic: the server can't
  connect a stamp to the check that bought it, whatever it computes, quantum or
  not. It never sees the message, the conversation or the recipient.
- **Bound to one message.** A stamp copied onto another message fails.
- **Bound to its hour.** Each stamp key signs only during its hour, and a stamp
  counts only for a time inside that hour (above). `HUMID_STAMP_EPOCH_MINUTES`
  (default 60, 5 to 360) sets the hour's length; shorter bounds stockpiling more
  tightly and costs more key generation.
- **Separate key.** Stamp keys must never be the access-pass key: a blind
  signer signs whatever it's handed, so a shared key would let a "stamp" request
  carry a blinded access pass. The app refuses a stamp key that appears among
  the pass keys, and stops counting a key's stamps after its `acceptUntil` day
  (15 days after its hour by default, `HUMID_STAMP_ACCEPT_DAYS`).
- **Stamps are RSA, with no post-quantum fallback.** Blind RSA (RFC 9474) is the
  only standard blind signature there is today, so stamps rest on RSA, as passes
  do. A future quantum computer could forge stamps; it couldn't unmask anyone.
  For a message that's harmless in hindsight, because a stamp only matters when
  it's received. For something published to last, a stamped media credential
  or an evidence release, it isn't: once RSA falls, anyone can forge the "live
  human" part. The persona's signatures on them (ML-DSA-87 and SLH-DSA) still
  hold, so who signed stays provable; that a live check was made does not.
- **Stamped media and releases keep verifying.** A message's stamp stops counting
  15 days after its key retires. A credential or release is instead checked
  against the issuer's archive of retired stamp public keys (`/msg/keys?all=1`),
  so a genuine one made today still verifies in four months; the key's epoch
  says when the live check happened.

### A new signal about human activity, with nothing about any human

The stamp issuer counts stamps and checks per day, and the server publishes the
totals (`/msg/stats`): how many messages, requests, approvals, "I'm here"
receipts and deletes on this server were approved with a live check on a proven
phone. Since only proven phones get stamps, a bot farm can't inflate it without
real people passing real checks (a person paid to approve a bot's messages
still can, at human speed), and it says nothing about who talked to whom. On a
small server, exact daily numbers would show individual activity, so a day is
published only once it has at least 1,000 checks (`HUMID_MSG_STATS_MIN`), and
both numbers are rounded down to a hundred. (What the issuer itself learns, see
the table below: how many stamps each account asked for.)

## Deleting

Every kind of delete is in one object the app uses, `Conversation`
(`packages/msg/src/conversation.js`).

| You choose | What happens on your phone | What happens on the contact's phone | At the relay |
|---|---|---|---|
| **Delete for me** | The message is overwritten and left out of the next save. | Nothing. | Nothing. |
| **Delete for both** (your own messages) | As above. | Their app erases it. If it hasn't arrived yet, their phone destroys the one key that would have opened it, so it can **never** be opened, even from a copy someone kept. | If the contact hasn't fetched it yet, it's **unsent**: removed, and you're told it was never delivered. |
| **Disappearing messages** (either of you sets it, 30 s to a year, or off) | Each message is deleted when its time is up, counted from when it was sent. If it was never delivered, you can still unsend it or delete it for both for 14 days. | Deleted when its time is up, counted from when it arrived. Your own timer applies to what you receive too (the shorter wins), so a contact can't send you something that stays forever. | Messages are kept at most 14 days anyway. |
| **Delete conversation, for me** | Every message and every key for this contact is overwritten; the contact's ID for you is forgotten for good. | Nothing; they aren't told. | — |
| **Delete conversation, for both** | As above. | Their app erases every message you sent, then the conversation ends (the deletes count even if the "end" arrives first). | Anything not yet fetched is unsent, even if the conversation had already ended. |
| **Cancel an invite / withdraw a request** | The invite's one-time keys are destroyed; requests to it can never be read. | — | The invite or request is taken down, so no one else can fetch it with the code. |

### Why a deleted message really is gone

- **Keys, not files.** Erasing a file on a phone's flash storage doesn't
  reliably erase its bytes: the storage chip moves data around and old copies
  survive. So a conversation (its ratchet and its history, in one blob) is
  sealed under a **new random key every time it's saved**, and the app keeps
  only the newest key, in the phone's secure storage (Keychain / Keystore),
  overwriting the old one. A deleted message, and the ratchet's key for a
  message deleted before it arrived, are absent from the new save; every older
  save that still held them is sealed under a key that no longer exists. Tested:
  the old save doesn't open with the new key. One blob also means a crash can't
  save half a change.
- **Saved before it's sent, and kept until it's posted.** With `persist`, every
  change is saved before anything is handed back to post; if the save fails,
  nothing goes out. What's to be posted is kept inside that same save (the
  conversation's outbox) until the relay has it, so a crash between saving and
  posting loses nothing and leaves no gap in the ratchet. Tested.
- **Nothing is erased until the delete is ready.** "Delete conversation for
  both" stamps and encrypts every delete and the end first, and only then erases.
  If the live check is cancelled, the server is busy or a save fails, the
  conversation is still there, unchanged, and you can try again. The unsend
  tokens always come back. Tested (precert PC-28).
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
  further use. Operations run one at a time, so a send or receive already under
  way finishes first and is forgotten with the rest. Tested.
- **Timers agree.** Both phones apply one rule to every timer change (the
  later change wins; on a tie, the shorter timer), so they can't end up with
  different settings. Tested.
- **No flooding.** Remembered ids of deleted messages are capped (5,000, oldest
  first), so a contact sending endless deletes can't fill your phone. Tested.

### What delete can't do

- **It can't force another phone.** "Delete for both" asks the contact's
  HumID app to erase, and an unmodified app always does. A screenshot, a photo
  of the screen, or a modified app keeps what it already showed. That's true of
  every messaging system; HumID says so instead of implying otherwise.
- **You delete what you sent.** A contact can never delete your messages from
  your phone, and you can't delete theirs from theirs: each person controls
  their own words on the other's phone, and their own copy of everything.
  Tested: a delete naming someone else's message is refused.
- **After a conversation has ended**, a new delete for both can't be sent; the
  app says so and keeps your copy so you can delete it for yourself. Unsend at
  the relay still works for anything not yet fetched.
- **Wiping memory in JavaScript** is best effort: key material is overwritten,
  but text shown on screen is a JavaScript string, which can't be. The storage
  promise (keys, not files) doesn't depend on this.

## Proving it's you

> Built on branch `v4/prove-its-me` (`challenge.js`, `media.js`,
> `evidence.js` in `packages/msg`; `tests/prove.test.js`, 17 tests).

Someone gets a call that sounds exactly like you, asking for money. A stored
copy of your voice or face can't settle it: a clone is *built* to match what
you sound and look like, so comparing the call with a sample proves nothing,
and doing the comparison would mean HumID handling biometrics, which it never
does. What a faker can't do is pass a live check on **your** phone. So HumID
doesn't try to recognise the fake. It lets the real you answer, live.

| Piece | What it does | What it proves |
|---|---|---|
| **"Is this really you?"** | The person on the call asks your phone, over the conversation they pinned when you connected. You answer yes or no with a live check. On a yes, both phones show the same spoken code; you read it aloud on the call. | The answer came from your device (the ratchet), a live human approved this answer to this question (the stamp), and the voice on the call knows a code that exists only on your phone after that check. |
| **Stamped media** | A voice note, photo or clip sent in a conversation carries a live stamp over its exact bytes. For media you publish outside HumID, a sidecar credential is signed by your **public persona** (ML-DSA-87 + SLH-DSA) and stamped. | These exact bytes were approved by a live human on a proven phone; with the credential, by the holder of the persona ID you publish. Anything that claims to be you without a stamp is unverified. |
| **Evidence locker** | Your real voice and photo, sealed on the device under a key from your account seed. Opened only after a live check. Released as a packet with a signed, stamped release statement naming who it went to, why, and until when. | "This is the real me, recorded on this date", for a platform's impersonation team, a lawyer or the police. A copy that travels further carries its own paper trail. |

### "Is this really you?"

```
 verifier (got the suspicious call)              claimant (the real you, wherever you are)
 ────────                                        ────────
 sendChallenge("call", note) ── "challenge" ───► readChallenge
                                                   "Are you on a voice call with me right now?"
                                                   live check → replyToChallenge(yes | no)
 checkReply ◄──── "challenge-reply" + live stamp ─ shows the spoken code (yes only): 7QX4-M2KD
   confirmed + 7QX4-M2KD   → "ask them to read their code"
   denied                  → "they say it isn't them: hang up"
   unverified / expired    → never shown as confirmed
```

- **One question, one answer.** A challenge has a random 128-bit id and lasts
  5 minutes by default (30 at most). The reply carries the id and a fresh
  nonce; its live stamp commits to exactly those bytes, so it can't confirm a
  different question. A second answer to the same question is flagged
  `already_answered`, and the first stands.
- **The spoken code** is 8 characters (40 bits) from
  `SHA3-256("spoken code" ‖ lp(conversation id, challenge id, reply nonce))`.
  It appears on your phone only after you pass the check, so even if you said
  "yes" by mistake, a faker on the line can't read it. The caller reads; the
  person who asked listens and compares. Never the other way round.
- **Verdicts are conservative.** `confirmed` needs a "yes", a valid live
  stamp, an answer in time by the verifier's own clock, and no duress flag. A
  "no" is `denied` whether or not it is stamped, because the safe action is the
  same. A "yes" sent from a duress unlock comes back `unverified` with
  `duress: true`: a coerced confirmation never turns green.
- **The relay can't tell.** A challenge, a reply and a media message pad to the
  same size class as a text. Tested.

### Stamped media

- **In a conversation**: kind `media`, body `lp(capture details, bytes)`, up to
  1.8 MB (larger files wait for attachments). The message's stamp covers the
  whole body.
- **Portable credential** (`clip.mp4.humid.json`): the media's SHA3-256 hash,
  size, kind, type and capture time, signed by your public persona with
  ML-DSA-87 **and** SLH-DSA-SHA2-256f over the statement plus its live stamp.
  `verifyMediaCredential` passes only if the bytes match, both signatures
  verify, the stamp is valid, and (when given) the signer is the persona ID
  you publish. Changing the capture time, the kind, the stamp or the signer
  fails. Tested.
- **Use a dedicated public persona.** A credential is meant to be attributable.
  Signing with one of your contact personas would let anyone link that contact
  to your public self.

### Evidence locker

```
locker key = HKDF-SHA3-256(account seed, "HUMID-MSG-v1 evidence locker")      on the device, after a live check
item       = AES-256-GCM(item key, lp(details ‖ media credential, bytes), aad = item id)
record     = { id, AES-256-GCM(locker key, item key, aad = item id), item }   kind, type, note, hash: all inside
release    = dual-signed + stamped: hash, recipient, purpose, released, expires, signer
```

- **HumID can't open it.** The key comes from the account seed, which only
  your devices hold. A stored record shows its id and rough size and nothing
  else: not the bytes, not their hash, not the kind or the note. Records can't
  be mixed up (each item's key and content are bound to its id). Tested.
- **Never a matcher.** The locker hashes and encrypts; it never extracts
  features from a recording or compares it with anything. A test fails the
  build if the API grows anything that looks like a matcher or a biometric
  export.
- **Releases expire as statements, not as copies.** A recipient's copy exists
  once handed over; what expires is your signed authorisation, so a copy shown
  after its date, or to someone else, is visibly out of bounds.

### Limits of proving it's you

- **Capture and release times are what you state**, signed but not
  independently witnessed. The stamp's key does pin the hour the live check
  was made. Anchoring statements to an independent timestamp (RFC 3161, or a
  transparency log) is listed below.
- **The "live" part of a credential is RSA** and can be forged once quantum
  computers break RSA (see "Live stamps"); the persona's signatures can't.
- **The challenge needs a connection made beforehand.** It works between people
  who connected in HumID before the suspicious call. Connect with the people who
  would act on a call from you (family, your finance contact) now.
- **A careless "yes" is caught by the code, not by the stamp.** The stamp
  proves *you* answered; the code proves the voice on the call is you. Both
  have to line up.
- **Illinois BIPA and similar laws.** Raw recordings and photos sealed so HumID
  can't read them, with no feature extraction, are designed to stay outside
  "biometric identifier" handling. Counsel should confirm before launch.

## Who can know what

| Party | Sees | Never sees |
|---|---|---|
| **Your contact** | your persona ID for them, your messages, the safety code, which messages were stamped live | your account, your other personas, your other contacts |
| **The relay** | random-looking box ids (a new one each day per direction), objects of fixed sizes, deposit and fetch times, the address that connected; from the size class, roughly what kind of object it is (an invite is 64 KiB, a request 128 KiB, a message usually 8 KiB). What it can still put together, below. | who you are, any persona key or ID, any message content |
| **The stamp issuer (vault server)** | that an account passed a live check and asked for a stamp, and how many per day | the message, the conversation, the recipient, the finished stamp |
| **Someone on the network** | that a phone talked to the relay, when, how much | anything inside |
| **A thief with your unlocked phone** | your conversations, as they are on screen | anything already erased by the ratchet |

**What the relay can still put together** (security review MSG-02). Its mailbox ids are
unlinkable *by themselves*, but how phones use them leaks some links, and this is what's left
after the mitigations:

- **A conversation, day to day.** Each poll asks for yesterday's and today's mailbox, so the
  polls on two consecutive days share one id, and a relay that records polls can chain one
  conversation's mailboxes across days. (Polls two days apart share nothing; tomorrow's box is
  asked for only in the two minutes before midnight UTC.)
- **Both ends of a conversation, by timing and address.** A deposit to a box and the later
  fetch of that box are, by design, the same id; the relay can't tell who deposited (each
  deposit comes from a relay session of its own that never signs in) but it sees the address
  of both sides. Without a VPN or Tor on both phones, that address pairs the two.
- **Your personas, by address and timing.** Each conversation is polled from its own relay
  session, in a random order with pauses, so no request names two of your personas. They still
  come from one address within a few seconds; only a VPN or Tor, with polls spread out, hides
  that.
- **After time away**, a phone fetches every day it missed, up to 14, in one go for that
  conversation: the relay sees that this conversation went unpolled for that long.

Not built yet, and what would close these: mailbox buckets (the relay stores by a short prefix
and the phone filters, so many conversations share each id) or cover polls.

## Applying the security audit

The 2026 audit ("HumID Security Audit: Tests, Coverage and Beyond-Standard
Threats") lists threats and open findings across HumID. Everything below is
built into 4.0 and tested unless marked otherwise. An independent review of the
first cut found no critical or high issues; its ten medium and low findings are
fixed or stated as limits here.

| Audit item | What 4.0 does |
|---|---|
| Timing leaks in the PQ code (T3–T4) | All primitives sit behind one swappable backend (`backend.js`). The app replaces the JS maths with the platform's own (iOS 26 CryptoKit ML-KEM-1024 / ML-DSA-87) via `useBackend`, which first runs `checkBackend` against the reference (exactly what it checks is listed under [Replacing the crypto backend](#replacing-the-crypto-backend)). The relay runs no cryptography, so there's no server-side timing oracle at all. `npm run test:timing` (Welch's t-test, valid vs invalid ML-KEM ciphertexts, X25519 scalars) runs in CI, informational on shared runners. |
| A lattice break (T5) | Every key needs X25519 as well as ML-KEM; every handshake needs SLH-DSA (hash-based) as well as ML-DSA. **Next:** HQC as a third KEM in the ratchet step once its standard is final (2027): one more secret in the step's input, under a new message-format version. |
| Signatures that must outlive their algorithm (T5) | Handshakes are dual-signed ML-DSA-87 + SLH-DSA-SHA2-256f, both required. Messages deliberately aren't signed (deniability), so nothing long-lived depends on lattice signatures. |
| Kernel spyware (T4) | Keys are erased as soon as used (forward secrecy), the ratchet heals after one exchange, and conversation state is sealed at rest. **Next:** keep persona signing keys in the Secure Enclave where the platform supports ML-DSA. |
| Forged attestation (T2–T4) | Stamps are issued only inside a step-up that already enforces the device policy. **Depends on** SEC-S-04 (fetch the Android revocation list) for stamps to mean what they say. |
| Fake faces (T2) | Stamps come only from the phone's hardware-gated check; there is no camera path and must never be one. |
| Coercion (T4) | Encrypted duress flag; constant-size wire objects so a duress session looks like any other; nothing on the relay to compel. |
| Rogue operator (T3) | The relay can't read, forge or substitute anything; safety codes catch key substitution; dropped messages show up as gaps. |
| AI-scale social engineering (T2) | Invites expire in 24 h and admit one person; requests carry a live stamp; approval takes a live check; the safety code is the defence against a cloned voice. |
| SEC-S-13 (reveals whether an account exists) | The relay answers an empty box and a never-used box identically. Tested. |
| SEC-S-02, -03, -08 (DoS) | Every relay dimension is capped (object size and count per box, bytes per box and in total, expiry), and rate limits key IPv6 by its /64. Tested. |
| H-1 (signer not pinned) | A contact's persona keys are pinned at the handshake; every later message is authenticated by keys only that persona could hold. |
| SEC-A-04 (swapped or replayed index) | Sealed conversation state binds its conversation id and a version number; an older copy is refused, because rolling back a ratchet would re-open used keys. Tested. |
| A-10 (40-bit match code) | Safety codes are 100 bits; invite codes pin the inviter's persona with 80 bits. |
| Malformed peer keys | Every ML-KEM key that arrives is checked (FIPS 203 modulus check) before use, so a bad one is refused at the door instead of breaking the conversation later. Tested. |
| "Unlinkability checked by string search only" | Tested by the protocol: personas share no key material, box ids differ by direction and day, every relay object is a fixed size class with no persona keys or IDs inside, the issuer sees only blinded values, the same message blinds differently each time. |
| Relay rate-limit table | Fixed-size count-min sketches, for calls per minute and bytes per day: they never fill up, so a flood of addresses can neither reset a busy client's limit nor lock new networks out (an earlier bounded table refused new addresses when full). Tested. |
| Relay fill-up (PC-27, MSG-05) | Daily byte quotas per address (IPv6 /64), per site (IPv6 /48) and per block (IPv4 /24, IPv6 /32, `HUMID_RELAY_MAX_BLOCK_BYTES_DAY`); past 75% full (`HUMID_RELAY_FAIR_ABOVE`), a block that already holds more than its fair share of today's deposits is refused, not everyone. A determined sender with addresses in many blocks can still fill it; relay postage (a blind token per deposit from the same live check) is the durable fix and isn't built yet. Tested. |
| "Fuzzing: one fixed seed, any error type accepted" | `tests/msg.test.js` fuzzes messages, requests, invites, stored state and codes with a fresh seed each run (printed on failure, rerun with `MSG_FUZZ_SEED`), and accepts only `MsgError` with a code. |

### Replacing the crypto backend

`useBackend(b)` installs a replacement only if `checkBackend(b)` passes. Before
audit finding PC-12 it compared key generation and one ML-DSA rejection, so a
replacement whose SLH-DSA verify always said yes, whose X25519 returned a
constant, or whose ML-DSA verify ignored the public key got in. It now checks,
against the reference (noble), on fresh random seeds and fixed test messages:

- **X25519.** The RFC 7748 §6.1 test vector (both public keys and the shared
  secret, both directions). On fresh keys: the same public keys; a shared
  secret equal to the reference's and the same from both sides. A public key
  with the top bit set, and nine low-order or non-canonical points (0, 1,
  p − 1, the two order-8 points, p, p + 1, and 0 and 1 with the top bit set),
  must be treated exactly as the reference treats them: the reference refuses
  all nine, so the candidate must refuse them too, not return zeros.
- **ML-KEM-1024.** The same public key from the same seed. The candidate's
  ciphertext decapsulates on the reference, and the reference's on the
  candidate, each with its own secret key and with the other side's (secret
  keys are stored in conversation state, so they must be interchangeable).
  Implicit rejection: a ciphertext with one bit flipped (first byte, last byte)
  must give the candidate the same value the reference gives, J(z ‖ c), never
  the real secret and never an error.
- **ML-DSA-87 and SLH-DSA-SHA2-256f**, the same procedure. The same public key
  from the same seed. The reference's signature verifies on the candidate; the
  candidate's signature verifies on the reference and on the candidate. For
  both signatures the candidate's verify must reject (return false or throw): a
  bit flipped at the first, middle and last byte of the signature, a bit
  flipped in the message, two other valid public keys (one fresh, one fixed
  whose encoding starts with a zero byte), and the signature truncated by one
  byte.

The first difference throws `MsgError` with a code naming the primitive:
`backend_mismatch_x25519`, `backend_mismatch_ml_kem`, `backend_mismatch_ml_dsa`
or `backend_mismatch_slh_dsa` (an error the candidate throws becomes the same
code). Each signature scheme signs once per side, so the check takes about 1.5 s,
mostly the two SLH-DSA signatures. It is an interoperability and
negative-case check, not a proof of correctness: it can't see timing, or a
fault that appears only on inputs it doesn't try.

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
  random. Cover traffic is not built. The relay and the stamp issuer write no
  log line per request (the relay keeps arrival to the minute, the issuer only
  days), so their logs can't be lined up to pair a stamp with a deposit; the
  gateway logs only that an encrypted call happened, not what it was.
- **"Locked" is the app's rule, not a cryptographic lock.** While the phone is
  unlocked, the keys that open waiting messages are in memory. The app shows
  nothing without a fresh live check, but malware on an unlocked phone, or a
  modified app, could read what's waiting. Locking the phone wipes them.
- **"Both here" is "within the last few minutes".** A modified app can buy
  stamps ahead, but only within the current stamp key's hour, so a holder can
  look "here" for at most the rest of that hour after their last real check.
- **Skipped message keys** (for messages a relay withholds) are kept until the
  message arrives or for 14 days, the relay's retention, then erased.
- **One messaging device per account, for now.** The ratchet state lives on one
  device; multi-device sessions come later.
- **The endpoints.** Encryption ends on the two phones. A compromised phone, a
  screenshot or a contact who forwards your words is outside what any protocol
  can stop.

## What is not built yet

1. **Native secure storage** for the newest conversation key and the rollback counter
   (Keychain / Keystore). Today they're kept wrapped under the account-derived key in the
   app's own storage, which protects them at rest but doesn't give flash-level erasure.
2. **Check-in and the duress erase extended to messaging** (destroying the storage key erases
   every conversation at once).
3. **Push notifications** for new messages (the app polls while open).
4. **Attachments**: sealed with a random key, uploaded as padded objects, key sent in a
   `file-key` message. Relay objects are limited to what fits an anonymous call (512 KiB).
5. **HQC** as a third KEM, once standardised.
6. **Multi-device**, cover traffic, rotating the mailbox and wire keys with the root key,
   Elligator-encoded request keys, one size class for invites and requests.
7. **Proving it's you, in the app**: the "Is this really you?" button, the spoken-code screen,
   the locker capture screen.
8. **Independent review** of the handshake, the ratchet and the human-to-human rule, and a
   machine-checked model (Tamarin or ProVerif), as the audit recommends for the rest of HumID.

## Try it

```bash
node --test tests/msg.test.js tests/msg-live.test.js   # protocol, and the human-to-human rule
node --test tests/e2e/messaging.test.js                # two holders through the real services
node tests/browser/messages.mjs                        # two phones in a browser (needs playwright)
node --test tests/prove.test.js                        # challenge verdicts, spoken code, stamped media, locker
npm run test:timing                                    # timing check of the current backend
npm run dev                                            # open two browser windows and try it
```
