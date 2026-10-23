# Continuity: proving it's the same person

Status: POC. Code: `packages/recovery` (parts, tiers), `packages/anchor` (ID
chips), `packages/audit` (public log), `services/recovery`, `services/ledger`,
`services/gateway`, `services/identity`, `apps/mobile`. Tests:
`tests/anchor.test.js`, `tests/tlog.test.js`, `tests/e2e/continuity.test.js`.

HumID promises that a vault opens only for the living person who sealed it.
On one phone, the secure chip proves a live face or fingerprint match. The
hard part is everything else: a lost phone, a new phone, a switch from iPhone
to Android. Phones never share biometric templates, and HumID never stores
any, so a new phone starts as a stranger.

HumID's answer: it never claims biological sameness. It keeps a **chain of
independent evidence** linking the person who sealed the vault to the person
asking now, and no single party can break that chain, including HumID.

Each holder chooses at setup how far that chain may reach
([RECOVERY.md](RECOVERY.md#two-recovery-modes)):

- **Only my own devices (holder-only).** Layers 1 and 2 only. No recovery
  part exists anywhere, and the servers refuse to store or use one. The
  choice is signed by the account key, so a server can't switch it on.
  Lose every device and the vault is gone.
- **A safe way back in (hardened, recommended).** Layers 1 to 5: two
  different proofs, a wait set by the evidence, and a veto from any
  surviving device.

## Layer 1 · Device keys die when the enrolled biometrics change

Each phone's liveness key and seed-unlocking key are created so the operating
system destroys them if anyone adds a face or fingerprint
(`.biometryCurrentSet` on Apple, `setInvalidatedByBiometricEnrollment(true)` on
Android, Class 3 only). An attacker can't enrol their own finger and keep
access. At setup and when joining, the app asks the person to confirm that
only their own biometrics are enrolled; the answer is recorded with the device
in the ledger (`device.added` · `soleBiometric`).

## Layer 2 · Several devices

Any device that holds the account seed `A` can add another (code or **QR**,
see [RECOVERY.md](RECOVERY.md#1-another-device-you-still-have-instant)).
Setup nudges people to add a second device straight away, so most lost phones
never need recovery.

## Layer 3 · Two-proof recovery (hardened mode)

`A` is split so that any two different parts rebuild it (Shamir over GF(2⁸), degree 1).
4.0 adds a fourth part, held under a FIDO2 security key ([SECURITY-KEY.md](SECURITY-KEY.md)).
The coefficients come from `HKDF-SHA3-256(A, "HUMID-QUORUM-v1 coefficient epoch e")`,
so every device holding `A` makes the same parts for epoch `e` at any time, and
parts of one epoch made at different times always fit:

| Part | x | Protected by | Released when |
|---|---|---|---|
| **Witness** | 1 | split again among 2–5 witnesses (any majority), each piece sealed to that witness's account key | a majority approve, each with their own live biometric on their own phone |
| **Anchor** | 2 | sealed on the holder's phone under a key from one passport or ID chip's public authentication key (DG15), and wrapped again by the server. This ties it to one chip, but **the server can open it** (it sees DG15 whenever the chip is checked): see [The anchor and the operator](#the-anchor-and-the-operator) | that same chip is proven again, live: in person at a station, or on the phone (Active Authentication) |
| **Card** | 3 | the seal card (`HUMID-…` code), AES-256-GCM, like the v1 card | the card is presented |
| **Key** (4.0) | 4 | a security key's `hmac-secret`, which it gives out only with its PIN | the key signs this recovery's fresh challenge with its PIN verified ([SECURITY-KEY.md](SECURITY-KEY.md)) |

Any two different parts of the same epoch rebuild `A`; the new device checks
that `A` derives the expected account id before joining. One part reveals
nothing. The server can open the witness, card and key parts only with the
holder's help; the anchor part it can open itself.

No one can recover alone: not a witness, not a thief with the card. A hostile
server operator is one proof short if the holder linked a passport (the
operator holds the anchor part), two short if not. Usual combinations:

- lost everything, still has friends and a passport → witnesses + anchor
- no witnesses reachable → anchor + card
- no chip ID, or a chip that can't prove it's present → witnesses + card
- a security key on the keyring → key + witnesses, or key + card or chip (no people)

**Epochs.** Removing a witness or replacing a card only stops that piece
counting on the server: its bytes still fit with the others. **Make new
recovery pieces** (You → Recovery, one live check) signs a new epoch into the
account's recovery-mode statement. New parts then come from a new line, the
epoch is bound into the card and key encryption and the witness piece, the
server deletes every older piece and cancels recoveries under way, and parts
of different epochs never combine. So a lost card or a removed witness's
piece, wherever it is (including old server backups), opens nothing.

### The identity anchor (ICAO 9303)

Linking the anchor, all inside one step-up:

1. The phone asks for a fresh challenge (`POST /recovery/anchor/challenge`)
   and reads the chip live: DG1 (the MRZ), EF.SOD and DG15, and the chip signs
   the challenge (Active Authentication). Copied chip files can't answer, so
   nobody can link someone else's identity from a scan a hotel or a bank kept.
2. The phone seals the anchor part itself:
   `key = HKDF-SHA3-256(DG15, "HUMID-ANCHOR-PART-v2 key")`, AES-256-GCM, with
   the account id and epoch as associated data. This ties the part to the chip
   whose DG15 it is. DG15 is public data (anyone who reads the chip with its
   MRZ or CAN gets it, and step 3 sends it to the server), so it is not a
   secret against the server.
3. The server runs **passive authentication**: DG hashes match the SOD; the
   SOD's signed attributes bind its content; the Document Signer's signature
   verifies (RSA PKCS#1, RSA-PSS, ECDSA); the DS certificate chains to a
   trusted **CSCA** (`HUMID_CSCA_DIR`); the document hasn't expired. Then it
   checks the chip's answer against DG15.
4. It stores `anchor = HMAC-SHA3(server key, "HUMID-ANCHOR-CHIP-v2|" ‖ SHA3(DG15))`,
   a fingerprint of **that one chip's key**, and the sealed part, wrapped
   again under its own secret. It doesn't store DG15, the MRZ or the names,
   so its database and secret alone don't open the part. A server that records
   one link or recovery request does. One chip anchors one HumID.

So the anchor is one document, not one person. Another passport doesn't
match: not your old one, still in date after you renewed, and not a
namesake's with the same name and birth date. **A renewed passport is linked
again** (You → Recovery → ID chip), and the old one stops counting.

Chips with no Active Authentication key (no DG15; some older ID cards) can't
hold an anchor part: linking them is refused. HumID doesn't read Chip
Authentication (DG14) yet; until it does, the safer choice is to refuse
rather than keep a part that would be weaker than the others.

Anchors linked before this change (v1, sealed under the server's secret and
the identity fields) still work for recovery. The server can't upgrade them on
its own, because it never has DG15. The Recovery screen asks the holder to
read the chip again, and that replaces the v1 anchor with a chip-bound one.

Proving it again:

- **Remote (live chip):** passive authentication plus **Active
  Authentication**: the server issues an 8-byte nonce for this recovery, and
  the chip must sign it with the private key behind DG15 (RSA ISO/IEC 9796-2
  scheme 1, or ECDSA). A copy of the chip's files can't answer. The server
  finds the anchor by that chip's key fingerprint and, after the wait, hands
  the recovering phone the sealed part. The phone opens it with the key from
  the DG15 it read itself, kept under its own lock during the wait.
- **Station (in person):** an operator account listed in
  `HUMID_STATION_ACCOUNTS` scans the person's recovery code, reads their chip
  (passive authentication, and Active Authentication when the chip has it),
  and confirms three checks: the document is genuine, the face matches its
  photo, the person is present and asking themselves. The operator's own live
  biometric signs the result. The station's phone also seals the chip's DG15
  to the recovering phone's keys (checked against the recovery code), so that
  phone can open the part later (the vault server sees DG15 here too, as it
  does in every chip check). The station operator never learns whose HumID it
  is. Both ledgers record it.

### The anchor and the operator

**What holds today.** The anchor is bound to one chip and can't be linked
from copied data: an old passport, a namesake's passport or a scan someone
kept can't stand in for yours (CREDS-01/02).

**What doesn't.** The anchor part's key comes from DG15, the chip's public
Active Authentication key. The server has to see DG15 to check the chip, at
every link and every recovery. So **in hardened mode, whoever runs your vault
server holds your passport piece in a form they can open**, if they record
one request. With it and any **one** other stolen proof (a photo of your
recovery card, say) they could rebuild your account key offline, without the
wait, the veto or a ledger entry. A thief who taps your passport with its MRZ
gets DG15 too, but still needs the stored blob, which only the server has.

No passport offers a fix inside the chip. Chips have no static secret they'll
give a reader: Active Authentication signs a challenge, and Chip
Authentication is an ephemeral key exchange. Neither yields the same key twice.

**What to do now, if you don't want to trust the operator that far:** don't
link a passport. Use witnesses or a security key as your proofs (each of
their parts needs something the server never sees), or choose holder-only.
The app says this on the ID chip screen.

**The real fix, for the owner to decide: a 2-of-2 split wrap with an
independent cosigner.**

- *What.* The anchor part is wrapped under a key `K` that is split in two:
  one share for HumID's server, one for a cosigner. The cosigner is a
  separate small service run by **a different organisation** (a notary, a
  civil-society group, a second hosting company) in a different
  jurisdiction, with its own keys that HumID never holds.
- *Linking.* The phone seals the part under a fresh random `K`, picks a
  random `R`, and sends the server `K ⊕ R` and the cosigner `R` (sealed to
  the cosigner's published post-quantum key, so the server only relays
  ciphertext). Both shares are bound to the account id and the chip's
  fingerprint. Neither side alone ever holds `K`.
- *Recovering.* After the server's checks and the wait, the cosigner checks
  for itself that the request is real: the live chip answer to its own nonce,
  the wait elapsed, and no veto in the public log. Only then does it release
  `R`, sealed to the recovering device's keys. The cosigner logs every
  release in its own transparency log.
- *What it buys.* A hostile operator alone can no longer open the anchor
  part. It would need the cosigner to collude too, so for the operator the
  passport becomes a full second proof again.
- *What it costs.* A second organisation to find, contract and keep running;
  one more round trip in recovery; and a second availability dependency (if
  the cosigner is down, passport recovery waits). The cosigner sees that an
  account recovers, and when, but no names.
- *Effort.* About 3–4 days, plus the partner. Files: `services/recovery`, a
  new `services/cosigner`, `core/recovery.js`, `core/join.js`, and the
  deploy configuration.

The same cosigner could later back up Check-in's fuse keys (docs/CHECKIN.md),
which have the same "the operator holds it" limit.

### Reading the chip

The app reads the chip itself: on iPhone and Android with the phone's NFC,
on Windows and Mac with a USB contactless card reader (handy for a station
laptop). `@humid/emrtd` implements ICAO 9303 part 11 once, in the shared app
code; the native plugin `tauri-plugin-humid-nfc` (`humid-nfc@1`) only moves
APDUs (Core NFC `NFCTagReaderSession`, Android `IsoDep` reader mode, PC/SC).

1. **Access.** The person types the document number, date of birth and expiry
   from the photo page, or an ID card's 6-digit CAN. **PACE** is used when the
   chip offers it (EF.CardAccess): ECDH Generic Mapping with AES-128/192/256
   or 3DES, on NIST P-256/384/521 or Brainpool P-256/384/512. Otherwise
   **BAC**. The details live only in that one read; nothing is stored.
2. **Files.** Over secure messaging: EF.COM, DG1, DG15 (if the chip has an
   Active Authentication key) and EF.SOD. The photo (DG2) is never read.
3. **Live proof.** When recovering, the app first asks the server for a nonce,
   and the chip signs it (INTERNAL AUTHENTICATE) in the same session.

The server then runs passive and active authentication as above; the phone
never decides whether a document is genuine. Tests cover the ICAO worked
example for BAC and secure messaging byte for byte, every PACE variant
against a simulated chip, and (in CI) the real PC/SC transport through
pcscd with a virtual reader. Real documents still need trying: PACE variants
with Integrated or Chip Authentication Mapping aren't supported yet, nor is
Chip Authentication, and some chips refuse to sign a nonce at all (those can
anchor, and recover through a station).

Files exported by other readers (DG1, SOD, DG15, or one `.json`) still load,
and local development builds read a simulated chip in the browser.

## Layer 4 · Waits set by the evidence, and the veto

| Proofs | Wait (production) | Formula |
|---|---|---|
| anchor at a **station** + anything | 24 h | base ÷ 3 |
| **witnesses** + card, key or live chip | 72 h | base |
| any two of card, key, live chip (no people) | 7 days | base × 7⁄3 |
| any of the above within 14 days of a **duress** signal | × 2 | |

`base` is `RECOVERY_DELAY_MS` (72 h). The wait starts when the second kind of
proof arrives; a stronger third proof can shorten it. During the wait every
device of the account sees an alert naming the evidence, witnesses see it
too, and **any surviving device cancels with one live check**. Proofs that
point at different accounts are refused. Removing a security key or replacing the seal
card during the wait withdraws it as a proof: a recovery left with one proof goes back
to collecting.

## Layer 5 · The continuity record and the public log

Every device carries the evidence that let it in: `device.added` records the
route (`register`, `link`, `quorum`…), and for recoveries the kinds of proof,
anchor mode, station and how long it waited. `recovery.evidence`,
`recovery.station_verified` and `recovery.completed` record each step.

Every ledger entry of every account is also a leaf of one append-only Merkle
tree (RFC 6962 shape, SHA3-256):
`leaf = SHA3(0x00 ‖ lp("HUMID-TLOG-v1", owner, seq, entry hash))`.
The ledger signs checkpoints `{size, root, at}` with its ML-DSA-87 key. Public,
unauthenticated:

| | |
|---|---|
| `GET /tlog/v1/checkpoint` | latest signed checkpoint and cosignatures |
| `GET /tlog/v1/consistency?from=&to=` | proof that one tree extends another |
| `POST /tlog/v1/cosign` | a configured cosigner's signature on a checkpoint |

On each Activity view the phone checks that its latest entry is included in
the current checkpoint and that the checkpoint extends the one it saw last
time (remembered on the device). Independent cosigners
(`tools/tlog-cosign.mjs`, configured with `HUMID_TLOG_COSIGNERS`) do the same
from outside and refuse — loudly — if the history ever forks. So the server
can't rewrite anyone's history, or show different histories to different
people, without leaving proof. Anyone can later check that a document sealed
in 2027 and opened in 2031 sits on one unbroken chain of the same person,
with the strength of each link on record.

The public endpoints reveal tree sizes and hashes only: the total number of
ledger events, never whose they are.

## Duress

If someone forces you to unlock, a gesture you chose (hold Unlock about two
seconds, or tap the mark three times) unlocks exactly as usual. Then:

- **Decoy view.** The app shows only documents you marked "Show in decoy
  view" (a flag inside the encrypted index), a calm Security screen (duress
  off, no alerts) and an Activity list limited to those documents.
- **Silent lockdown.** Every sign-in carries a duress flag, signed by the
  device key that only the live check releases (the flag is decided inside
  that check, from the sealed setting). The sign-in has the same size and
  shape either way, and the server's work happens after the reply. A bare
  request from a session that is already signed in can't raise it (the old
  `POST /auth/presence` flag is ignored), so malware riding an open session
  can't lock down or erase a vault. With the flag set, the server locks the account:
  adding or removing devices, approving links, changing recovery, settings or
  stations, helping others recover and closing the account fail like a busy
  server (`503 busy`), on every session. Reading still works, so nothing
  looks wrong.
- **Slower recoveries.** Recoveries under way and any started in the next 14
  days wait twice as long.
- **Witness alert (opt-in).** Witnesses who were asked to be told see "someone
  you protect signaled duress" next time they open HumID.
- **Lifting it.** Only from a normal (non-decoy) unlock, with a live check,
  once it has been calm for `HUMID_DURESS_COOLOFF_MS` (24 h). Signal and lift
  are both in the ledger; the Activity view of a decoy session hides them.

Limits: a gesture can be coerced out of someone who is threatened long
enough; an attacker who knows HumID well may try to force a normal unlock
later, which the cool-off and the doubled waits make slow. The duress setting
is stored on the device, so forensic access to an unlocked device can reveal
that it's on. Treat duress as raising the cost of coercion, not removing it.

## What it doesn't prove

- **Biological sameness.** Without stored biometrics, HumID proves a chain of
  independent evidence. That's deliberate: a stolen biometric database can
  never be changed.
- Identical twins with each other's documents, document fraud by a state, a
  colluding majority of witnesses plus a stolen card, or a compromised
  station operator can defeat the chain. The waits, the veto, the alerts and
  the public log are what catch those.
- The waits and the veto are server rules. A dishonest server that also got
  the holder's proofs could release early or skip the wait. Without a
  passport link it needs **two** of them. With one, it already holds the
  passport piece ([above](#the-anchor-and-the-operator)), so **one** more is
  enough. The cryptography guarantees confidentiality; the clock is the
  server's word.
- In **holder-only** mode there is nothing to recover with at all, so none
  of this applies, and nothing can bring the vault back after every device is
  lost.
- **Law.** A station's face match falls under biometric-privacy law (in
  Illinois, BIPA: written consent first, a published retention and
  destruction policy, nothing kept after the match) and GDPR's special
  categories. HumID itself stores no face data; stations must handle consent.
