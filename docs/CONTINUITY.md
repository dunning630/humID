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

## Layer 3 · Two-proof recovery

`A` is split 2-of-3 (Shamir over GF(2⁸), degree 1). The coefficients come from
`HKDF-SHA3-256(A, "HUMID-QUORUM-v1 coefficient epoch e")`, so every device
holding `A` makes the same three parts at any time:

| Part | x | Protected by | Released when |
|---|---|---|---|
| **Witness** | 1 | split again among 2–5 witnesses (any majority), each piece sealed to that witness's account key | a majority approve, each with their own live biometric on their own phone |
| **Anchor** | 2 | stored by the server, AES-256-GCM under `HKDF(server secret, account, identity fields)` — the identity fields themselves are never stored | the passport or ID chip is proven again: in person at a station, or live (Active Authentication) |
| **Card** | 3 | the seal card (`HUMID-…` code), AES-256-GCM, like the v1 card | the card is presented |

Any two different parts rebuild `A`; the new device checks that `A` derives the
expected account id before joining. One part reveals nothing.

No one can recover alone: not a witness, not a thief with the card, not HumID
with the anchor part. Usual combinations:

- lost everything, still has friends and a passport → witnesses + anchor
- no witnesses reachable → anchor + card
- no chip ID (country without e-passports) → witnesses + card

### The identity anchor (ICAO 9303)

Setting the anchor: the owner's device sends the chip's DG1 (the MRZ), EF.SOD
and DG15 if present, plus the anchor part, inside one step-up. The server runs
**passive authentication**: DG hashes match the SOD; the SOD's signed
attributes bind its content; the Document Signer's signature verifies (RSA
PKCS#1, RSA-PSS, ECDSA); the DS certificate chains to a trusted **CSCA**
(`HUMID_CSCA_DIR`); the document hasn't expired. It then stores
`anchor = HMAC-SHA3(server key, issuer | nationality | names | birth date | sex)`
— the fields that survive renewal — so a new passport still matches, and the
part encrypted under those fields. One ID anchors one HumID.

Proving it again:

- **Remote (live chip):** passive authentication plus **Active
  Authentication**: the server issues an 8-byte nonce for this recovery, and
  the chip must sign it with the private key behind DG15 (RSA ISO/IEC 9796-2
  scheme 1, or ECDSA). A copy of the chip's files can't answer. Chips without
  AA can't be used remotely.
- **Station (in person):** an operator account listed in
  `HUMID_STATION_ACCOUNTS` scans the person's recovery code, reads their chip
  (passive authentication), and confirms three checks: the document is
  genuine, the face matches its photo, the person is present and asking
  themselves. The operator's own live biometric signs the result. The
  operator never learns whose HumID it is. Both ledgers record it.

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
| **witnesses** + card, witnesses + live chip | 72 h | base |
| card + live chip (no people) | 7 days | base × 7⁄3 |
| any of the above within 14 days of a **duress** signal | × 2 | |

`base` is `RECOVERY_DELAY_MS` (72 h). The wait starts when the second kind of
proof arrives; a stronger third proof can shorten it. During the wait every
device of the account sees an alert naming the evidence, witnesses see it
too, and **any surviving device cancels with one live check**. Proofs that
point at different accounts are refused.

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
- A server that holds `anchor-secret.bin` **and** the person's identity
  details **and** their card could skip the wait. The cryptography alone
  guarantees confidentiality; the waits are server rules.
- **Law.** A station's face match falls under biometric-privacy law (in
  Illinois, BIPA: written consent first, a published retention and
  destruction policy, nothing kept after the match) and GDPR's special
  categories. HumID itself stores no face data; stations must handle consent.
