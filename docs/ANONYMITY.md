# Anonymity: who can know what (POC v2)

Status: POC. Code: `packages/pass`, `services/access`, `services/gateway`
(`register`, `passKeys`, `passIssue`), `apps/mobile` (onboarding *access* step,
`redeemAccessCode` in `src/core/controller.js`). Tests: `tests/pass.test.js`,
`tests/e2e/pass.test.js`.

HumID's promise: **only the holder knows whose HumID it is.** Not HumID, not
the payment provider, not someone who breaches the server. This page says how
each part keeps that promise, and where it stops.

## What each party can see

| Party | Sees | Never sees |
|---|---|---|
| **The phone** | everything: keys, documents, the access code until the pass is ready | — |
| **identity** | the account's public keys; per device: platform (`iOS app`), gate method, hardware level (`android-strongbox`…) | a name, email, phone number, biometric, payment |
| **access** | which access codes exist, by hash; on which **day** each was minted and used; hashes of spent passes, by **day** | any account, device or key; any time of day; which pass came from which code |
| **vault, ledger, recovery** | as in [SECURITY.md](SECURITY.md#what-it-does-not-protect-against-yet) | payments, codes, passes |
| **Whoever sold the code** (a counter, an online store) | who bought it, if they paid by card | which account it became |
| **Someone on the network** | that a device talked to the vault, when, from which address | anything inside HTP/1 |

## Registration collects nothing personal

An account is its public keys (ML-KEM-1024, ML-DSA-87, X25519). There's no
field for a name, email or phone number anywhere in the protocol.

**Biometrics never leave the phone.** The face or fingerprint is matched by
the phone's own secure hardware (Secure Enclave, Android Keystore). HumID gets
a signature from a key that the hardware releases only after a live match, and
an attestation that the key really is biometric-only. It never receives an
image, a template or a measurement. That also keeps HumID out of collecting
biometric identifiers, which laws like Illinois' BIPA regulate strictly
(confirm the position with counsel). Don't add code that captures them.

The attestation details kept per device are coarse and shared by millions of
phones (hardware level, attestation version, app package). The attestation
certificates themselves aren't stored.

## Paying without being identified

```
 buy                    swap (once, anonymous session)            spend (at registration)
 ┌────────────┐  code   ┌──────────────────────────────┐  pass    ┌─────────────────────┐
 │ counter or │ ──────► │ app blinds a new pass        │ ───────► │ gateway: access     │
 │ web store  │         │ access signs it BLIND        │          │ spends the pass,    │
 └────────────┘         │ app unblinds and checks it   │          │ then identity makes │
   knows the buyer      └──────────────────────────────┘          │ the account         │
                          sees: code + a blinded value             └─────────────────────┘
                          that is unrelated to the pass             access sees: the pass
                                                                    identity sees: the keys
```

1. **Buy an access code** (`HA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, 110 random bits
   plus 2 check characters so typos are caught on the phone). Operators mint
   them and sell them for cash or through any shop that delivers license keys.
2. **Swap it for a pass.** The app makes a random pass, *blinds* it (RFC 9474,
   RSABSSA-SHA384-PSS-Randomized), and sends the code with the blinded value in
   a session of its own that never signs in. The access service checks the
   code, marks it used, and signs the blinded value. The app unblinds the
   signature and checks it against the published key.
3. **Spend the pass** when creating the account. The gateway asks the access
   service to spend it (stored: a hash of the pass and the day), then asks
   identity to create the account. If that fails, the pass is refunded.

**Why the vault can't connect them.** In step 2 the access service sees a
blinded value: a number made uniformly random by the app's secret blinding
factor. Every pass it later sees in step 3 is equally consistent with every
blinded value it ever signed. This holds against unlimited computing power,
quantum included: it's information-theoretic, not a hard problem someone
might later solve. The access service also never learns which account a pass
created: the gateway creates the account after the spend and doesn't tell it.

**A paid code is never lost.** Before the code is sent, the app saves the
blinded request (and the code) on the phone. If the app dies or the network
drops, it sends the same request again and the access service, recognising it,
answers again. Once the pass is finished the code is deleted from the phone.
The unspent pass lives in its own store (`wallet`), so erasing an identity
doesn't throw it away. After registration it's deleted.

**Key rotation.** A pass key signs for a year (`HUMID_PASS_ISSUE_DAYS`) and its
passes are accepted for 18 months (`HUMID_PASS_ACCEPT_DAYS`), so at most two
keys are ever live. The app refuses a server that publishes more than two
keys, or more than one signing key: a server handing different people
different keys could otherwise sort them into groups.

## Selling access codes

```bash
# Docker
docker compose run --rm access server.mjs mint 100 counter-2026-10
# HumID Server for Windows (Terminal, Admin)
humid mint 100 counter-2026-10
```

Each line printed is one code. The batch name is only for your own records
(which batch went to which shop); it's stored with each code's hash. Print
codes on cards for cash sales, or load them into a store that delivers keys
after payment. A card payment tells the store who bought *a code*; the blind
signature means that never extends to *which account*. Cash leaves no trace.

Set `HUMID_PASS_BUY_URL` to the https page where people buy codes; the app
links to it on the access step.

## Emergency recovery, anonymously

Recovery always needs two of three proofs ([CONTINUITY.md](CONTINUITY.md)).
Their anonymity differs:

| Proof | Reveals |
|---|---|
| **Seal card** | nothing: a code the holder keeps |
| **Witnesses** | to the server, which pseudonymous accounts protect which; to each witness, only what the holder chose to tell them |
| **ID chip** | the one that ties a HumID to a real identity: the server keeps a keyed fingerprint of the passport's stable fields, so someone with the server's secret and a person's passport details could confirm that person has a HumID. The app says so before anchoring. |

The fully anonymous emergency path is **seal card + witnesses**, and a second
device makes recovery rarely needed at all. Setup points people there.

## What it doesn't hide

- **The network.** The vault learns a connecting device's IP address for the
  moment of the connection. Neither edge logs addresses, and the gateway uses
  them only for in-memory rate limits, but a compromised edge could watch live.
  Use a VPN or Tor for network anonymity.
- **Timing within a day.** The access service stores days, never times, but
  the ledger records when each account was created to the second. Someone with
  both databases could narrow a code to the accounts created that day. Swap the
  code for a pass early and register later to widen the crowd.
- **The seller.** A store that took a card payment knows who bought a code.
- **Forgery after quantum computers.** Blindness holds forever; *unforgeability*
  rests on RSA-4096. A future quantum attacker could mint free passes, not
  unmask anyone. Keys rotate yearly; a post-quantum blind signature can replace
  the suite behind the same interface.
- **Two key groups.** The two-key limit bounds how far a malicious server can
  sort people by key; publishing pass keys in the public log would remove it.
- **The ID anchor and witnesses**, as in the table above.
- **Where you sealed things, to whoever holds your keys.** A document's location
  stamp (on by default on the seal screen, off per document) is kept in its
  encrypted index, which the server can't read; but anyone who opens your vault sees
  where each document was sealed. Turn the stamp off for documents you'd rather not
  tie to a place (docs/ID-SCANNING.md).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `HUMID_REGISTRATION` (gateway) | `pass` | `pass`: a new HumID needs an access pass. `open`: anyone. |
| `HUMID_PASS_BUY_URL` (gateway) | empty | https page where people buy codes; the app links to it. |
| `HUMID_PASS_ISSUE_DAYS` (access) | `365` | How long a pass key signs new passes. |
| `HUMID_PASS_ACCEPT_DAYS` (access) | `545` | How long a key's passes stay spendable. Between ISSUE_DAYS and 2 × ISSUE_DAYS. |
| `HUMID_PASS_KEY_BITS` (access) | `4096` | RSA modulus size for new pass keys. |
