# HumID security model (POC v2)

**Status: proof of concept.** The building blocks are standard (ML-KEM-1024,
ML-DSA-87, X25519, AES-256-GCM, SHA-3, from audited libraries), but the way
HumID composes them (HTP/1, the envelope format, the recovery flows) has not
had an independent cryptographic review. Don't store real customer data in
it until that review and the items under *Before real data* are done.

## What it protects against

| Threat | What stops it |
|---|---|
| **The server is breached, or an insider looks** | The vault holds only envelopes sealed on the phone to the account's ML-KEM-1024 + X25519 key, and index entries encrypted with a key derived from the account seed. No service holds a key that opens either. |
| **Someone on the network, or a proxy that ends TLS** | HTP/1 runs inside TLS 1.3. Its frames are encrypted end to end between app and gateway with keys from a hybrid ML-KEM-1024 + X25519 handshake. The app pins the server's key and refuses any other. |
| **Harvest now, decrypt later** | Transit and stored documents both use a hybrid of ML-KEM-1024 and X25519. An attacker must break both. Signatures are ML-DSA-87. |
| **A bot, or someone with your PIN or password** | HumID never accepts a PIN, passcode or password, on any device. Every check is a live face or fingerprint match. On phones a hardware *liveness key* (Secure Enclave or Android Keystore, usable only after a live Class 3 / Face ID / Touch ID match) signs each sign-in, step-up and sealed file, and the server verifies that signature. When a phone joins, the server checks that this key is really in secure hardware and really biometric-only: Android key attestation chained to Google's roots, or Apple App Attest chained to Apple's root. A bot with the account's keys but no live finger or face on that phone can't produce the signature. See *Live biometric checks* below. |
| **A stolen or lost phone** | Keys are released only by a live biometric check in the Secure Enclave or Android Keystore. Remove the device from any other device: its sessions end and the server refuses it. |
| **A stolen session or a replayed request** | Opening, deleting, exporting, adding or removing devices, changing recovery, and closing the account each need a fresh biometric signature over that exact request, bound to the session, at most 60 seconds old. The app reserves the request slot first (a *ticket*), so the liveness key signs that exact request during the check; a signature captured for one request can't approve another. Frames carry sequence numbers checked against a replay window. |
| **A stolen seal card** | Two-proof recovery: the card is one of three parts, and any recovery needs a second, different proof (witnesses or the ID chip). Then a wait of 24 h to 7 days, set by the evidence, during which any surviving device can veto. See [CONTINUITY.md](CONTINUITY.md). |
| **Rogue or coerced witnesses** | A majority must approve, each with their own live biometric, and that counts as one proof only. Fewer pieces reveal nothing. |
| **A copied passport chip** | Remote ID proofs need Active Authentication: the chip signs a fresh server nonce with its private key. Copied files can't. Otherwise only an in-person station check counts. |
| **A forged or altered ID** | ICAO passive authentication: data-group hashes, the Document Signer's signature, and a chain to a trusted country CSCA. |
| **Being forced to unlock** | A duress gesture unlocks into a decoy view and silently locks devices, recovery and closing the account; recoveries wait twice as long for 14 days; witnesses can be alerted. |
| **The server rewriting history** | Every ledger entry is a leaf of a public append-only Merkle log; phones check inclusion and consistency, and independent cosigners refuse forks. |
| **The server substituting keys while you add a device or contact** | Every code you type is a hash of the public keys behind it. The app recomputes it from what the server returns and stops on a mismatch. |
| **Tampering with your access history** | Each account's ledger is a SHA-3 hash chain with an ML-DSA-87-signed head, verified on the phone. Opening or deleting a document is refused if the ledger can't record it first. |
| **Brute force** | Sign-ins are rate-limited per account, handshakes per IP, calls per session. |

## What it does not protect against yet

- **Unreviewed composition.** See the status note above.
- **Attestation proves the key, not the person.** The secure chip proves a
  live biometric match on that phone unlocked the key. It can't tell whose
  enrolled face or finger it was: anyone the phone's owner enrolled can pass.
  Keys are destroyed if enrolment changes, and the owner confirms at setup
  that only their own biometrics are enrolled (recorded in the ledger).
- **Recovery proves a chain of evidence, not biology.** See the limits in
  [CONTINUITY.md](CONTINUITY.md#what-it-doesnt-prove).
- **ID chips: what's not checked yet.** The app reads chips with BAC or PACE
  (ECDH Generic Mapping) and Active Authentication. Chip Authentication, and
  PACE with Integrated or Chip Authentication Mapping, aren't supported yet;
  chips without Active Authentication count only at a station. A server with
  no CSCA certificates configured can't use ID anchors.
- **Stations are trusted operators.** Their face check is a human check, and
  their legal obligations (BIPA, GDPR) are theirs to meet.
- **iPhone attestation proves the app, not the key's settings.** App Attest
  shows the genuine HumID app made the liveness key; Apple has no way to show
  the key's biometric-only setting to a server. A modified app can't pass App
  Attest, so this holds as long as Apple's attestation does.
- **Desktops can't prove their checks.** Touch ID on a Mac, Windows
  fingerprint readers (through the Windows Biometric Framework; Windows Hello
  isn't used because it always allows a PIN) and Linux fprintd are
  biometric-only, but the secret is guarded by the operating system, not by
  attested hardware, and a server can't verify the check happened. The default
  policy (`HUMID_DEVICE_POLICY=attested`) therefore accepts phones only;
  `biometric` also admits these desktops and the app labels them as unproven.
- **The web build can't unlock anything.** A browser can't prove a live
  biometric, so the web app only points people to the iPhone and Android apps.
- **A compromised phone.** Malware with control of the operating system can
  see what you open while you open it.
- **Recovery timing is a server rule.** The cryptography keeps the seed
  secret, but the 72-hour wait and the cancel are enforced by the recovery
  service. An attacker who controls the server *and* holds your card could
  skip the wait.
- **Removing a device doesn't rotate the account key.** A thief who also
  defeated a lost phone's secure hardware would hold the account seed, though
  the server refuses that device. Rotation (re-sealing every document) is the
  follow-up.
- **Alerts appear in the app only.** There are no push or email alerts yet,
  so a recovery is noticed when you next open HumID.
- **Metadata.** The server sees account and device ids, document sizes and
  times, IP addresses at the edge, and which accounts protect which. It never
  sees names, contents or keys. The public log reveals the total number of
  ledger events. The server holds a keyed hash of an anchored ID's stable
  fields, and its issuing country.
- **Demo mode has no biometric.** It exists only in local development builds
  (`npm run dev`); release builds don't contain it, and servers refuse it
  unless `HUMID_DEVICE_POLICY=demo`.
- **Server keys are files.** The gateway's HTP key and the ledger's signing
  key live on the server's volumes, not in a hardware security module.

## Before real data

1. Independent review of HTP/1, the envelope format and the recovery flows.
2. Test live checks on real hardware: several Android phones (TEE and
   StrongBox, Class 3 face and fingerprint) and iPhones with App Attest in
   production. Pin `HUMID_ANDROID_CERT_DIGESTS` to your signing key, and
   keep the pinned Google and Apple roots current (Google's revocation list
   is not fetched yet).
3. Native apps only, signed, with the server key pinned at build time.
4. Server keys in an HSM or cloud KMS; encrypted, tested backups of every volume.
5. Push and email alerts for new devices and recoveries.
6. Account-key rotation after a device is removed.
7. Penetration test of the deployed stack.
8. Privacy policy, terms and data-handling review with counsel.

## Live biometric checks

"Human validated" means the server has evidence, for every action, that a
live face or fingerprint match happened on a device it trusts. Here is how.

**When a phone joins** (first device, link, recovery), its secure chip makes a
new P-256 *liveness key* that can only be used after a live biometric match,
for one operation at a time:

| | Android | iPhone |
|---|---|---|
| Key | Android Keystore (StrongBox if present), `AUTH_BIOMETRIC_STRONG`, per use, invalidated if biometrics change | Secure Enclave, `.privateKeyUsage` + `.biometryCurrentSet`, passcode fallback hidden |
| Proof | Key attestation chain to Google's root; the server checks: hardware-backed (TEE or StrongBox), EC P-256, biometric-only (no PIN or password), per use, not usable while merely on-body, locked bootloader and verified boot, app `app.humid.vault`, challenge = this session's transcript | App Attest object chained to Apple's App Attestation Root; the server checks: app id, production environment, counter 0, key id, and `clientDataHash = SHA-256(session transcript ‖ liveness key)` |

The liveness key then signs the device-enrolment statement in the same check.
The server stores the key and the proof (`android-tee`, `android-strongbox`
or `apple-secure-enclave`) with the device.

**Every later check** is signed by that key:

| Action | What the liveness key signs |
|---|---|
| Sign in | the server's one-time sign-in challenge, bound to the session |
| Step-up (open, delete, export, devices, recovery, close) | `HTP/1 live ‖ session ‖ seq ‖ method ‖ path ‖ time`, from a ticket reserved before the prompt |
| Seal a document | `HUMID-SEAL-v1 ‖ SHA3-512(ciphertext)`; the vault refuses a phone's envelope without it |

A missing or wrong signature is refused and logged in the holder's activity
as an access denied, so a bot holding the account's keys gets nowhere and
leaves a trace.

**Device policy** (`HUMID_DEVICE_POLICY` on the gateway): `attested`
(default) accepts only proven phones; `biometric` also accepts
biometric-only desktops without proof; `demo` is for local development.
Tightening the policy locks out devices that no longer qualify at their next
sign-in.

## Reporting a problem

The repository is private. Report anything security-related to the
maintainer directly, not in an issue.
