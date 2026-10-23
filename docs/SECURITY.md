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
| **Spyware on the phone copies the keys** (a Pegasus-class kernel exploit reading memory during a biometric check) | Split keys: every document sealed since split keys also needs its own 256-bit key, held by the separate keyshare service and released one document at a time inside a live, chip-signed check, capped per hour. The stolen account keys, even with a full copy of the vault, open nothing. See [*A compromised phone*](#a-compromised-phone). |
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
| **Paying links you to your account** | The access code you buy is swapped for a pass the server signs blind (RFC 9474), in a session that never signs in; registration spends the pass. The access service, which keeps codes and spent passes, never sees an account, and stores days, not times. See [ANONYMITY.md](ANONYMITY.md). |
| **Brute force** | Sign-ins are rate-limited per account, handshakes per IP, calls per session. |

## What it does not protect against yet

- **Unreviewed composition.** See the status note above.
- **Attestation proves the key, not the person.** The secure chip proves a
  live biometric match on that phone unlocked the key. It can't tell whose
  enrolled face or finger it was: anyone the phone's owner enrolled can pass.
  Keys are destroyed if enrolment changes, and the owner confirms at setup
  that only their own biometrics are enrolled (recorded in the ledger).
- **A live check is not consent.** It proves an enrolled face or finger was
  matched live, not that its owner meant it: a finger pressed while asleep, or
  under force (the duress gesture covers force), passes.
- **The seal proves who and when, not that the document is genuine.** A forged
  page or card seals like a real one. Only an ID chip read carries the
  issuer's signature.
- **Seal time is the server's.** The phone writes its own clock into the
  envelope (`manifest.created`); the chip's live signature covers the
  ciphertext, not the time. The app therefore shows the vault server's receive
  time as **Sealed** (`apps/mobile/src/core/sealtime.js`). The genuine app
  can't reach the server with its clock more than two minutes off (HTP frame
  window), so the two agree; a larger gap is shown as "Phone's clock said …".
  An exported sealed file still carries only the phone's time.
- **Desktop apps are paused** (2026-10-17). A desktop gate has no hardware
  proof: on Windows (DPAPI) and Linux (Secret Service) the secret is protected
  by the operating system for the signed-in user, so malware running as that
  user can reach it without a finger. Servers refuse desktops by default
  (`HUMID_DEVICE_POLICY=attested`), and *Release apps* no longer publishes
  macOS, Windows or Linux apps unless the repository variable
  `HUMID_DESKTOP_RELEASES=on` is set.
- **Recovery proves a chain of evidence, not biology.** See the limits in
  [CONTINUITY.md](CONTINUITY.md#what-it-doesnt-prove).
- **ID chips: what's not checked yet.** The app reads chips with BAC or PACE
  (ECDH Generic Mapping) and Active Authentication. Chip Authentication, and
  PACE with Integrated or Chip Authentication Mapping, aren't supported yet;
  chips without Active Authentication count only at a station. A server with
  no CSCA certificates configured can't use ID anchors.
- **A scanned ID is a copy, not a proof.** "Scan an ID" stores what the
  document says. A license barcode and a photographed MRZ aren't signed, so
  they show what's printed, not that the card is genuine. A chip copy is
  checked against the issuing country's signed hashes, but the signer's
  certificate is only checked against a country CSCA when the chip anchors an
  identity on the server. See [ID-SCANNING.md](ID-SCANNING.md).
- **Document images are parsed by WebAssembly engines.** zxing-cpp and
  Tesseract read camera frames and chosen photos inside the app's sandbox,
  which needs `'wasm-unsafe-eval'` in the content security policy (WebAssembly
  only; JavaScript `eval` stays blocked).
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
- **A compromised phone.** Split keys limit it; nothing inside an app can stop
  it. See [*A compromised phone*](#a-compromised-phone) below.
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
  times, IP addresses at the edge (not logged), and which accounts protect
  which. It never sees names, contents or keys, and can't link a payment to an
  account ([ANONYMITY.md](ANONYMITY.md) lists what that doesn't cover: network,
  timing within a day, the seller). A document's location stamp, like its name,
  is inside the encrypted index: the server never sees it. The public log reveals the total number of
  ledger events. The server holds a keyed fingerprint of an anchored ID chip's own key
  (not the holder's details), and its issuing country. A holder-only account has no
  recovery material on the server at all ([RECOVERY.md](RECOVERY.md#two-recovery-modes)).
- **Demo mode has no biometric.** It exists only in local development builds
  (`npm run dev`); release builds don't contain it, and servers refuse it
  unless `HUMID_DEVICE_POLICY=demo`.
- **Server keys are files.** The gateway's HTP key, the ledger's signing key,
  the access service's pass keys and keyshare's `share-key.bin` live on the
  server's volumes, not in a hardware security module.
- **Pass keys aren't post-quantum.** Blind passes stay unlinkable forever, but
  a quantum computer could forge them (free accounts, not unmasked ones). Keys
  rotate yearly.

## A compromised phone

The threat: spyware with control of the phone's operating system (a
Pegasus-class zero-day exploit chain) reads the app's memory the moment its
owner passes a face or fingerprint check. The secure chip protects keys while
they rest; it can't protect what the app has in memory while it works.

**What HumID can't prevent, and no app can:** while the phone is infected,
anything shown on it can be read, and any document its owner opens there can
be copied as it opens. A kernel attacker can also change what the prompt says,
so the owner's check approves a different document than they think. The fix
for that lies with the operating system and its updates, not inside an app.

**What split keys change:** before them, one biometric check put the account
seed in memory, and that seed opened every document, past and future, for good.
Now:

| | Before split keys | With split keys |
|---|---|---|
| Account keys copied during one check | open every document whose envelope the attacker gets, forever | open **nothing**: each document also needs its own key from keyshare |
| Account keys + a full copy of the vault's disks | the whole vault | nothing |
| Keyshare's database + share-key.bin | — | nothing: the keys open only envelopes, which need the account keys |
| The infected phone itself | every document, through its own sessions | only documents released through live checks on it, at most `HUMID_SHARE_RELEASES_PER_HOUR` an hour, each one in the ledger |

How it works ([`packages/crypto/src/split.js`](../packages/crypto/src/split.js),
[`services/keyshare`](../services/keyshare/src/server.js)):

1. **Sealing.** The phone encrypts the document (name and type included) under
   a fresh random 256-bit key, then seals that to the account's keys as an
   ordinary envelope. The envelope goes to the vault; the key goes, inside the
   same encrypted HTP/1 call, to the gateway, which hands it to keyshare and
   strips it before the vault sees the request. The phone wipes it. If keyshare
   can't store it, the upload is undone, so no document exists without its key.
2. **Opening.** The step-up that already lets the vault return the envelope
   (a fresh live check, signed by the phone's secure chip over that exact
   request) also lets keyshare release that one document's key. The gateway
   records the open in the ledger before releasing either. No extra prompt.
3. **Separation.** Keyshare never sees an envelope, a name or an account key;
   the vault never sees a document key. Keyshare stores keys encrypted
   (AES-256-GCM, bound to account and document) under `share-key.bin`. In the
   Docker deployment, keep `keyshare-data` on different storage from
   `vault-data`, ideally another host, and move `share-key.bin` into an HSM or
   KMS before real data. Since server 3.0, `share-key.bin` is sealed under the
   machine's seal key (DPAPI with BitLocker's TPM protector on Windows, a TPM2
   systemd credential on Linux), and the keys role can run on its own machine
   and storage over mutual TLS (docs/DEPLOY-VMS.md). On a single PC both halves
   still share one machine, but a copy of its data folder opens neither. Its
   backups keep them apart too (server 3.1): each is encrypted to a backup key
   kept off the computer, with keyshare's half in a separate file that can go
   to another disk ([ADMIN.md](ADMIN.md), *Backups*).

**Limits:**

- **Older documents.** Documents sealed before split keys aren't split. Open
  and re-add any that matter, or wait for account-key rotation.
- **Names in the list.** Item names in the vault list are encrypted under a key
  derived from the account seed, so copied account keys reveal names (not
  contents) of documents whose index entries the attacker also gets.
- **The cap is a speed limit.** At the default 120 an hour, an attacker in
  control of a phone and its owner's routine checks could still release many
  documents over days. Every release is in the ledger and visible in Activity.
- **The seed is still exposed at each check.** The account keys still pass
  through memory at every check. Split keys make them worth far less; they
  don't keep them out of memory. The follow-ups below shrink what's left.

**Adding a device takes more than the seed.** Copied account keys can't be used to add a
phone of the attacker's own: a device joins only through a link that one of the account's
devices approved, with a live check, for that exact device key, or through a released
recovery (proofs in, wait over, not cancelled), and every surviving device is alerted to a
recovery and can veto it.

**Follow-ups:** second-device approval (an infected phone can't approve alone,
and the second device shows what is really being approved); account-key
rotation (stolen keys stop working; also removes the "older documents" gap);
a security-patch gate (refuse phones whose attested patch level is stale).

## Offline

With no connection, or with the vault server down, Unlock still works: the same live
check opens a **read-only copy kept on the device**. It holds what the app last showed
online: the document list (each entry still sealed under the index key), devices,
recovery and duress status, and the verified Activity ledger. It never holds a document
or a document's key, so nothing opens offline: opening needs the vault and both halves
of a split key, exactly as online, under the same per-hour cap, recorded in the ledger.

| | Online | Offline |
|---|---|---|
| Unlock | live check, signed in to the vault | the same live check, on the device only |
| See the list, Activity, Security | live | as of the last sync, marked "Offline · read only" |
| Open, save, rename, delete, add | each with its own live check | refused until it reconnects |
| Duress gesture | decoys only, server locks down | decoys only; the server is told at reconnect |

How it's kept ([`packages/crypto/src/suites/pq1.js`](../packages/crypto/src/suites/pq1.js),
[`apps/mobile/src/core/controller.js`](../apps/mobile/src/core/controller.js)):

- **Sealed.** AES-256-GCM under `offlineKey`, derived (HKDF-SHA3-256) from the account
  seed, which only a live check releases. The key is held while unlocked and wiped on
  lock. What's on disk reads as random bytes; the account id is the only label.
- **No new secrets.** Everything in the copy is something an unlocked phone already
  shows. Spyware that can read the screen gains nothing new from it, and stolen
  account keys can't use it to open a document.
- **Duress.** A duress session never writes the copy. Offline, the duress gesture shows
  only the decoy documents, as online; reconnecting from that session reports duress,
  so the server locks down then. Which gesture means duress is itself sealed on the
  device (`settingsKey`, same derivation family) and read only inside the live check, so
  the copy, the identity record and the setting all read as random bytes at rest.
- **Removal.** Erasing the device's vault erases the copy. When the server says the
  device was removed (or isn't the server it trusted), the copy is deleted at that
  moment. Until a removed device reconnects, its owner's live check still shows its
  copy: a list, not documents.

What offline mode doesn't do: open documents. Keeping a document readable offline
would mean its key on the device, which is what split keys exist to prevent.

## Check-in

A holder can arm a timer before a high-stakes situation (docs/CHECKIN.md):
check in with a live check before each deadline, or the vault locks, then is
erased for good. While it's armed, every split key of the account is sealed
under a fuse key that keyshare keeps in memory only; destroying it is the
erase, so every copy of those keys, live or in a backup made since arming,
becomes unreadable. A duress unlock while armed erases at once and leaves the
duress session looking ordinary. The duress setting itself is sealed on the
phone (see the 2.0 security pass below), so a copy of the phone doesn't tell a
coercer which gesture to avoid.

What it doesn't cover: an operator who changes keyshare to keep fuse keys;
backups made before arming (they hold the keys of documents sealed before it);
item names in vault backups, readable with a recovered account seed; anything
already saved or exported; a server seized while running. A keyshare restart
erases every armed vault, by design. Off by default (`HUMID_CHECKIN`) until
push reminders exist.

## 2.0 security pass

A review of the app shell and what it keeps on the device (October 2026); the item-by-item
table is in [HARDENING.md](HARDENING.md#20-security-pass-october-2026). In short:

- **Nothing about duress is on the device in the clear.** The setting is sealed under a
  seed-derived key; the decoy-or-real decision is made after the live check, from the
  opened setting (`apps/mobile/src/core/duress.js`).
- **Leaving the screen locks**, even with a file picker open: the exemption is bounded
  (60 s, `pagehide`, a 20 s hidden span; the Android document scanner, below, 90 s and a
  60 s hidden span).
- **Names are forgotten on lock**; a decoy session never decrypts the other names.
- **Release builds carry no demo or simulation code** (`tests/bundle.test.js`); the
  simulation app has its own bundle identifier.
- **The WebView never leaves HumID.** Links go out through `openExternal` (https, tel,
  mailto only) and the shell refuses any other navigation.
- **Every request times out** (45 s), so a silent server can't hold a live check open.
- **Chip photos are bounded** before decoding (2 MB, 4 Mpixel), and never decoded from
  a chip that fails its own hash list.
- **iOS backups exclude the WebView's data store.**

## The Android document scanner (apps 2.1.1, narrowed in 2.1.2)

On Android, **Add ▸ Photo** and **Another card** photograph with the phone's document
scanner (ML Kit, run by Google Play services; `plugins/humid-docscan`). It runs on the phone
in base mode (crop and turn, no filters or ML clean-up), one page, no gallery import, and
the page comes back to HumID as JPEG bytes; the scanner's file is deleted once read, and a
start-up sweep clears any page left by a HumID that was stopped in between. Other apps
can't receive the result (it returns to HumID's activity; the file is in HumID's private
storage). What it costs, and why IDs are kept off it:

- **HumID's screen protection doesn't reach it.** HumID's window blocks screenshots,
  screen recording, casting and the recents thumbnail (`FLAG_SECURE`, no recents
  snapshot on API 33+). The scanner's screen belongs to Play services, which HumID can't
  set flags on, so what it shows can most likely be screenshotted, recorded by a screen
  recorder the person allowed, or appear in recents. **So driver's licenses, passports,
  ID cards, permits and payment cards use HumID's own camera** (`DocCamera`, `native`
  off by default); only Photo and Another card use the scanner.
- **Google learns usage, not content.** Per Google's ML Kit data disclosure, ML Kit sends
  device model and OS, the app's package name, a per-installation identifier, timings,
  image format and size, and error codes, for diagnostics and analytics; no opt-out.
  Google says the scanner flow runs entirely on the device, so pictures aren't sent. For
  HumID this means Google can learn that a phone runs HumID and when it scanned. The
  privacy policy and Play's Data safety form must say so.
- **Code HumID doesn't control.** Play services updates the scanner on its own schedule;
  base mode is said to get only minor refinements. The Maven dependency
  (`play-services-mlkit-document-scanner:16.0.0`) is pinned but not checksum-verified
  (Gradle dependency verification is off; with the SC-01..05 supply-chain items in
  HARDENING.md).
- **The vault stays unlocked while the scanner is up**, because HumID can't tell the
  scanner from the person pressing Home from it: at most 60 s off the screen (90 s in all),
  then it locks as usual.

## Before real data

1. Independent review of HTP/1, the envelope format and the recovery flows.
2. Test live checks on real hardware: several Android phones (TEE and
   StrongBox, Class 3 face and fingerprint) and iPhones with App Attest in
   production. Pin `HUMID_ANDROID_CERT_DIGESTS` to your signing key, and
   keep the pinned Google and Apple roots current (Google's revocation list
   is not fetched yet).
3. Native apps only, signed, with the server key pinned at build time.
4. Server keys in an HSM or cloud KMS (including keyshare's `share-key.bin`), keyshare on
   separate storage from the vault; encrypted, tested backups of every volume. Server 3.0
   covers the middle of this: every server secret sealed at rest under a TPM-bound machine
   key, the keys role on its own machine over mutual TLS, and (3.1) backups encrypted to a key
   held offline, with the key-share data in its own file (docs/DEPLOY-VMS.md, docs/ADMIN.md). An HSM is still the step after.
5. Push and email alerts for new devices and recoveries.
6. Account-key rotation after a device is removed.
7. Penetration test of the deployed stack, including the admin console (docs/ADMIN.md).
8. Privacy policy, terms and data-handling review with counsel.
9. The access pass is now sealed at rest (see *The access pass at rest* below). Still
   to do: hold the install key in the platform's secret store (a non-biometric Keychain,
   Keystore, DPAPI or Secret Service slot via a new gate-plugin command) rather than in
   the WebView's key store, and seal the `pending` join record while a join waits.

## Server 3.0: the server's own hardening

- **Internal requests are bound and single-use (SEC-S-01, fixed).** The gateway's signed
  assertion to a service now names the service, the method, the exact path and query and
  the SHA-256 of the body, and carries a random id that the service accepts once. A service
  also refuses assertions minted before it started. One captured assertion (from a download,
  say) authorises nothing else: not `DELETE /objects`, not the same request twice. Tests:
  `tests/server3.test.js`.
- **Server secrets are sealed at rest.** The HTP identity keys, the ledger's signing key, the
  recovery anchor secret, keyshare's master key, the pass issuer keys, the internal signing
  key and the role certificates' keys are AES-256-GCM-sealed under a seal key the machine
  protects (DPAPI on Windows; a key file the operator provides elsewhere, e.g. a TPM2
  systemd credential). Each sealed file names itself in its associated data, so files can't
  be swapped. A plain secret from an older install is sealed in place with the same key
  material: the server's kid doesn't change.
- **Mutual TLS between roles.** When front, core and keys run on separate machines, each
  hop is TLS 1.3 with Ed25519 certificates from the server's own CA; core and keys accept
  only `humid-front`, and the gateway accepts only the role it meant to reach.
- **Encrypted backups (server 3.1, PC-10).** `humid backup` writes chunked AES-256-GCM files
  whose file keys are sealed (HUMID-PQ1: ML-KEM-1024 + X25519) to a backup key the
  administrator makes with `humid backup-key new -Path <file>`. Its private half goes only to
  that file, kept off the computer; the server keeps the public half, so it can make backups
  but can't open them. The key-share data goes to its own file (another disk), and the seal key
  travels only inside the encrypted stream, so a restore on a new machine seals it again under
  that machine's DPAPI. A cut, reordered, swapped or altered backup is refused before anything
  changes. (3.0 test builds kept a DPAPI-sealed backup key on the server; 3.1 removes it.)
- **Still open:** the hypervisor of a VM can read its memory (use confidential VMs where
  possible); restarting the keys role erases Heartbeat-armed vaults; an HSM for the seal
  key; one process per role (no scale-out yet).

## The access pass at rest

Between buying an access pass and spending it (`docs/ANONYMITY.md`) there is no account,
so no seed-derived key. Until 2.0 the wallet record (the draft: access code and blinded
request; then the finished pass) sat in IndexedDB as it was. Now (`@humid/pass/atrest`,
apps 1.13):

- **Install key.** On first use the app generates a 256-bit AES-GCM key with WebCrypto as a
  *non-extractable* `CryptoKey` and stores it in its own IndexedDB database (`humid-keys`),
  apart from the wallet. JavaScript never sees the key's bytes: it can only ask the WebView's
  crypto engine to encrypt or decrypt with it. The same mechanism works in all five native
  builds and the web app; a private window with no IndexedDB keeps the key in memory, like
  the pass itself there.
- **Sealing.** The whole wallet record is JSON, sealed with AES-GCM, a fresh 96-bit IV per
  write and the AAD `HUMID-PASS-v1`. Only the code, the draft and the pass live in it, so
  none of them is readable as stored (`tests/pass-atrest.test.js`).
- **Migration.** A clear record written by an older build is re-sealed on the first read and
  the plaintext overwritten. A record that doesn't open (another install's key, damage) is
  dropped rather than shown.

Why not the gate plugin: `humid-gate@2` holds one secret per identity and releases it only
after a live biometric check, which is the wrong shape for a value the app needs silently at
boot and before any identity exists; a non-biometric slot would be a new native command on
every platform. Why not a file in the app data directory: the shell's only file command is
the save dialog, and a file next to the database is no stronger than the key record.

Limits: the key is held by the WebView's crypto engine, not by the secure chip. Chromium and
WebKit serialise non-extractable keys to the profile's storage in the clear, so a copy of the
**whole** profile (root, a full-filesystem backup on a platform where the data store isn't
excluded) carries both the key and the pass. What it defeats: reading the code or pass out of
the wallet database alone, backups that include the database but not the key store, and
casual inspection of the storage. Moving the key into a platform secret-store slot is the
remaining item under *Before real data* #9.

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
