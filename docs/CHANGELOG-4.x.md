# HumID 4.x: change notes that were never versioned

HumID 4.x kept one changeset per change in `.changeset/` (`npx changeset`), to be turned into
per-package versions and CHANGELOG entries by `changeset version`. That step never ran, so
these notes were the only record of the changes. HumID 5.0 drops changesets (one version for
the app, one for the server, tagged on main); the notes are kept here as they were written,
in file-name order. Each heading is the note's file name; the line under it is the version bump
each module would have taken.

## anchor-chip-bound

*@humid/recovery minor, @humid/anchor minor, @humid/api major, @humid/recovery-service major, @humid/gateway-service minor, @humid/mobile minor*

The ID-chip recovery anchor is now bound to one chip (CREDS-01, CREDS-02). The anchor part is no longer stored in a form the server's files and the holder's details open (VAULT-01 and CREDS-03, at rest only).

- The phone seals the anchor part under `anchorPartKey(DG15)` before sending it (`sealAnchorPart`). The server doesn't store DG15, so its secret, its database and the holder's name and birth date together don't open the part.
- **Limit (V74-03):** DG15 is public chip data, and the server sees it at every link and recovery. An operator that records one request can open the part, so in hardened mode the passport plus any one other stolen proof is enough for a hostile operator. The app and the docs say so. The fix, a split wrap with an independent cosigner, is an open decision (docs/CONTINUITY.md).
- The anchor is `chipAnchorOf(DG15)`, a fingerprint of that chip's own key. An old passport or a namesake's passport doesn't match; a renewed passport is linked again.
- Linking needs the live chip: `POST /recovery/anchor/challenge`, then `PUT /recovery/anchor { chip, sealedPart, signature }`. A plain `part` is refused (`update_required`), and so is a chip with no Active Authentication key (`no_chip_proof`).
- Recovery returns `anchorSealed`, which the recovering device opens with the chip it reads live. After a station, the station's phone seals the chip's DG15 to the recovering device's keys (`stationVerify({ chipKey })`; `stationRequest` now returns those keys, checked against the code), so the device gets `anchorKey`.
- Anchors linked before this (v1) keep working, and the app asks the holder to re-link them on the next chip read.

Breaking: `api.setAnchor({ chip, part })` is now `api.setAnchor({ chip, sealedPart, signature })`.

## android-launcher-icon

*@humid/mobile patch*

Android shows the HumID peace-sign icon. The release build regenerates the Android project with `tauri android init`, which writes Tauri's own launcher icons (the blue-and-orange logo), and nothing put HumID's back. A release step now replaces them with `src-tauri/icons/android` (every density, the adaptive icon's layers and its background colour) and fails the build if any didn't land.

## app09-screen-readers

*@humid/gate minor, @humid/mobile patch*

Android: an app that can read the screen is named first (APP-09). `@humid/gate` exports `enabledAccessibilityServices()` (the native plugin's new `enabled_accessibility_services`, Android only; `[]` elsewhere, never throws). Before a document or card opens, a recovery card is made, or messages open, the app checks for an enabled accessibility service that can read window content and, if one is on, names it and asks; "Not now" shows nothing. A yes holds for that session and that set of services. Needs a device to confirm the native list.

## apps-3-2-1-security

*@humid/mobile patch*

3.2.1 is a security release: it carries the fixes 3.2.0 was built without. A duress unlock is now signed into the sign-in itself, so a stolen session can't erase or lock down a vault (PC-01). A new phone can join only with a link one of your devices approved, or a released recovery (PC-02). A document opens only if your own key signed it, so a server can't plant one (PC-03). Activity pins the ledger's key on first check and counts only cosigners built into the app (PC-04). Builds are released only from reviewed code on main, with every build action pinned (PC-05, PC-06, PC-11). It also includes 4.0 credentials and the "Proving it's you" messaging core, which have no app screens yet.

## apps-4-0-0

*@humid/mobile major*

4.0.0 brings every line of work onto one code base: the 3.x apps (the rebuilt document camera, payment cards, wallet passes, Check-in, the admin console) with all of the 4.0 track and every security fix to date. In it: person-to-person messaging with per-contact IDs and live stamps, delete for both and disappearing messages, "Proving it's you" (challenges, stamped media, an evidence locker), public credentials (mobile driver's licenses and EU digital IDs, with a trust store whose issuers' country and state come from the trusted list, never the document), a FIDO2 security key as a fourth recovery proof, and HumID Server for Windows 3.1 (updates signed by the HumID release key, backups encrypted to a key you keep offline, the keyshare kept apart). Security: PC-01 to PC-11 from the pre-certification assessment, plus CRD-01, CRD-02 and APP-05: an opened document must be the one your vault's own index names, and an ID's chip photo is re-made from the chip every time it opens. Messaging, credentials and the security key have their protocol code and tests in this release; their app screens come next.

## apps-session-duress

*@humid/mobile patch*

Duress and session fixes from the overnight review. Duress Practice and the Lock screen now recognise the taps with the same code, and the Lock screen waits for the tap window before it starts the check, so the rhythm Practice accepts is the one that opens the decoy view (APP-01); Practice says how far apart your taps were. A lock forgets everything the session showed, the search and filters included, through one reset that a test keeps complete (APP-07). A new recovery card survives a lock in memory only and comes back after a real unlock, never in a duress session, and closing it before you've checked it asks first (APP-02, APP-03). Leaving HumID while a check is running locks it; only the phone's own face or fingerprint prompt is excused (PC-17). A duress session's Activity is numbered without gaps and doesn't claim to be complete, its Duress screen lists the decoys, and its Recovery screen names no one (PC-16). The duress unlock for keyboards and screen readers is named for what it does and sits behind "More ways to unlock" (APP-06). Writes to this device's identity record no longer undo each other, so a duress setting saved during the public-log check stays saved (APP-11). Back closes the viewer's "Save a copy?" question before the viewer, and the question never carries to the next document (APP-08).

## att01-low-s

*@humid/attest minor, @humid/gate patch, @humid/mobile patch*

Liveness signatures are low-S only (audit ATT-01 / LIVE-03). `verifyLiveSig` now refuses the high-S form (r, n − s) of an ECDSA P-256 signature, so a captured sign-in, step-up, seal or admin approval can't be re-encoded into a second valid signature with a different proof hash. The native gate normalises whatever the Keystore or Secure Enclave returns to low-S before it leaves the app (`packages/gate/src/lows.js`), so apps and servers must be upgraded together: an older app's signature is refused about half the time. New exports `isLowS`, `ecdsaRS`, `P256_N`; `packages/attest/src/ecdsa.js` lists which ECDSA checks require low-S (HumID's own liveness keys) and which don't (mdoc, SD-JWT, passports, X.509, FIDO keys: their standards allow either form).

## creds-04-chip-issuer-label

*@humid/idscan minor, @humid/mobile patch*

A chip read on the phone no longer earns the green "Read from the chip" label (review finding CREDS-04). The phone checks the chip's files against the chip's own list of hashes, which a cloned or made-up chip satisfies, so `provenance` now gives such a record the level `chip-issuer-unverified` ("Read from the chip, issuer not verified on this phone"), shown in amber. The `chip` level needs a fresh issuer check passed as `provenance(rec, { chip: { ok, chain } })`; a failed one is `chip-mismatch`.

## creds-05-valid-document-basis

*@humid/creds minor*

`minimise(..., { share: ["valid_document"] })` no longer asserts `valid_document: true` from the expiry date alone (review finding CREDS-05). `true` now needs a revocation check that came back valid and a holder-bound credential; otherwise it's refused with `unchecked`, unless the caller passes `allowUnchecked: true`, and the claim then carries `basis.valid_document` (`expiry`, `revocation`, `holder`) inside its commitment. An expired, revoked or suspended credential is still simply `false`.

## creds-06-master-list-rollback

*@humid/creds minor, @humid/anchor minor*

Master lists only move forward (review finding CREDS-06). `readMasterList` now returns the list's signed `signingTime`; `applyMasterList` passes it to the store, and `setCscas(source, entries, { signedAt, sha256 }, { now })` refuses (`rollback`) a list signed before the one already applied for that source, one signed at the same time with different contents, or one with no signing time once one was seen, so replaying an older, still validly signed list can no longer drop CSCAs. A list dated more than a day ahead is refused; the same list again changes nothing (`unchanged: true`).

## creds-08-no-sha1-sod

*@humid/anchor minor, @humid/creds minor*

Passive authentication refuses a passport or ID card chip whose SOD uses SHA-1 (review finding CREDS-08): the data group hashes, the signer's digest or the signature algorithm. Doc 9303 has allowed only SHA-2 since its 7th edition (2015). For older, still valid passports a caller can pass `allowSha1: true` to `passiveAuth` or `verifyPassportChip`; the result then carries `weakHash: true` (and a note). The recovery service keeps the default, so a SHA-1 chip can no longer anchor or recover an account.

## crypto01-ledger-crosscheck

*@humid/audit minor, @humid/api minor, @humid/ledger-service minor, @humid/mobile patch*

The ledger page and the public log must describe one history (audit CRYPTO-01). `api.continuity({ head })` asks the log about the head of the page the phone verified and fails with `mismatch: true` unless the log holds that same seq and hash; `verifyLedger(page, { previousHead })` refuses a page that dropped or changed the head the phone confirmed last time, and `api.ledger({ previousHead })` links a page that starts later back to it through the new `GET /ledger/events?from=&to=` range (checked with the new `verifyBridge`). Activity shows a mismatch as a failed check. Release builds can carry the ledger key's fingerprint (`HUMID_LEDGER_KEY_FP`, logged by the ledger and printed by `deploy/setup.sh`), so a new install doesn't trust the first key it sees.

## crypto03b-internal-tls-hybrid

*@humid/svc minor*

Internal TLS between roles uses the hybrid X25519MLKEM768 key exchange only (audit CRYPTO-03 b): `serverTls` and `clientTls` set it on both ends, a peer offering X25519 alone is refused, and a split role won't start on a Node whose OpenSSL lacks the group. New export `INTERNAL_TLS_GROUPS`.

## crypto04-sessions

*@humid/htp minor, @humid/gateway-service patch*

Handshakes and the session table hold up under a flood (audit CRYPTO-04, SRV-25). `HtpServer.hello(wire, now, { group })` refuses a hello whose client nonce it has already answered (409 `replay`), lets each group (the gateway passes the client's IPv4 address or IPv6 /64) hold 20 sessions that haven't signed in, drops those after 2 idle minutes, and when the table is full evicts the least recently used unsigned session instead of answering `busy` to everyone. Frames refuse meta JSON over 64 KiB (`MAX_META_BYTES`, 413 `too_large`) before parsing it. Gateway: handshake, cosign and failed sign-in limits are per IPv4 address or IPv6 /64, and the limiters forget their least recently used key instead of clearing every counter at 100,000 keys (`Buckets` is exported).

## crypto05-index-rev

*@humid/crypto minor, @humid/store minor, @humid/api minor, @humid/vault-service minor, @humid/gateway-service patch, @humid/mobile patch*

Index entries can't be rolled back or moved (audit CRYPTO-05). `sealIndex(key, entry, { id, rev })` makes a v2 entry (`"HIX2"` prefix, AAD `"HUMID-INDEX-v2" ‖ lp(id)`, `rev` inside); `openIndex(key, blob, { id })` opens it only as that item's and returns its `rev` (v1 entries open as rev 0). The app picks each new item's id (`api.upload(…, id)`, header `x-humid-object-id`; the vault refuses a duplicate or a non-UUID-v4), re-seals every rename, pin and decoy change at a newer rev, and keeps the highest rev it has seen per item sealed on the device (`sealIndexRevs`, `store.putIndexRevs`). An older entry than that is shown as "Changed on the server" and its flags aren't believed. Existing v1 entries move to v2 the next time they are changed, never in bulk.

## crypto06-ticket-once

*@humid/htp patch*

A step-up ticket sends exactly one frame (audit CRYPTO-06). The ticket's sequence number is also the frame's AES-GCM nonce, so passing the same ticket to `call()` twice (a retry wrapper, a refactor) would have encrypted two requests under one key and nonce. The client now refuses the second use with `ticket_used` before anything is sent; a retry needs a new ticket and a new live check.

## crypto07-policy-floor

*@humid/htp minor, @humid/api patch, @humid/mobile patch*

A replayed older signed policy is never used (CRYPTO-07 round 2). `HtpClient.policySeen` holds the newest signed policy the client has accepted; `serverKeys()` uses whichever of it and the served one is newer (`policyReplayed`, `policyAt`), re-checking the stored signature. `verifyPolicy` takes `{ maxAgeMs }`. The app keeps `policySeen` in the identity record and hands it to the client at boot.

## crypto07-signed-policy

*@humid/htp minor, @humid/gateway-service patch, @humid/mobile patch*

The policy hint in `GET /htp/v1/keys` is signed (audit CRYPTO-07, PC-13, VAULT-04). `HtpServer.signedPolicy(policy)` returns `{ policy, policySig }`, signed with the server's static ML-DSA-87 key over `"HTP/1 policy" ‖ lp(kid, canonical JSON, at)` and cached for an hour; `HtpClient.serverKeys()` believes the hint only when it verifies under the pinned key and is under 7 days old (`server.policySigned`), and otherwise uses the strict defaults. New exports: `policyMessage`, `verifyPolicy`, `canonicalJson`. A pinned release app refuses to seal unsplit even on its first run. Older apps ignore the new field; a new app against an older gateway sees the strict defaults, so upgrade the gateway first.

## humid-4-1-p2p-live

*@humid/msg minor, @humid/api minor, @humid/htp patch, @humid/store minor, @humid/relay-service minor, @humid/access-service minor, @humid/gateway-service minor*

HumID 4.1 preview (non-production): person-to-person messaging in the app, under one rule: nobody interacts without a live check. Strict mode in @humid/msg (requests, acceptances and every message must carry a live stamp; anything without one is discarded unread and nothing it says is applied), stamps bound to their send time and counted once, the mutual "both here" state (live.js), "I'm here" receipts, one check per action (at most two stamps). New relay service (no accounts, no addresses, per-network daily quota); a separate stamp key and daily totals in access; /msg/keys, /msg/stats, /msg/stamp and the relay routes on the gateway (relay only from sessions that never sign in). Messaging is off unless the server turns it on (HUMID_RELAY_URL with Docker, HUMID_MESSAGING=on on Windows). See docs/MESSAGING.md.

## humid-4-credentials

*@humid/mdoc minor, @humid/sdjwt minor, @humid/creds minor, @humid/idscan minor, @humid/anchor minor*

HumID 4.0 (provisional): ask for and check public identity credentials. `@humid/mdoc` (mobile IDs, ISO 18013-5, ported from lane/core/mobile-id) gains online requests through the Digital Credentials API: ISO 18013-7 Annex C (`org-iso-mdoc`) with HPKE responses, OpenID4VP session transcripts, and ReaderAuth. New `@humid/sdjwt`: SD-JWT VC verification with key binding, the JOSE a verifier needs (JWS, x5c, JWK thumbprints, ECDH-ES JWE), and IETF Token Status List revocation (JWT and CWT). New `@humid/creds`: one request for every current browser and wallet (OpenID4VP DCQL + Annex C), one verifier and result shape across mobile licenses and IDs, EU PID (mdoc and SD-JWT), wallet photo IDs, passport chips (`@humid/creds/server`) and license barcodes, with an honest assurance level, revocation checks, minimised claims committed to a 4.0 persona, SSN structure checks and an eCBSV adapter for permitted entities. `@humid/idscan`: `applyMdoc`. `@humid/anchor`: `mdocAuth` and ICAO CSCA master lists (`readMasterList`). See docs/CREDENTIALS.md. Includes the fixes from the independent security review (2026-10-21): explicit issuer allowlists for keys without certificates, SD-JWT issuer bound to its certificate's SAN and country, VICAL signer / freshness / rollback checks, master list signer key usage and no SHA-1, photo ID country bound to its root, stricter mobile-ID and status-list chains, coded errors for hostile input, salted claim commitments, and Annex C HPKE info as plain CBOR (checked against @owf/mdoc).

## humid-4-delete

*@humid/msg minor*

Delete, built in: delete a message for yourself or for both of you (only your own messages on the contact's phone); unsend at the relay before delivery; a delete for an undelivered message destroys the contact's key for it, so a kept copy can never be opened; disappearing messages (30 s to a year); delete a whole conversation and its keys, for you or for both; cancel an invite or withdraw a request. The message history is re-sealed under a new key on every save, so deleted messages can't be recovered from storage. Superseded ratchet states are now overwritten. See "Deleting" in docs/MESSAGING.md.

## humid-4-messaging

*@humid/msg minor*

HumID 4.0 (provisional): new module for person-to-person messaging between HumID holders. Per-contact persona IDs (unlinkable across contacts), invites sealed under the invite secret, contact approval with a live check, hybrid ML-KEM-1024 + X25519 handshake dual-signed with ML-DSA-87 and SLH-DSA-SHA2-256f, a hybrid post-quantum double ratchet, blind live stamps (a live human approved this message, unlinkable to the account), fixed-size padded wire objects on daily-rotating mailboxes, a relay contract with IPv6 /64 rate keys, rollback-proof sealed state, drop detection and a swappable crypto backend for the platform's constant-time code. See docs/MESSAGING.md.

## humid-4-prove-its-me

*@humid/msg minor*

HumID 4.0 (provisional): proving it's you against cloned voices and deepfakes, without HumID ever handling biometrics. "Is this really you?": a contact sends a challenge over the pinned conversation; the real holder answers yes or no with a live check, and on a yes both phones show a 40-bit spoken code to read aloud on the call (verdicts confirmed / denied / unverified / expired; a duress answer is never confirmed). Stamped media: a `media` message kind whose live stamp covers the bytes, and a portable media credential dual-signed (ML-DSA-87 + SLH-DSA-SHA2-256f) by a public persona plus a live stamp. Evidence locker: voice and photo originals sealed on the device under a key from the account seed, opened after a live check, and released with a signed, stamped, expiring release statement. Nothing compares one voice or face with another. See docs/MESSAGING.md, "Proving it's you".

## humid-4-security-key

*@humid/fido minor, @humid/recovery minor, @humid/api minor, @humid/svc patch, @humid/recovery-service minor, @humid/gateway-service minor, @humid/ledger-service minor, @humid/mobile minor*

HumID 4.0 (provisional): a FIDO2 security key as the fourth recovery proof. New module `@humid/fido` (CTAP 2.1 over NFC on any APDU transport: canonical CBOR with limits, command and response chaining, NFCCTAP_GETRESPONSE, PIN/UV auth protocols 1 and 2, `hmac-secret`, `credProtect` level 3, a relying party no website can claim). The account seed gets a fourth part (x = 4) locked under the key's PIN-gated `hmac-secret`; the recovery service counts a key only when the key itself signs a fresh challenge with its PIN verified, refuses counters that go backwards (copied keys), and withdraws a removed key (or a replaced card) from recoveries under way. App: You → Recovery → Security key (name, PIN, one tap, one live check), Prove it's me → Security key, Activity events. No biometric is stored anywhere. See docs/SECURITY-KEY.md.

## ledger-scale

*@humid/ledger-service minor*

The ledger scales with its log (crypto review, efficiency). The tree size is one indexed lookup instead of `COUNT(*)` over every leaf on every write; reading the history re-uses the account's signed head until it moves or is an hour old, instead of an ML-DSA-87 signature per read; and the public log signs at most one checkpoint per `HUMID_TLOG_CHECKPOINT_MS` (default 5 s), not one per entry, pruning superseded uncosigned ones after an hour. An inclusion proof for an entry newer than the latest checkpoint waits for the next one.

## link-check-v2

*@humid/recovery major, @humid/api patch, @humid/recovery-service patch, @humid/gateway-service patch, @humid/mobile minor*

Codes a server can't precompute (CRYPTO-08).

- The match code for adding a device is `accountCheck(account, linkKemPk, linkXPk)` (`HUMID-ACCOUNT-CHECK-v2`). It commits to the new device's link keys, not just the public account id, so it can't be ground ahead of time. Breaking: `accountCheck` now needs the link's keys.
- Recovery-request codes have 16 characters (80 bits), because they live up to a week. Link, witness and admin codes keep 12 (60 bits). `parseCode`, QR codes and the gateway routes accept both lengths.

## live01-android-peruse

*@humid/gate minor, @humid/mobile patch*

Android: the seed-unwrap secret opens only inside a prompt HumID asked for (audit LIVE-01, humid-gate 2.1.0). The gate's `release` may now return `handle`, a replacement for the one passed in (a 2.0 time-bound key moved to a per-use key); the app stores it at once (`withKeys`). Needs a device to confirm.

## live02-revocation

*@humid/attest minor, @humid/identity-service minor*

Attestation revocation that works in Docker, and fails closed (PC-14 / LIVE-02 / SRV-33). `revocationList` reads a copy another process fetched (`file`) as well as fetching one itself (`url`), and `required` now also refuses a copy older than `maxAgeMs` (48 h, `status_stale`), not only a missing one. New `fetchStatusToFile` / `runStatusFetcher` / `readStatusFile`: the identity image runs as an `attestation-status` sidecar (`server.mjs status-fetch`), the only container with a route out, which writes Google's list to a volume identity reads (`HUMID_ATTESTATION_STATUS_FILE`). `HUMID_ATTESTATION_STATUS_REQUIRED` defaults to 1 for the attested policy (unset = by policy; 0 = explicit opt-out).

Identity logs one `live-human posture` line at start, a warning naming every weakened setting (LIVE-04), and refuses to start with `HUMID_ANDROID_ALLOW_ANY_SIGNER=1` and the attested policy unless `HUMID_INSECURE_TEST=1`.

## live06-keys-gone

*@humid/api minor, @humid/identity-service minor, @humid/gateway-service minor, @humid/ledger-service minor, @humid/mobile patch*

The server learns when a device's biometric keys are gone (audit LIVE-06). When Android or iOS destroys them (fingerprints or face changed, HumID reinstalled), the app reports it with `HumidApi.reportKeysGone({ id, device })` (`POST /auth/key-invalidated`, no sign-in: there's nothing left to sign with). Identity marks the device `needsSetup` in `/me` until its next live sign-in; the ledger records `device.keys_invalidated` (new event type, at most once a day per device) and Activity shows it. The answer is the same whether or not the account or device exists; a signed-in session can report only its own account's devices; a duress session sends nothing.

## msg-live-rule-fixes

*@humid/msg minor, @humid/api minor, @humid/htp patch, @humid/svc patch, @humid/relay-service minor, @humid/access-service minor, @humid/gateway-service minor*

Messaging review fixes (4.1 preview). Stamps only for a hardware-proven phone, whatever the device policy (MSG-03). Hourly stamp keys: the issuer signs only with this hour's key and phones count a stamp only for a time inside its key's hour, so stamps can't be stockpiled (MSG-01); request stamps cover their time; a stamp under a key not fetched yet waits for a refetch instead of being discarded (MSG-07). Delete-for-both stamps and encrypts everything before erasing, works in steps within the 2-stamps-per-check cap, and each conversation keeps its unposted messages in its own sealed save (PC-28). Backfill after days away and missing-message notices (MSG-04); a relay session per deposit and per conversation, no "tomorrow" in polls (MSG-02). Relay limits that never fail closed, quotas per IPv4 /24 and IPv6 /32, fair share near full (MSG-05). One person per invite (PC-26). Safety-code "Different" everywhere, approval that doesn't spend the invite on failure, request-flood handling, stamped challenges (MSG-06/08/09/11). Stamped media and releases verify against retired stamp keys (MSG-10). Quiet relay and issuer logs, thresholded /msg/stats, sealed outbox records, honest copy (MSG-13). New settings: HUMID_STAMP_EPOCH_MINUTES (60), HUMID_STAMP_ACCEPT_DAYS now defaults to 15, HUMID_RELAY_MAX_BLOCK_BYTES_DAY, HUMID_RELAY_FAIR_ABOVE, HUMID_MSG_STATS_MIN. HUMID_STAMP_ISSUE_DAYS is gone. See docs/MESSAGING.md.

## pc01-duress-in-signin

*@humid/htp minor, @humid/api minor, @humid/identity-service patch, @humid/gateway-service minor, @humid/mobile patch*

Duress is reported inside the signed sign-in, never as a request of its own (audit PC-01). New `loginPresenceMessage(th, id, challenge, d)`: the liveness key signs the plain challenge, the device key (released by the same live check) signs it with the duress flag. `api.login`'s `sign` callback now gets `{ presence }` and may return `d`. The gateway ignores the flag in `POST /auth/presence`, so a bare request from a signed-in session can no longer lock down an account or erase an armed Check-in vault. Apps older than this release no longer signal duress and should update.

## pc02-enrol-evidence

*@humid/api minor, @humid/gateway-service minor, @humid/identity-service minor, @humid/recovery-service minor, @humid/mobile patch*

A device joins an account only with evidence (audit PC-02): a link one of the account's devices approved for that exact device key (`startLink({ devicePk })`, `enrollDevice({ linkCode })`; single use), or a released recovery of the same route. The account seed alone no longer lets a phone in, and `via: "register"` is refused on `/auth/device`. Links without a device key are refused (`update_required`). New internal routes: recovery `POST /internal/links/:code/consume|restore`, `POST /internal/requests/:id/check`; identity `GET /internal/devices/:id`, `POST /internal/devices/:id/revoke`.

## pc03-pc04-trust-pins

*@humid/crypto minor, @humid/audit minor, @humid/api minor, @humid/mobile patch*

What a malicious server can't make the phone believe (audit PC-03, PC-04). `open(envelope, keys, { signer })` refuses an envelope signed by anyone but `signer` (`wrong_signer`); the app's read path passes the account key, so a server can't plant a forged document. `verifyCheckpoint` counts only cosigners from a `cosigners` map (new `parseCosigners`), checked under the built-in key, never one the server sends; the app builds the list in from `HUMID_TLOG_COSIGNERS` and pins the ledger key it first verifies (`ledgerKeyFp`).

## pc08-bound-assertions

*@humid/svc minor, @humid/gateway-service patch*

Internal assertions are bound to one request (audit PC-08): `signRequestAssertion(sk, claims, { method, path, body })` signs the method, target and body hash in, and `createService` refuses an assertion on any other request or a second time (by `rid`). A captured assertion can no longer be replayed or turned from a read into a delete. Services and gateway must be upgraded together.

## recovery-epochs

*@humid/recovery minor, @humid/api minor, @humid/recovery-service minor, @humid/mobile minor*

Recovery pieces rotate (CRYPTO-02). Before, every piece sat on one fixed line through the seed, so two removed witnesses plus any current piece rebuilt it.

- An account's recovery epoch is part of its signed recovery-mode statement. `quorumParts(seed, epoch)` parts carry `epoch`, and the card and key AAD and the witness share carry it too from epoch 2 on. `combineQuorum` refuses to combine parts from different epochs.
- Signing a new epoch ("Make new recovery pieces" on the Recovery screen, and every mode switch) makes the recovery service delete every stored piece from older sets and cancel any recovery under way. It also refuses new pieces for an older set (`stale_epoch`), or with no epoch once the account is past epoch 1 (`update_required`).
- `setCard`, `setContacts`, `addKey` and `setAnchor` take an `epoch`. Released recoveries say which `epoch` their pieces are from.
- The app no longer says a removed witness's or card's piece "no longer works". It says the piece no longer counts on this server, and that new pieces stop it fitting anything new. Two old pieces still fit each other, because the account seed doesn't change (V74-04).

## recovery-holder-proofs

*@humid/recovery-service minor, @humid/gateway-service patch, @humid/identity-service patch, @humid/svc patch, @humid/htp minor, @humid/api minor, @humid/mobile patch*

The recovery service checks the holder's own proof (audit SRV-30 follow-up). Every route that changes or releases recovery material verifies the holder's step-up itself, against the device key identity vouches for and against the body it received, once. That covers seal card, contacts, anchor, security keys, settings, link approval, a witness's help, cancelling, station verification and the new `DELETE /escrow` the gateway uses on account close. The setup recovery card is signed by the account key in the registration's live check (`setupCardMessage`), and identity issues a short-lived `created` statement for a new account. The recovery service needs `HUMID_CORE_STATEMENT_PK`. `holderProofs().check` takes the received `body`.

## recovery-mode-chain

*@humid/recovery major, @humid/api patch, @humid/identity-service minor, @humid/recovery-service minor, @humid/gateway-service minor, @humid/mobile minor*

The recovery mode can't be deleted or rolled back below what each device has seen (V74-01, V74-02).

- Each mode statement now names the hash of the one before it: `recoveryModeMessage(account, mode, version, epoch, prev)`. Version 1 names `RECMODE_GENESIS`. `followsMode` decides whether a statement may replace another.
- Identity accepts only statements that follow its own and is the source of truth.
- The recovery service keeps a high-water mark that only goes up. A missing, older or forked row reads as holder-only.
- Before every recovery route, the gateway brings whichever service is behind up to the newest statement (`syncMode`). Recoveries started on a stale row are refused.
- The phone pins the newest statement it has checked (`modePin`, in its sealed identity record, written through `core/identity.js` `updateIdentity`). It also checks the served statement against identity's copy and the ledger's latest `recovery.mode_set`. A missing, lower or forked statement makes it warn and act as holder-only: it makes no recovery piece.
- A device that joins by link gets the approving device's pin inside the sealed hand-over.

Breaking: version 2 and later statements need `prev`.

## recovery-mode-pin-monotonic

*@humid/mobile patch*

The recovery-mode pin only goes forward (V74B-03).

- `core/identity.js` `updateIdentity` never writes a record whose `modePin` is at a lower version or epoch than the stored one, or that has none. A writer working from an older copy keeps its own change, but the pin stays where it was.
- `interrupt.js` `keepGateHandle` (a gate that moved its secret to a new key, LIVE-01) now writes through `updateIdentity`, instead of putting back the record as it was when the live check began. No module in `core/` writes the identity record itself any more.
- Also: `withKeys` called `gateLabel` without importing it (a regression from the one-vocabulary change), so every live check threw `ReferenceError: gateLabel is not defined`. Fixed.

## recovery-mode-vouched

*@humid/mobile minor, @humid/identity-service patch, @humid/recovery-service patch, @humid/gateway-service patch*

A phone makes recovery pieces only for a recovery choice it can vouch for itself (V74B-01).

- `mayMakePieces` now needs the shown hardened statement to be `vouched`: equal to or after this phone's pin, or the pin it got from the device that added it, or (on a phone recovered with two-proof pieces and no pin yet) hardened at exactly the epoch of the pieces it combined. `judgeMode` takes that floor; `finishJoin` stores it as `modeFloor` (`recoveredEpoch`).
- A signed statement the phone can't vouch for (no pin and no floor, or an older server with no modes) is shown but never pinned, and `partOf` refuses with the reason. Recovery and Protection ask the holder to **Check and confirm**. `confirmModeHere` shows the mode history from the verified ledger, then signs the next statement under a live check and pins it.
- `loadRecoveryMode` loads the ledger itself when this session hasn't verified a page, and refuses a statement when the ledger's `recovery.mode_set` at the same version names a different one.
- `recovery.mode_set` ledger entries now carry `hash`, the statement's `recoveryModeHash`. Identity's and the recovery service's `POST /internal/recovery-mode` return it.
- A cosigned public-log checkpoint is not counted as a vouch: it proves an entry is in the log, not that nothing newer exists. docs/RECOVERY.md "When a phone makes recovery pieces" states the rule and the per-device limit that remains.

## recovery-modes-app

*@humid/mobile minor*

Setup now asks "If you lose every device" before the first check. The choices are "A safe way back in" (recommended, and selected) and "Only my own devices". Holder-only skips the recovery card, signs the mode into registration, and asks for a second device straight away. Protection then counts devices only, and warns while the account has just one. The Recovery screen shows the mode, checks the server's statement against the account key, and switches modes; switching to holder-only deletes every proof first, each with its own check. For a holder-only HumID, the join screen offers only the device link. Activity names `recovery.mode_set`.

## recovery-modes

*@humid/recovery minor, @humid/api minor, @humid/identity-service minor, @humid/recovery-service minor, @humid/gateway-service minor, @humid/ledger-service minor*

Two recovery modes, chosen at setup (docs/RECOVERY.md#two-recovery-modes). **Holder-only**: only the holder's own enrolled devices open anything. No card, witnesses, ID anchor or security key is ever stored, and the recovery service refuses every escrow write and every recovery for the account. **Hardened**: two proofs, a wait and a veto, as before. The mode is a statement signed by the account key (`recoveryModeMessage`: `HUMID-RECMODE-v1 ‖ lp(account, mode, version, epoch)`). It is kept by identity (shown in `/me`) and by recovery (`GET /recovery/mode`), checked again on every escrow route, and recorded as `recovery.mode_set`. A stored statement that no longer verifies counts as holder-only. Switching: `POST /recovery/mode` with a step-up. Switching to holder-only is refused (`escrow_remains`) until every piece has been deleted, each one under its own step-up; `DELETE /recovery/keys` (all keys) is now reachable through the gateway. Accounts with no statement on file are hardened. (Superseded by `recovery-mode-chain.md`: the statement gained `prev`, and a missing or older row below the recovery service's high-water mark reads as holder-only. A phone makes no piece for a version-0 "hardened" it can't vouch for, `recovery-mode-vouched.md`.)

## review-2026-10-23

*@humid/identity-service patch, @humid/gateway-service patch, @humid/recovery-service patch, @humid/htp patch, @humid/svc patch, @humid/mdoc patch, @humid/mobile patch*

Fixes from the full code review of 23 October 2026, each with a regression test that fails on the old code.

- **SRV-01 (Critical):** `/auth/register` no longer adds a new device to an existing account. A copy of the account seed alone used to enrol a thief's attested phone with no approval, wait or alert, which then opened every document, split ones included. Registration on an existing account now succeeds only for a device already enrolled there (a lost-answer retry); a new device joins only through an existing device's approval or a completed recovery (`409 identity_exists` otherwise).
- **CRYPTO-01 (High):** a reply is never sealed for a session dropped while its request was in flight. `drop()` wiped the keys in place, so the reply went out under 32 zero bytes, readable by anyone on the path. Dropped sessions are marked dead, their keys are cleared, `seal` refuses them, and the gateway answers `session_unknown` in the clear with no content.
- **SRV-02 (High):** every multi-statement write in the recovery service goes through `db.tx`, which always commits or rolls back. A clashing card tag used to leave the single connection inside an open transaction and wedge recovery writes for every account until a restart.
- **CRED-01 (High):** a mobile ID's device signature is checked only against this session's own DeviceAuthentication. A signature captured by another relying party, with its old payload attached, used to pass as `issuer+holder`.
- **appui NEXT-01 (High, regression):** the ID camera is its own modal layer, and the newest layer is never left inert, so the shutter, Close and Photo buttons work again when the camera opens with its step.
- **DEPLOY-02 (Medium):** the Windows admin console shows server-written numbers only as numbers, so a compromised server can't inject markup into the SYSTEM console.

Also: Dependabot groups updates into one pull request per ecosystem per week, covers every Rust crate, and leaves major versions for a deliberate upgrade.

## revoked-android-test-key

*@humid/attest patch*

Refuse Android liveness keys from apps signed with the leaked test key (`tools/android-test.keystore`, certificate SHA-256 `b066cd45…928c`), even when a server lists it in `HUMID_ANDROID_CERT_DIGESTS` or sets `HUMID_ANDROID_ALLOW_ANY_SIGNER=1`. New export `REVOKED_ANDROID_CERTS`; new error code `revoked_signer`.

## srv24-signin-oracle

*@humid/identity-service patch, @humid/gateway-service patch*

Sign-in no longer tells an unknown account, an unknown device and a wrong key apart (audit SRV-24): all three are `401 bad_proof` with one message, after the same signature check (a throwaway key stands in for a device that doesn't exist), and the ledger note for a real account is written after the reply. A closed account or a removed device is still named, but only to a caller who has just signed with that device's own key.

## srv30-holder-proofs

*@humid/svc minor, @humid/htp minor, @humid/api minor, @humid/gateway-service minor, @humid/vault-service minor, @humid/keyshare-service minor, @humid/identity-service minor, @humid/ledger-service minor, @humid/mobile patch*

The gateway's internal key alone no longer releases or deletes anything (audit SRV-30 / H-1, with CRYPTO-03 a).

- Vault, keyshare and identity check the holder's own step-up proof (the device key's ML-DSA-87 signature over the exact request, and the liveness key's) against the device keys identity vouches for, once each, instead of trusting `claims.stepUp`. New `@humid/svc/holder` (`holderProofs`, `checkReceipt`) and `signStatement`/`verifyStatement`/`newStatementKeys`.
- The open is written to the ledger first; the vault releases an envelope only against the ledger's signed receipt for it.
- Check-in: the vault's sweep delete needs keyshare's signed erase token; a duress erase needs the duress sign-in itself, checked by keyshare and acted on once.
- Split-document keys travel sealed (ML-KEM-1024 + X25519) to a one-time key the phone puts in the body it signs (`shareReceiver`/`sealShare`/`openShare` in `@humid/htp`), so the gateway forwards ciphertext only. Older apps get `426 update_required` for split documents.
- New settings: `HUMID_CORE_STATEMENT_SK`/`_PK` (identity, ledger) and `HUMID_KEYS_STATEMENT_SK`/`_PK` (keyshare). `deploy/setup.sh` adds them to an existing `.env`; `humid init` adds them on Windows; `humid pki issue` carries each role's own to its machine. Services and gateway must be upgraded together.

## srv32-route-body-caps

*@humid/gateway-service patch, @humid/htp patch*

Per-route body caps (audit SRV-32, the SRV-25 residue). A signed-in session's frame may still be as large as a vault upload, but once it is open the gateway holds the body to the route's own cap before anything parses it: 64 KiB for JSON and control routes, a few hundred KiB for recovery routes that carry envelopes or ID-chip reads, the full `GATEWAY_MAX_CALL_BYTES` only for `POST /vault/objects`. HTP frame meta is capped at 64 KiB (`MAX_META_BYTES`), since it is parsed before the route is known.

## srv34-recovery-flood

*@humid/recovery-service patch, @humid/gateway-service patch*

Anonymous recovery requests are bounded (audit SRV-34): the gateway lets one network (IPv4 address or IPv6 /64) start `HUMID_RECOVERY_STARTS_PER_HOUR` (20) an hour; the recovery service keeps at most `HUMID_RECOVERY_MAX_UNBOUND` (20,000) requests with no proof yet and refuses more as busy; and one that gets no first proof within `HUMID_RECOVERY_UNBOUND_TTL_MS` (24 h) ends and is deleted, instead of staying a week.

## ux-a11y

*@humid/mobile patch*

Accessibility. Every layer that takes the screen (a sheet, a pushed screen, the document viewer, the live-check overlay and the chip reader) is modal now: focus moves into it, Tab and Shift+Tab stay inside it, everything behind it is `inert`, and focus goes back to what opened it when it closes (APP-12). Welcome and Lock have an h1 (the wordmark); section headings under a screen's title are h2, styled as before; the viewer's header is no longer a second page banner. In the light theme mint text is darker (#0E6B47), so it meets 4.5:1 on its own wash over every surface (the active filter chip was 4.26:1). Segmented controls, the search field and "More filters" are 44 px like every other control. The type comment no longer claims iOS Dynamic Type works without code.

## ux-first-paint

*@humid/mobile patch*

A lighter start. Setting up, joining, recovery and the operator tools (`core/enroll.js`, `join.js`, `recovery.js`, `recmode.js`, `seckey.js`, `operators.js`, with `@humid/recovery`'s app-side code) moved behind a second kernel barrel, `core/setup.js`, that loads with the screens that use it; the first paint keeps only recovery alerts and the kept recovery card (`core/alerts.js`). First paint of a release build: 311 KB → 276 KB raw (117 → 107 KB gzip). Boot reads the gate probe, the identity record, the wallet and the offline copy at the same time. The viewer's "Open for N s" line ticks on its own instead of re-rendering the document every second, and Activity describes its entries once per page. The web favicon is a 2.4 KB vector of the same mark (was a 55 KB trace).

## ux-honest-copy

*@humid/mobile patch, @humid/gateway-service patch*

Honest copy (overnight review). Welcome, Lock, How HumID protects you and Protection say the live-check promise only as strongly as the device can keep it: "its secure chip signs each one" on a phone, "no secure chip signs it" on a computer, and the web app says where it holds. The sealed toast no longer says only your face or fingerprint can open a document. Activity describes each proof by what the server recorded with it, the device that made it and how strongly that device proves its checks, and says "signed by one of your devices" for older entries (APP-09); the gateway now records `assurance` and `by` (the proving device) with every step-up event. README, SECURITY.md and ARCHITECTURE.md drop "zero knowledge" and "seal card", state both recovery modes, and say what a live check does and doesn't prove.

## ux-one-vocabulary

*@humid/mobile patch*

One word per concept. The biometric act is a "live check" everywhere (no bare "check", "fresh check" or "face or fingerprint check"), the people are "witnesses" (Activity said "older contacts"), and a duress unlock is "the duress gesture". The recovery proof count is one sentence on setup, Protection and Recovery ("any two of your four kinds of proof"), and the card says it is one proof of two. The gate-method, device-joined and recovery-method names live once, in `ui/labels.js`.

## ux-spacing

*@humid/mobile patch*

Spacing on the token grid. The screens' 190 inline `style={{ marginTop: N }}` become `mt-N`/`mb-N` utility classes mapped to `--s-1…--s-8`, and the off-grid margins (6, 10, 14, 18, 22 px) snap to the nearest grid step, so gaps between cards are even. Each moves by at most 2 px. The Recovery screen no longer says the proof rule twice.

## v3-2-0-integrate-4

*@humid/mobile minor*

**Apps 3.2.0: the 3.x apps now carry the HumID 4.0 foundations.** The 4.0 track (person-to-person messaging, `@humid/msg`, and public credentials, `@humid/mdoc` online requests, `@humid/sdjwt`, `@humid/creds`, with the fixes from their independent reviews) is merged onto the 3.1.1 apps. Nothing changes on screen yet: the new modules are provisional and not wired into any screen (`NOT_SHIPPED` in `tools/affected.mjs`), so the apps behave exactly as 3.1.1 does. This release puts every line of work on one base, so the next screens (Messages, Add from a wallet) build on what's published. See docs/MESSAGING.md and docs/CREDENTIALS.md.

## v3-app

*@humid/mobile major*

**HumID 3.0: the app, rebuilt from the ground up.** One kernel of small modules (`core/`, one public surface in `core/index.js`) instead of a 2 100-line controller; the official brand carried as meaning (amber = a human action, mint = verified, nothing else coloured); the system typeface (no font files, the OS text size applies, four in-app steps to 175 %); a first paint that carries only Welcome, Lock and the Vault, every other screen a chunk loaded when needed; nothing animates and no timer runs unless a person did something or a check is running. The full spec is `docs/V3.md`.

What a person notices: the no-password promise said first on Welcome and Lock; camera-first Add with a picker that remembers the last kind; forms and captured ID sides survive a lock; duress is a triple-tap by default with a practice mode; You is a hub with pushed detail screens; Close & erase is under About › Advanced behind a typed CLOSE; Activity verifies in one plain line; "Check-in" is **Heartbeat** and "account check" is a **match code** (*check* means the biometric only); the location stamp is opt-in and coarse; Save a copy has its own check and is in the ledger; the "can't reach your vault" strip never covers a title.

Security in the client: unauthenticated transport errors can no longer steer identity state or delete the offline copy; the sealed duress setting is a fixed size and a missing one reads as tampering; results that land after a lock are wiped (session epoch); a compiled server pin always wins; a split-keys ratchet; index entries padded to 64-byte buckets; marking an item for the decoy view needs a live check; QR codes read by the bundled zxing-cpp reader (`jsqr` removed); every file under `/assets/` content-hashed and immutable, the shell `no-cache`, the service worker precaching by hash. The SIMD Tesseract core is used where the WebView supports it.

Carries 2.2.0 forward: cards, licenses, ID cards and passport pages are a guided scan with a fixed outline and plain-word guidance, taken by itself as a still cut to the outline; the picker's ID entry asks which ID it is so the right outline is drawn; the review opens before the clean scan is made, and sealing warms up and reads the location in parallel.

## v3-camera-crop-focus-cvv

*@humid/mobile patch*

**The photo is the document, and it focuses with a hand that isn't still.**

- **Cut to the document.** A card, license, passport page or sheet of paper is cut out of the frame's crop by its own edges (the same measurement the live guidance makes, refined by the corner finder) and straightened at its proportions, so the kept picture is the document filling the whole frame, with no table round it. When the edges can't be told it falls back to the frame itself, without the margin. If the cut-out doesn't read, the uncut crop is read too.
- **Focus.** Where the camera offers zoom, cards are scanned at 2x and passport pages at 1.5x, so the phone is held about twice as far away: most phones can't focus on a card that fills the frame at 1x (it sits closer than their minimum focus distance). The camera is asked to focus on the frame from the start, and again sooner when it stays blurred. Where there's no zoom and it never comes sharp, the frame gets smaller after 2.6 s and says why ("Too close for the camera to focus"). The photo no longer waits for the hand to be still: it's taken at the sharpest lined-up moment (a 0.3 s hold, sharp near the peak of the last 1.2 s, only clear movement holds it back), and without a full-resolution still the sharpest of three frames is kept.
- **The security code.** After a card's number is read, from the front or a chip tap, the back's camera opens by itself for the security code (card chips never give it out, by design), with Skip. The back is read whole and, if the code isn't found, its signature-strip band enlarged; the camera says the code was read (masked) before moving on.

## v3-camera-full-view

*@humid/mobile patch*

The guided camera asks for the long side only, so a portrait phone no longer loses the top and bottom of the document in the preview (a width and a height together make a browser cut the frame to that shape); if the preview still comes back turned the wrong way for the screen it asks once more with both sizes. The shaky-camera test fixture has 16 distinct views, so the stability test cannot pass or fail on two equal frames by chance.

## v3-camera-rebuild

*@humid/mobile minor*

**The document camera, rebuilt around what the person needs to know.** The frame stays fixed (the crop never moves), and now: a lock box inside it follows the document the camera actually sees and settles onto the frame when it's lined up; one instruction and a row of live chips (Framed · Sharp · Steady · Light · Barcode / ID lines) sit right under the frame instead of 200 px below it; problems are said after 0.35 s (not up to 2.2 s) and good news at once; a ring fills round the frame as it holds still.

A license's barcode and a passport's lines are now **read live**, the moment they're in the frame, so the photo is taken when the details are in rather than read (or missed) afterwards. The photo freezes in the frame with a flash, and before moving on the camera **says back what it read** (name, date of birth, number, expiry, city; a card's brand and last four). When something had to be read and wasn't, it says so plainly with Try again or Keep the photo — no silent retry loop. A license back held up for the front is read and kept as the back. Tap the picture to focus; a blur while lined up asks the camera to focus again. `core/capture.js` replaces `core/scanflow.js`.

## v3-crypto

*@humid/crypto minor*

Vault-index entries are padded to 64-byte buckets before sealing (`sealIndex`), so the size of a sealed entry, and the size change when one is re-sealed for a pin or a decoy flag, says nothing about what it holds. `openIndex` strips the padding; entries sealed by earlier releases still open.

## v76-02-signin-revocation

*@humid/attest minor, @humid/identity-service minor, @humid/gateway-service patch*

Google's attestation revocation list and the 48 h staleness rule apply at every sign-in, not only at enrolment (V76-02). `verifyLiveKey` returns the chain's certificate `serials`; identity keeps them with the device (`att_serials`) and checks them on every `/internal/verify`. A listed certificate removes the device (`attestation_revoked`, recorded as `device.removed`); a missing or stale list under a required policy refuses the sign-in (503 `status_unavailable` / `status_stale`); an Android device enrolled before serials were kept is refused with `reattest_required` under a required list.

## v76-03-shared-address

*@humid/gateway-service minor, @humid/htp minor, @humid/api minor*

A visitor can't lock every holder out when the proxy can't name visitors (V76-03, Windows behind Tailscale Funnel with `HUMID_TRUST_FORWARDED=off`). When the forwarded address is the proxy's own loopback address, handshakes share a server-wide ceiling (`sharedHelloPerMin` / `HUMID_SHARED_HELLO_PER_MIN`, 600 a minute) instead of 30 per address, failed sign-ins count per identity and server-wide only, and in-flight bodies only against the server-wide cap. Every sign-in returns a one-use `helloPass` (`sessionView`); `HtpClient` sends it with its next handshake (`x-humid-hello-pass`), which skips every handshake limit, and `HumidApi` keeps it (in memory, and in `localStorage` where there is one, per server), so unlocking and checking in always get through.

## vault08-station-wildcard

*@humid/recovery-service patch*

`HUMID_STATION_ACCOUNTS="*"` (every account is a verification station) is refused at start-up unless `HUMID_ALLOW_ANY_STATION=dev` is also set, and logs an error line when it is (audit VAULT-08). Local dev servers set the flag; a production server can no longer become an every-account station by one setting.
