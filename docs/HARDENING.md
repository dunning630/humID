# Hardening against camera/input injection and device compromise

The rule: nothing from the camera, the app's own UI or the phone's OS is trusted on
its own. The server accepts only (a) signatures from the hardware liveness key, made
after a live biometric, and (b) signatures from an ID chip or its country's chain.

This file is the audit against that rule (October 2026), item by item, and where
each item stands. **Status:** ✅ fixed · ◑ partly, with what's left · ⬜ open ·
➖ already met · 🔒 needs a real device to confirm.

## P1 — Hardware key: one live biometric, one signature

| Item | Where | Before | Now |
|---|---|---|---|
| Android liveness key: biometric-strong only, per use (timeout 0), invalidated by new biometrics, attestation challenge | `plugins/humid-gate/android/…/HumidGatePlugin.kt:220-243` | Already so | ➖ |
| `setUnlockedDeviceRequired(true)` | same, liveness key and secret key | Missing | ✅ |
| StrongBox preferred, TEE fallback recorded | `:234-242`; server records `level` and now `keymasterLevel` | TEE/StrongBox recorded from one level only | ✅ |
| Signing only inside `BiometricPrompt` success with `CryptoObject(Signature)`, `BIOMETRIC_STRONG` only, no device credential | `:313-354`; device-credential results rejected at `:325` | Already so | ➖ 🔒 |
| The 32-byte secret key (AES-GCM) is usable for 3 s after the same check | `:247-268` (`SECRET_WINDOW_S`) | By design: one prompt can unlock one `CryptoObject`, which is the liveness `Signature` | ◑ documented; the server never sees this key |
| iOS: Secure Enclave key, `.privateKeyUsage + .biometryCurrentSet`, `WhenPasscodeSetThisDeviceOnly`; no `.userPresence`/`.biometryAny`/`.devicePasscode` | `HumidGatePlugin.swift:344-349` (`createLiveKey`) | Already so | ➖ 🔒 |
| iOS: fresh `LAContext` per operation, reuse duration 0, action in `localizedReason` | `:298-308` | Fresh context; reuse duration not set explicitly | ✅ |
| Desktop: biometric only, no Windows Hello / PIN; server default `attested` (phones only) | `plugins/humid-gate/src/desktop/*`, `services/gateway/src/server.js:154` | Already so | ➖ |
| **Release builds:** Android was published as a `--debug` APK (debuggable, WebView remote debugging on, cleartext allowed, logs to logcat), signed with a key committed to the repo | `.github/workflows/release.yml`, `tools/android-test.keystore` | The worst finding | ✅ release key required, debug path removed, APK checked (signer, not debuggable), committed key deleted |

## P1 — Server: verify attestation strictly

| Item | Where | Before | Now |
|---|---|---|---|
| Chain to pinned Google roots | `packages/attest/src/android.js` | Yes | ➖ |
| Every certificate above the leaf in date; every issuer a CA | same | Intermediates' dates only; no CA check | ✅ (leaf dates left out, as Google's verifier does: devices set them unreliably) |
| Google's revocation/status list | `packages/attest/src/status.js` | Never fetched | ✅ refreshed every 6 h; `HUMID_ATTESTATION_STATUS_REQUIRED=1` refuses until fetched |
| Both security levels TEE or StrongBox; Software refused | `android.js` | `≥ 1` (so KeyMint's `100` passed) | ✅ allow-list {TEE, StrongBox} for both |
| Verified boot, locked bootloader | same | Yes (`HUMID_REQUIRE_LOCKED_BOOT`, default on) | ➖ 🔒 rooted-phone test |
| Biometric-only auth type, no `noAuthRequired`, timeout 0 | same | Yes | ➖ |
| Purpose SIGN | same | SIGN required, others allowed | ✅ SIGN only |
| Package name and signing-certificate digest | same; `services/identity/src/server.js` | Digest optional and empty by default (any signer passed) | ✅ the official release certificate is built in (`HUMID_ANDROID_RELEASE_CERT`); none configured = refused; test-only opt-out `HUMID_ANDROID_ALLOW_ANY_SIGNER` |
| Challenge is a single-use, short-lived server nonce | identity `liveness()` | The session transcript (server-random), reusable for 8 h | ✅ the session must be under 5 min old, and each challenge enrols one device |
| Minimum `osPatchLevel` | `android.js` | None | ✅ optional `HUMID_ANDROID_MIN_PATCH=YYYYMM` |
| Malformed attestation data | `attest/src/index.js` | Could surface as a 500 | ✅ always a refusal |
| iOS App Attest: attestation verified; `clientDataHash` carries the server challenge | `packages/attest/src/apple.js` | Yes | ➖ |
| iOS: release builds reject `appattestdevelop` | same, `HUMID_APP_ATTEST_ENV` | Server setting, default `production` | ➖ |
| iOS: assertions verified, counter strictly increasing | — | No assertions at all | ⬜ needs the iOS app to keep its App Attest key and assert on sign-in; iPhone builds aren't signed yet |
| iOS key binding: the Secure Enclave liveness key bound by App Attest | `attest/src/index.js` (`appAttestClientData`) | Bound inside the **attestation's** `clientDataHash` (SHA-256 of challenge ‖ liveness key), not an assertion | ◑ equivalent proof that the genuine app registered that key in that session. Neither form proves the key is in the Secure Enclave; the server's label `apple-secure-enclave` overstates that. Assertions (above) add an ongoing check |

## P1 — Sign the action, not just a nonce

| Item | Before | Now |
|---|---|---|
| A server-issued challenge per action: action, targets, device, nonce, expiry ≤ 60 s | Client-chosen request slot and time; no server nonce | ✅ `POST /auth/step-up` issues a single-use approval for one method + path (which carries the target ids), this device, a nonce, an expiry 60 s on (`packages/htp/src/proofs.js` `actionBytes`) |
| The prompt shows the action | Yes: "Delete Last will", "Add a device"… (Android title, iOS `localizedReason`) | ➖ |
| The signature covers exactly those bytes | ML-DSA covered request + body; the secure chip covered the slot, method, path, time | ✅ both now cover the issued action too |
| Refuse reused, expired, other-action, other-device | Replay window stopped reuse; no device or expiry binding; `abs()` let proofs be dated 60 s ahead | ✅ each refusal tested (`tests/e2e/liveness.test.js`); future-dated proofs refused beyond 5 s of clock skew |
| The secure chip doesn't cover the request body | — | ◑ by design: the body (e.g. a seed sealed to a new device) is made with keys the same check releases, so it can't exist before the prompt; the ML-DSA signature from that check covers it |

## P2 — Camera: in-app only

| Item | Where | Status |
|---|---|---|
| No hand-off to an external camera app | No `capture` attribute and no native camera intents. The manifest declared a `<queries>` entry for `IMAGE_CAPTURE` that let the photo picker offer camera apps | ✅ entry removed (`plugins/humid-gate/android/src/main/AndroidManifest.xml`) |
| In-process capture | `getUserMedia` inside the app's WebView; zxing-cpp and Tesseract run on the phone | ➖ (the equivalent of CameraX with on-device ML Kit; nothing leaves the phone) |
| Frames in memory only; camera stopped after a scan | Canvases in memory, the stream stopped on finish | ➖ |
| No selfie or face capture | Rear camera only; face checks are the OS biometric | ➖ |
| Location stamp is the phone's word | `core/place.js`: what the OS geolocation reported, kept in the encrypted index, never in the file; shown as "as the phone reported", never as proof | ➖ a rooted or emulated phone can report any place |
| "Photo" picks a file through the system chooser | `ids.jsx` `DocCamera`, `accept="image/*"` | ✅ images only, and with the `<queries>` entry gone it can't reach a camera app; a picked photo is the lowest-ranked source (`record.js` `RANK`) |

## P2 — QR payloads

| Item | Where | Status |
|---|---|---|
| Versioned format, purpose, expiry | `packages/recovery/src/index.js:338-383` | ✅ `HUMID:2:KIND:CODE:EXPIRY` |
| Signed / verified before acting | The 12-character code is a commitment to the keys behind it | ✅ see below. The scanning device recomputes it from the keys the server returns (`api/src/index.js` `getLink`/`getOffer`/`getHelp`), and now the **displaying** device does too, so a server can't hand back a code for keys of its own (`api/src/index.js:280,312,376`) |
| Strict parser: size cap, unknown fields and versions | `parseQr` | ✅ 48 characters; one canonical spelling; unknown versions, kinds and extra fields refused; no bare codes from the camera; the scanner takes only the kind it asked for (`ui.jsx` `Scanner`) |
| Never a URL or deep link | Never opened | ➖ (and URLs don't parse) |
| Device link: short authentication string on both screens | `accountCheck` (`recovery/src/index.js:389`); new device `onboarding.jsx`, old device `security.jsx` `AddDeviceSheet` | ✅ the new device joins only after the person confirms the account check matches the other screen (`controller.js` `confirmJoin`) |
| Both devices confirm with a live biometric; the new device passes attestation | Approve is a step-up; joining is an attested enrolment | ➖ (P1) |
| The new device's name is free text | `services/recovery/src/server.js:147` | ✅ control, zero-width and direction-override characters stripped; shown as "It calls itself …" |
| Witness / recovery codes checked against the ledger and public log | — | ⬜ open: a witness checks the code's keys, not yet the public log |
| Fuzz tests | `tests/fuzz.test.js` | ✅ found two bugs, both fixed: non-canonical QR spellings parsed, and a malformed SOD signer id surfaced as a server error |

**Why a commitment and not a signature.** The brief asks for a signature from the
issuing device's key. A QR here always introduces keys the scanner doesn't know yet
(a new device, a stranger offering to be a witness), so there is no key it could
already trust to check such a signature with: a signature would prove only that
whoever made the keys signed them. The code is a hash commitment to the keys that a
person can also read out or type; both ends recompute it, and the account check
then confirms which account the new device is joining.

## P2 — ID chip and MRZ

| Item | Where | Status |
|---|---|---|
| MRZ/CAN only derive BAC/PACE keys; identity only from DG1 after passive authentication (server) | `packages/emrtd`, `packages/anchor` | ➖ |
| Vault ID records: typed fields outrank chip fields while the record still says "from the chip" | `packages/idscan/src/record.js` `provenance` | ✅ a record with a typed change says "Read from the chip, then changed by hand" |
| Check digits | `packages/anchor/src/mrz.js:66-67` | ✅ the overall (composite) and personal-number check digits too, for TD1, TD2 and TD3 |
| Wipe MRZ/CAN and derived keys | `emrtd/src/bac.js`, `pace.js`, `sm.js` `wipe()`, `index.js` `readDocument` | ✅ BAC seed and keys, PACE password key and shared secret, session keys (on success and failure). ◑ the MRZ/CAN themselves are JavaScript strings, which can't be zeroed; they live only in the form's state and are never stored or logged |
| Passive auth: SOD to CSCA, every DG hash | `anchor/src/index.js:229-283` | ✅ contentType required; the SOD's signer identifier must name the certificate used; that certificate must have document-signing key usage and not be a CA; CSCA, document signer and MRZ issuer must be one country (`countries.js` maps MRZ codes to ISO 3166, with ICAO's own: D, GBD…, UTO); every data group sent is checked; malformed input is a refusal, never a 500. ⬜ CRL / revocation of document signers |
| Client "matches the issuing country's signed hashes" without checking any signature | `record.js` `provenance`, `ids.jsx` | ✅ reworded: the phone checks the files against the chip's own hash list, and says the country's signature isn't checked there |
| Active authentication challenge from the server, single use, short-lived | Remote anchor | ➖ |
| A chip that fails its hash check, throws, or returns no result was still applied and labelled verified; its photo was still decoded | `idscan/src/chip.js` `safeCheckIntegrity`, `record.js` `applyChip`, `controller.js` `readChipInto` | ✅ fails closed (Oct 2026 audit): chip data is used only when integrity is explicitly `ok:true`; otherwise the record stays printed-only, marked "Not verified". A passing chip is labelled "Chip data integrity-checked". The phone still does not verify the SOD signature, the CSCA chain or Active Authentication in the vault-copy path (needs a bundled CSCA masterlist): ⬜ open |
| Stations accept chip data from a file, no AA | `services/recovery/src/server.js:658-692`, `security.jsx` `StationSheet` | ✅ a chip whose SOD lists an AA key must answer a fresh single-use station challenge, and leaving DG15 out doesn't dodge it; stations no longer load files. Chips with no AA key are still accepted at a station, on the operator's in-person check (that is what stations are for). The station wait is unchanged (out of scope) |
| TLV/ASN.1 bounds, APDU loops | `emrtd/src/util.js:61-120`, `index.js:42-58`, `sm.js:45-66` | ✅ tags ≤ 3 bytes, lengths ≤ 3 bytes and inside the data, duplicate tags refused, GET RESPONSE chaining capped (32 rounds, 64 KB), a read longer than asked refused, DO87 padding indicator / whole blocks / DO99 and DO8E sizes checked |
| `humid-nfc` is a byte pipe | Yes | ➖ |
| Fuzz tests for TLV, ASN.1, SOD | `tests/fuzz.test.js` | ✅ TLV, secure messaging, EF.CardAccess, SOD, DG1, passive authentication; seeded (`FUZZ_SEED`, `FUZZ_N`) |

## P2 — Screen, overlay and input exposure

| Item | Status |
|---|---|
| Android `FLAG_SECURE`, hide overlays (API 31+), `filterTouchesWhenObscured`, no recents screenshot | ✅ for the whole app (`HumidGatePlugin.kt:121`): every screen shows something private. Screenshots of HumID are no longer possible 🔒 |
| Input fields: no suggestions or learning | ✅ `autocorrect`, `autocomplete` and `spellcheck` off on every text field. ◑ a WebView can't set `IME_FLAG_NO_PERSONALIZED_LEARNING`; with these attributes Chromium asks the keyboard for no suggestions |
| Clipboard | ✅ removed: the seal card and ID numbers can't be copied (save or print the card instead) |
| Accessibility-service warning (optional) | ⬜ |
| iOS: block third-party keyboards, hide the app-switcher snapshot, react to screen capture | ✅ in code (`HumidGatePlugin.swift:97-190`, *screen exposure*): a cover in the app switcher and while the screen is recorded or mirrored; third-party keyboards refused. 🔒 needs a signed iPhone build to confirm |

## P2 — WebView and shell

| Item | Status |
|---|---|
| Bundled content only, no `eval`/inline script | ➖ |
| CSP | ◑ strict; `connect-src` allows any `https:` because the server is the person's choice (their own Windows server, or a hosted one). Every call is HTP-encrypted to the pinned server key, so another origin learns nothing. Loopback stays for a server on the same computer |
| WebView debugging off in release | ✅ (it was on in the debug APK; there are no debug APKs now) |
| Narrow bridge, validated arguments | ✅ the gate plugin checks every argument natively: prompt length and control characters, base64 and sizes of challenges and handles (`HumidGatePlugin.kt`, `.swift` `badArgs`); the app clips prompts first (`gate/src/adapters/native.js`). ◑ `core:default` permissions are Tauri's defaults |
| `freezePrototype` | ⬜ off: needs checking against the scan engines on devices first |

## P3 — Logging and memory

| Item | Status |
|---|---|
| App, packages and plugins log nothing sensitive | ➖ no client logging at all |
| Server request log | ✅ logs the route pattern (`/links/:code`), never the path's codes or ids (`packages/svc/src/index.js:112`) |
| Zero buffers after use | ✅ seeds and keys were already wiped; chip session keys now too |

## 2.0 security pass (October 2026)

A second pass over the app shell and the data it keeps on the device. Finding numbers
are the review's; F3, F4, F8 and F9 were screen-level changes made alongside (the
seal card's PDF viewer sandbox, CSS, and the screens calling `openExternal`).

| # | Finding | Fix | Where |
|---|---|---|---|
| F1 | The duress setting (`{ enabled, gesture }`) sat in the identity record in the clear: anyone with the phone's storage could see duress was set up and which gesture triggers it | Sealed under a key derived from the account seed (`settingsKey`, HKDF info `HUMID-PQ1 device-settings`, AEAD `HUMID-SETTING-v1`) as `duressSealed`. The Lock screen reports which gesture was used; the controller opens the setting inside the live check and decides decoy-or-real **after** it. A plaintext setting from an earlier release is sealed on the first unlock. ✅ `tests/duress.test.js` proves the record holds no `duress`, `gesture` or state in the clear | `packages/crypto/src/suites/pq1.js` (`settingsKey`, `sealSetting`, `openSetting`), `apps/mobile/src/core/duress.js`, `controller.js` `unlock` / `unlockOffline` / `saveDuress` / `loadDuressSetting` |
| F2 | iOS backups could carry the WebView's IndexedDB (wrapped identity, sealed offline copy, access pass) | `Library/WebKit` and `Caches/WebKit` excluded from backups at plugin load, every launch. ✅ 🔒 (Android already: `allowBackup=false`, data-extraction rules.) The join record's `pending` block is replaced by `null` when the join completes. ◑ the access pass is still stored as is; see SECURITY.md *Before real data* | `HumidGatePlugin.swift` `excludeWebDataFromBackups` |
| F5 | Release bundles still contained the simulated vault server, the demo gate's callers and the `/dev/*` endpoints, switched off only at run time | The build flags are tested inline where used (the only form esbuild folds at parse time) and `startSim` is a conditional expression, so the branches and the sim chunk are gone from release builds. ✅ `tests/bundle.test.js` builds a release and checks. A simulation build is its own app, `app.humid.vault.sim` / "HumID Sim", and can't be published | `apps/mobile/build.mjs`, `controller.js`, `core/nfc.js`, `.github/workflows/release.yml` |
| F6 | `knownNames` (item id → name, for Activity) survived lock and erase, and in a decoy session held every item's name | Cleared on `lock()` and `eraseEverything()`; a decoy session keeps only the decoy items' names | `controller.js` `refresh`, `lock`, `eraseEverything` |
| F7 | `markPicking()` (a system file picker is up) suppressed lock-on-hide until a later focus event, so a picker that never came back left HumID unlocked off screen | Bounded: clears itself after 60 s; `pagehide` clears it and locks; a hidden span over 20 s locks anyway (timer while hidden, and on return) | `controller.js` `markPicking`, `wireGlobalEvents` |
| F10 | `<a target=_blank>` links left the WebView free to navigate | `openExternal(url)`: only `https:`, `tel:`, `mailto:`; the Tauri opener plugin with a capability scoped to exactly those; in a browser `noopener,noreferrer`. The shell's `on_navigation` refuses anything but the app's own origin (`tauri://`, `tauri.localhost`, loopback in dev) | `apps/mobile/src/core/external.js`, `src-tauri/src/lib.rs` `own_origin`, `capabilities/default.json` |
| F11 | A JPEG 2000 chip photo's header decided the canvas size: a hostile chip or file could declare a huge image | ≤ 2 MB and ≤ 4,000,000 declared pixels, checked before anything is allocated; no portrait is decoded from a chip whose files fail its own hash list | `core/scan.js` `jp2ToJpeg` / `portraitTooBig`, `controller.js` `readChipInto` |
| F12 | A request with no timeout could hold a live check (keys in memory) open for as long as a proxy kept the socket | Every HTP request has a 45 s timeout (`AbortSignal.timeout`, injectable); the connection probe 15 s. A hung download ends the check. The ciphertext download stays inside the check on purpose: `GET /vault/objects/:id` *is* the step-up request, released only on the signature made during that check | `packages/htp/src/client.js` `request`, `controller.js` `fetchPlain` |
| — | The seal card sheet and the payment-card sheet shared the type `"card"` | Seal card sheet is `recoveryCard` | `controller.js` `makeNewCard`, `security.jsx` |

## Out of scope, unchanged

Recovery waits, duress behaviour and the public log design are as they were. None of
the changes above conflicts with them.

## Oct 2026 audit: open findings (not yet fixed)

A read-only audit of crypto/transit, server, app/plugins/ID parsers, supply chain, plus fuzzing (reports kept with the Build Log). Fixed on `integration/demo-hardening`: `GET //` crash, pre-auth body caps, sign-in lockout that could force a Check-in wipe, null-body 500s, MRZ name ReDoS, chip fail-closed. Still open, most important first:

| ID | Finding | Status |
|---|---|---|
| H-1 | Envelope signer is not pinned to the account: a malicious vault can serve forged content signed with its own key (`pq1.js` `verify/open`, `controller.js` `fetchPlain`) | ⬜ |
| H-2 | Transparency-log cosigner and ledger keys come from the server's own response (`audit/index.js` `verifyCheckpoint`) | ⬜ |
| SRV-01 | Device enrolment needs only the account key, no approval from an existing device (`gateway` `enrollDevice`) | ⬜ |
| SRV-05 | `POST /auth/presence` with `d:1` destroys an armed vault with no step-up | ⬜ |
| SRV-04 | Windows SYSTEM console works in a directory LOCAL SERVICE controls (junction primitive) | ⬜ |
| M-1 | `/htp/v1/keys` policy hints are unauthenticated (a proxy can turn off split keys) | ⬜ |
| F-07 | Windows/Linux desktop gates are not OS-enforced (desktop paused) | ⬜ |
| F-08/F-09 | Android wrapping key is valid 3 s after any biometric, not per use; no runtime root detection | ⬜ |
| SC-01..05 | Actions pinned to mutable tags, release job permissions, no artifact provenance, unpinned base images, secrets in scripts | ⬜ |
| SRV-07 / F-04 | Per-IP limits bypassable with spoofed `CF-Connecting-IP` / `X-Forwarded-For` | ⬜ |
| Dep | `@noble/post-quantum` 0.7.1 is pre-1.0 and not independently audited; HTP, blind-RSA pass and key-share code are in-house | ⬜ independent review |
