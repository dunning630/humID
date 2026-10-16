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
| iOS: Secure Enclave key, `.privateKeyUsage + .biometryCurrentSet`, `WhenPasscodeSetThisDeviceOnly`; no `.userPresence`/`.biometryAny`/`.devicePasscode` | `HumidGatePlugin.swift:246-256` | Already so | ➖ 🔒 |
| iOS: fresh `LAContext` per operation, reuse duration 0, action in `localizedReason` | `:197-210` | Fresh context; reuse duration not set explicitly | ✅ |
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
| No hand-off to an external camera app | No `capture` attribute; no native camera intents. The manifest's `<queries>` for `IMAGE_CAPTURE` is unused | ⬜ remove the `<queries>` entry |
| In-process capture | `getUserMedia` inside the app's WebView; zxing-cpp and Tesseract run on the phone | ➖ (equivalent to CameraX + on-device ML Kit; nothing leaves the phone) |
| Frames in memory only; camera stopped after a scan | Canvases in memory, the stream stopped on finish | ➖ |
| No selfie or face capture | Rear camera only; face checks are the OS biometric | ➖ |
| "Photo" picks a file through the system chooser (camera apps can register for it) | `ids.jsx` | ⬜ restrict to images and say it's a file, untrusted like any other input |

## P2 — QR payloads

| Item | Where | Status |
|---|---|---|
| Versioned format, purpose, expiry | `packages/recovery/src/index.js` `qrPayload`/`parseQr`: `HUMID:KIND:CODE`, no version, bare codes accepted | ⬜ |
| Signed / verified before acting | The code is a 60-bit commitment to the keys, checked by the scanning device | ◑ the **displaying** device doesn't recompute its own code (`controller.js` link, recovery, offer), so a malicious server could substitute keys ⬜ |
| Strict parser: size cap, unknown fields/versions | Anchored regex, no length cap | ⬜ |
| Never a URL or deep link | Never opened | ➖ |
| Device link: short authentication string on both screens, both confirm with a live biometric, attestation | Both live checks and attestation ✅; no SAS; new device doesn't confirm the account; the new device's name is free text | ⬜ |
| Witness / recovery codes checked against the ledger and public log | Not before releasing a piece | ⬜ |
| Fuzz tests | None | ⬜ |

## P2 — ID chip and MRZ

| Item | Where | Status |
|---|---|---|
| MRZ/CAN only derive BAC/PACE keys; identity only from DG1 after passive authentication (server) | `packages/emrtd`, `packages/anchor` | ➖ |
| Vault ID records: typed fields outrank chip fields while the record still says "from the chip" | `packages/idscan/src/record.js` | ⬜ |
| Check digits | Server: number, birth, expiry; not composite or personal number. Client DG1 parse is the lenient OCR parser | ⬜ |
| Wipe MRZ/CAN and derived keys | BAC/PACE/SM keys never zeroed | ⬜ |
| Passive auth: SOD to CSCA, every DG hash | Server: yes (DG1, DG15). Missing: contentType required, signer-info match, DS key usage, **country of the signer = DG1 issuer**, revocation | ⬜ |
| Client "matches the issuing country's signed hashes" without checking any signature | `record.js`, `ids.jsx` | ⬜ reword or verify |
| Active authentication challenge from the server, single use, short-lived | Remote anchor: yes | ➖ |
| Stations accept chip data from a file, no AA, on the shortest wait | `services/recovery`, `security.jsx` | ⬜ |
| TLV/ASN.1 bounds, APDU loops | `packages/emrtd/src/util.js`, `index.js`, `sm.js`; `packages/idscan/src/chip.js` | ⬜ |
| `humid-nfc` is a byte pipe | Yes | ➖ |
| Fuzz tests for TLV, ASN.1, SOD | None | ⬜ |

## P2 — Screen, overlay and input exposure

| Item | Status |
|---|---|
| Android `FLAG_SECURE`, hide overlays (API 31+), `filterTouchesWhenObscured`, no recents screenshot | ⬜ none set (`HumidGatePlugin.load()` is the place) |
| Input fields: no suggestions or learning | ◑ `autocomplete`/`spellcheck` off on most; `autocorrect` nowhere. A WebView can't set `IME_FLAG_NO_PERSONALIZED_LEARNING` on ordinary fields |
| Clipboard | The seal card code and an ID's number can be copied, never cleared ⬜ remove |
| Accessibility-service warning (optional) | ⬜ |
| iOS: block third-party keyboards, hide the app-switcher snapshot, react to screen capture | ⬜ none |

## P2 — WebView and shell

| Item | Status |
|---|---|
| Bundled content only, no `eval`/inline script | ➖ |
| CSP | ◑ strict, but `connect-src` allows any `https:` and loopback in release ⬜ pin to the server |
| WebView debugging off in release | ✅ (it was on in the debug APK; there are no debug APKs now) |
| Narrow bridge, validated arguments | ◑ `core:default` is broad; plugin argument lengths unchecked ⬜ |
| `freezePrototype` | ⬜ off |

## P3 — Logging and memory

| Item | Status |
|---|---|
| App, packages and plugins log nothing sensitive | ➖ no client logging at all |
| Server request log | ⬜ redacts hex ids only: recovery codes and request ids are logged |
| Zero buffers after use | ◑ seeds and keys are wiped; eMRTD session keys aren't ⬜ |

## Out of scope, unchanged

Recovery waits, duress behaviour and the public log design are as they were. None of
the changes above conflicts with them.
