# HumID Vault — native apps

One codebase, five apps: **iOS, Android, macOS, Windows, Linux**. HumID seals
files with ML-KEM-1024 + X25519 and signs them with ML-DSA-87. Every key use
is a *biological interrupt*: the keys exist in memory only after a live
biometric check on the device, and only for the length of that operation.

Built on [Tauri 2](https://tauri.app): a thin native shell around the system
webview (WKWebView, WebView2, WebKitGTK, Android WebView). Typical installers
are 3–10 MB. The whole web layer is about 300 KB, fonts included, and the app
makes no network calls.

## Architecture

```
modules/                     independently versioned JS packages
  codec/   @humid/codec      .humid envelope framing (format v1)
  crypto/  @humid/crypto     sealing-suite registry; ships HUMID-PQ1
  gate/    @humid/gate       biometric gate contract + adapters (native, WebAuthn, demo)
  store/   @humid/store      identity + vault storage, per-record migrations
  io/      @humid/io         save dialog / download
  ui/      @humid/ui         screens; talks to the others only via their interfaces
plugins/
  humid-gate/                Rust crate + Swift + Kotlin: the native biometric gate
shell/                       the app shell (Tauri); bundles modules into dist/
tools/affected.mjs           maps a change to the modules and platforms it touches
tests/                       module tests + compatibility test against the original app
```

Each module declares what it **provides** and **requires** in its
`package.json` (`"humid": {...}`). The shell build refuses to bundle an
incompatible combination, so modules can ship on their own schedule.

### The biometric gate on each platform

| Platform | How the key is protected | Biometric only? | Assurance |
|---|---|---|---|
| iOS | Keychain item, `.biometryCurrentSet`, Secure Enclave policy | Yes (no passcode fallback) | hardware |
| Android | Keystore AES-256 key (StrongBox if present), auth-per-use `BIOMETRIC_STRONG` | Yes | hardware |
| macOS | Data-protection keychain, `.biometryCurrentSet` (Touch ID) | Yes | hardware |
| Windows | Windows Hello KeyCredential (TPM-backed where present) | **No**: Hello also accepts the PIN | hardware |
| Linux | fprintd fingerprint match, secret in Secret Service keyring | Fingerprint, but enforced by HumID, not hardware | os |
| Browser | WebAuthn platform authenticator + PRF (the original web app) | Depends on the authenticator | hardware |

Every envelope's signed manifest records the gate `method` and `assurance`,
and the UI labels envelopes by assurance, so a weaker gate is never presented
as a stronger one.

**Biometric changes are destructive by design.** On iOS, macOS and Android,
adding or removing a face or fingerprint invalidates the gate key, and the
identity on that device can no longer be unlocked. Envelopes not exported
before that point cannot be recovered. See *Open decisions* below.

## Develop

Prerequisites: Node 22, Rust (stable), plus the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS.

```bash
npm install
npm test                      # module + compatibility tests
npm run tauri -- dev          # desktop app on this machine
npm run tauri -- android dev  # needs Android Studio, SDK, NDK
npm run tauri -- ios dev      # needs a Mac with Xcode
```

The first run on a phone needs the mobile project generated once:
`npm run tauri -- android init` / `npm run tauri -- ios init`.

## Build installers

Locally: `npm run tauri -- build` builds for the machine you are on.

In CI: **Actions → Release apps → Run workflow**, then choose the platforms
(`all`, or e.g. `windows`). Each platform builds on its own runner and uploads
its installers. Pushing a tag `app-vX.Y.Z` builds all five into a draft GitHub
release. See `RELEASING.md`.

| Platform | Output | Signing needed for |
|---|---|---|
| Linux | `.deb`, `.rpm`, `.AppImage` | nothing |
| Windows | `.msi`, `-setup.exe` | SmartScreen reputation (optional) |
| Android | `.apk`, `.aab` | Play Store upload (unsigned APK sideloads) |
| macOS | `.dmg` | **Touch ID**: the keychain entitlement only works in a signed build |
| iOS | `.ipa` | **any device install**: App Store / TestFlight |

Apple builds need an Apple Developer account (Team ID, a Developer ID or
distribution certificate, and an App Store Connect API key). The secrets the
workflow expects are listed at the top of `.github/workflows/release.yml`.

## Compatibility with the original web app

`tests/compat.test.js` runs the crypto from the original single-file
HumID Vault next to `@humid/crypto` and proves that both derive identical
keys, wrap seeds identically, and open each other's envelopes. Identities
created in the web version migrate automatically (`@humid/store`, schema 1 → 2).

## Open decisions

- **Recovery.** A lost device or a biometric change means a lost identity.
  Options: an exportable recovery kit (seed under a passphrase), multi-device
  enrolment (seal to several identities), or accept it as the security model.
- **Windows PIN.** Windows Hello cannot be restricted to biometrics through
  its public API. The alternative is the Windows Biometric Framework
  (fingerprint only, but no TPM-bound key).
- **Linux hardware binding.** A FIDO2 security key with a built-in fingerprint
  reader (e.g. YubiKey Bio) would give Linux a hardware-assurance gate. It
  slots in as one more gate adapter.
