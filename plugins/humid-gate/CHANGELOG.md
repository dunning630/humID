# tauri-plugin-humid-gate

## 2.2.0

- New command `enabled_accessibility_services` (`enabledAccessibilityServices` on Android):
  the accessibility services switched on, `{ services: [{ id, label, canRead, canAct }] }`,
  so the app can name one that could read the screen before it shows a document (APP-09).
  iOS and desktops return none. Allowed by the default permission set. Not built or run in
  CI here: needs a device to confirm.

## 2.1.0

- Android: the secret's AES key is per use and bound to its own prompt (LIVE-01). In 2.0 it was
  usable for 3 s after *any* Class 3 check, a lock-screen unlock included, so code running in the
  app could open the secret without a HumID prompt. Now its Cipher is the CryptoObject of its own
  BiometricPrompt. A CryptoObject holds one primitive, so a check that also signs with the
  liveness key shows two prompts in a row (the second without a confirm button). Handles are
  version 3.
- Android, existing installs: a 2.0 (v2) handle is released once more the old way and moved to a
  per-use key in the same call; `release` returns the new handle as `handle` and the app stores
  it. The 2.0 key is deleted the first time the new handle is used. Needs a device to confirm.
- All platforms: `release` may return `handle` (a replacement to store). iOS and desktops never
  do.

## 2.0.2

- iOS: the WebView's data store (`Library/WebKit`, `Caches/WebKit`: the wrapped identity,
  the sealed offline copy, an access pass) is excluded from iCloud and iTunes backups at
  plugin load, every launch. No change to the gate's commands.

## 2.0.1

- Android: declares location access (`ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, both
  optional hardware) for the app's "Stamp where it's sealed". The WebView asks for it only
  when a seal screen opens with the stamp on. No change to the gate's commands.

## 2.0.0

- Live biometrics only, never a PIN, passcode or password.
- iOS: Secure Enclave liveness key (`.privateKeyUsage` + `.biometryCurrentSet`) signs each check's challenge in the same Face ID / Touch ID evaluation that reads the secret; App Attest vouches for it when a device is added.
- Android: Keystore P-256 liveness key, BIOMETRIC_STRONG per use, StrongBox when present, with key attestation; the prompt is bound to its signature. The secret's AES key is biometric-only for 3 s after that check. Needs Android 11 (API 30).
- Windows: fingerprint through the Windows Biometric Framework plus DPAPI, replacing Windows Hello (which always allows a PIN).
- macOS / Linux: unchanged gates, now reported as assurance `os` (no hardware proof).
- `enroll` / `release` take `challenge` and `attest`; responses may include `live`. `probe` reports `modalities` and `proof`.

## 1.0.0

- Native biometric gate for iOS (Keychain .biometryCurrentSet), Android (Keystore BIOMETRIC_STRONG), macOS (Touch ID keychain), Windows (Hello KeyCredential), Linux (fprintd + Secret Service).
