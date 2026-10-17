# tauri-plugin-humid-gate

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
