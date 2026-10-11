// Native gate: talks to the tauri-plugin-humid-gate plugin, which uses the
// OS biometric key store on each platform:
//   iOS      Keychain item, access control .biometryCurrentSet (Secure Enclave policy)
//   Android  Keystore AES-GCM key, auth-per-use BIOMETRIC_STRONG, BiometricPrompt
//   macOS    Keychain item, access control .biometryCurrentSet (Touch ID)
//   Windows  Windows Hello KeyCredential (TPM-backed), deterministic signature
//   Linux    fprintd fingerprint match, secret held in the Secret Service keyring
// The plugin reports the method and assurance it actually achieved.

import { fromB64 } from "@humid/codec";
import { GATE_CONTRACT, ASSURANCE, CANCELLED, interruptRecord } from "../contract.js";

const invoke = (cmd, args) => globalThis.__TAURI_INTERNALS__.invoke(`plugin:humid-gate|${cmd}`, args);

export const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";

function mapError(e) {
  const msg = typeof e === "string" ? e : e?.message || String(e);
  if (/cancel/i.test(msg)) return new Error(CANCELLED);
  return new Error(msg);
}

export const nativeAdapter = {
  id: "native",
  contract: GATE_CONTRACT,

  async probe() {
    if (!inTauri()) return { available: false, method: "native", assurance: ASSURANCE.NONE, label: "Device biometric", reason: "Not running inside the HumID app." };
    try { return await invoke("probe"); }
    catch (e) { return { available: false, method: "native", assurance: ASSURANCE.NONE, label: "Device biometric", reason: mapError(e).message }; }
  },

  async enroll() {
    try {
      const r = await invoke("enroll", { prompt: "Bind your HumID identity to this device" });
      return {
        handle: r.handle,
        bindingId: r.handle.id,
        secret: fromB64(r.secret),
        interrupt: interruptRecord(r.method, "enroll", r.assurance, r.detail || {}),
      };
    } catch (e) { throw mapError(e); }
  },

  async release(handle, purpose, prompt) {
    try {
      const r = await invoke("release", { handle, prompt: prompt || "Confirm it's you" });
      return {
        secret: fromB64(r.secret),
        interrupt: interruptRecord(r.method, purpose, r.assurance, r.detail || {}),
      };
    } catch (e) { throw mapError(e); }
  },

  async forget(handle) {
    try { await invoke("forget", { handle }); } catch { /* best effort */ }
  },
};
