// Native gate: talks to tauri-plugin-humid-gate (humid-gate@2), which accepts
// only a live biometric on each platform:
//   iOS      Face ID / Touch ID. Secret in the Keychain (.biometryCurrentSet);
//            liveness key in the Secure Enclave; App Attest vouches for it.
//   Android  Class 3 fingerprint or face. Liveness key in the Keystore
//            (StrongBox if present), biometric-only and per use; key attestation.
//   macOS    Touch ID, Keychain .biometryCurrentSet. No liveness key yet.
//   Windows  Fingerprint via the Windows Biometric Framework (not Hello, which
//            accepts a PIN). No liveness key.
//   Linux    Fingerprint via fprintd. No liveness key.

import { fromB64, toB64 } from "@humid/codec";
import { GATE_CONTRACT, ASSURANCE, CANCELLED, interruptRecord } from "../contract.js";
import { lowS } from "../lows.js";

/** What the native side accepts (it checks too): one line, at most 120 characters. */
const promptText = (s, fallback) => {
  const t = String(s || fallback).replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").trim();
  return t.length > 120 ? `${t.slice(0, 117)}…` : t;
};
const invoke = (cmd, args) => globalThis.__TAURI_INTERNALS__.invoke(`plugin:humid-gate|${cmd}`, args);

export const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";

const NOT_APP = "HumID checks your face or fingerprint with your phone's secure chip, so it works only in the HumID app for iPhone and Android.";

function mapError(e) {
  const msg = typeof e === "string" ? e : e?.message || String(e);
  if (/cancel/i.test(msg)) return new Error(CANCELLED);
  // The OS deleted or invalidated this device's key (biometrics changed, app reinstalled,
  // data restored from a backup): nothing can unlock this identity here any more.
  if (/invalidated|key is gone/i.test(msg)) return Object.assign(new Error(msg), { code: "key_invalidated" });
  return new Error(msg);
}

const b64 = (b) => (b ? toB64(b) : null);
function live(l) {
  if (!l) return null;
  const a = l.attestation;
  return {
    pub: l.pub ? fromB64(l.pub) : null,
    sig: lowS(fromB64(l.sig)), // the secure chip may return either form; servers take only low-S
    ...(a ? { attestation: a.kind === "android-key" ? { kind: a.kind, chain: a.chain.map(fromB64) } : { kind: a.kind, object: fromB64(a.object) } } : {}),
  };
}

export const nativeAdapter = {
  id: "native",
  contract: GATE_CONTRACT,

  async probe() {
    const off = { available: false, method: "native", assurance: ASSURANCE.NONE, label: "Face or fingerprint", modalities: [], proof: null };
    if (!inTauri()) return { ...off, reason: NOT_APP };
    try { return { modalities: [], proof: null, ...(await invoke("probe")) }; }
    catch (e) { return { ...off, reason: mapError(e).message }; }
  },

  async enroll({ prompt, challenge, attest } = {}) {
    try {
      const r = await invoke("enroll", { prompt: promptText(prompt, "Bind HumID to your face or fingerprint"), challenge: b64(challenge), attest: b64(attest) });
      return {
        handle: r.handle,
        bindingId: r.handle.id,
        secret: fromB64(r.secret),
        interrupt: interruptRecord(r.method, "enroll", r.assurance, r.detail || {}),
        live: live(r.live),
      };
    } catch (e) { throw mapError(e); }
  },

  async release(handle, { purpose, prompt, challenge, attest } = {}) {
    try {
      const r = await invoke("release", { handle, prompt: promptText(prompt, "Confirm it's you"), challenge: b64(challenge), attest: b64(attest) });
      return {
        secret: fromB64(r.secret),
        interrupt: interruptRecord(r.method, purpose, r.assurance, r.detail || {}),
        live: live(r.live),
        // the platform moved the secret to a new key (Android 2.0 → per-use, LIVE-01): keep this instead
        ...(r.handle ? { handle: r.handle } : {}),
      };
    } catch (e) { throw mapError(e); }
  },

  async forget(handle) {
    try { await invoke("forget", { handle }); } catch { /* best effort */ }
  },
};

/**
 * Android: the accessibility services switched on right now, `[{ id, label, canRead, canAct }]`
 * (APP-09). An enabled service can read what HumID shows and tap its buttons, which FLAG_SECURE
 * doesn't stop. Elsewhere, or when it can't be asked: []. Never throws.
 */
export async function enabledAccessibilityServices() {
  if (!inTauri()) return [];
  try {
    const r = await invoke("enabled_accessibility_services");
    return (Array.isArray(r?.services) ? r.services : []).slice(0, 32).map((s) => ({
      id: String(s?.id || "").slice(0, 200),
      label: String(s?.label || s?.id || "An app").replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").trim().slice(0, 80),
      canRead: s?.canRead !== false, // unknown counts as able
      canAct: s?.canAct === true,
    }));
  } catch { return []; }
}
