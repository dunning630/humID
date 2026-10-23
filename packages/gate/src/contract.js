// @humid/gate — Gate contract v2: live biometrics only.
//
// A gate adapter turns "a live human just passed a biometric check on this
// device" into (1) a 32-byte secret that unwraps the device's seeds, and
// (2) on phones, a signature by a hardware liveness key that the server can
// check. No gate may fall back to a PIN, pattern or password.
//
// Every adapter implements:
//   id                  stable string, stored with the identity
//   probe()             -> { available, method, assurance, label, modalities, proof, reason }
//   enroll(opts)        -> { handle, bindingId, secret, interrupt, live }
//   release(handle, opts) -> { secret, interrupt, live }
//   forget(handle)      optional; removes the OS-held key material
//
// opts: { purpose, prompt, challenge, attest }
//   challenge  bytes the liveness key signs inside this one biometric check
//              (the sign-in message, a step-up ticket, a sealed file's hash…)
//   attest     bytes (the session transcript) to make a fresh liveness key and
//              attest it to: Android key attestation or Apple App Attest
// live: null (no liveness key on this platform) or
//   { pub: SPKI bytes, sig: DER ECDSA P-256 over challenge, low-S (lows.js),
//     attestation?: { kind: "android-key", chain: [DER…] } | { kind: "apple-app-attest", object: CBOR } }
// modalities: which live biometrics this gate accepts, e.g. ["face", "fingerprint"].
// proof: what can vouch for it to a server: "android-key" | "apple-app-attest" | null.
//
// assurance: "hardware" (secure hardware releases the secret only after a
// biometric match), "os" (the OS verifies a biometric; software-held secret),
// "none" (demo, local development builds only).

export const GATE_CONTRACT = 2;

export const ASSURANCE = Object.freeze({ HARDWARE: "hardware", OS: "os", NONE: "none" });

export const CANCELLED = "Interrupt cancelled.";

export function interruptRecord(method, purpose, assurance, extra = {}) {
  return {
    method, purpose,
    up: true,
    uv: assurance !== ASSURANCE.NONE,
    assurance,
    ...extra,
    at: new Date().toISOString(),
  };
}

export function assertAdapter(a) {
  for (const k of ["id", "probe", "enroll", "release"]) {
    if (!(k in a)) throw new Error(`Gate adapter is missing "${k}".`);
  }
  if (a.contract !== GATE_CONTRACT) {
    throw new Error(`Gate adapter ${a.id} implements contract ${a.contract}, app needs ${GATE_CONTRACT}.`);
  }
  return a;
}
