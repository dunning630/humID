// @humid/gate — Gate contract v1.
//
// A gate adapter turns "a live human just passed a biometric check on this
// device" into a 32-byte secret. The identity seed is wrapped under that
// secret, so no key exists in memory without a fresh interrupt.
//
// Every adapter implements:
//   id                      stable string, stored with the identity
//   probe()                 -> { available, method, assurance, label, reason }
//   enroll()                -> { handle, bindingId, secret, interrupt }
//   release(handle, purpose, prompt) -> { secret, interrupt }
//   forget(handle)          optional; removes the OS-held key material
//
// handle      JSON-serialisable data the adapter needs later (key alias, salt…).
// bindingId   base64 id, bound as associated data when the seed is wrapped.
// secret      Uint8Array(32); callers wipe it after use.
// interrupt   record signed into every envelope manifest:
//             { method, purpose, up, uv, assurance, at, ...adapter fields }
//
// assurance is "hardware" (secret released by secure hardware only after a
// biometric match), "os" (OS-verified biometric, software-held secret) or
// "none" (demo). The UI and manifests show it, so a weaker gate is never
// presented as a stronger one.

export const GATE_CONTRACT = 1;

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
