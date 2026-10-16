// Demo gate: no sensor. Exists so the app can be tried on a laptop during
// local development. Compiled only into builds made with HUMID_ALLOW_DEMO=1
// (npm run dev); release builds don't contain it, and servers refuse it unless
// HUMID_DEVICE_POLICY=demo. Every interrupt is recorded as "demo-no-hardware".

import { toB64, fromB64 } from "@humid/codec";
import { GATE_CONTRACT, ASSURANCE, interruptRecord } from "../contract.js";

const METHOD = "demo-no-hardware";
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export const demoAdapter = {
  id: "demo",
  contract: GATE_CONTRACT,
  needsHold: true,

  async probe() {
    return { available: true, method: METHOD, assurance: ASSURANCE.NONE, label: "Demo mode (no sensor)", modalities: [], proof: null };
  },

  async enroll() {
    const secret = random(32);
    const handle = { id: toB64(random(16)), demoSecret: toB64(secret) };
    return { handle, bindingId: handle.id, secret, interrupt: interruptRecord(METHOD, "enroll", ASSURANCE.NONE), live: null };
  },

  async release(handle, { purpose } = {}) {
    // Tests (development builds only): act as if the phone deleted its key, the way
    // Android does when its fingerprints change, to exercise the "key is gone" path.
    if (globalThis.__humidDemoKeyGone) throw Object.assign(new Error("The device biometric key is gone or was invalidated by a biometric change. This identity can no longer be unlocked here."), { code: "key_invalidated" });
    return { secret: fromB64(handle.demoSecret), interrupt: interruptRecord(METHOD, purpose, ASSURANCE.NONE), live: null };
  },

  async forget() {},
};
