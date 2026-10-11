// Demo gate: no hardware. The secret is stored next to the identity, and every
// interrupt is recorded as "demo-no-hardware" so envelopes prove nothing about
// a human. The UI asks for a press-and-hold to stand in for the sensor read.

import { toB64, fromB64 } from "@humid/codec";
import { GATE_CONTRACT, ASSURANCE, interruptRecord } from "../contract.js";

const METHOD = "demo-no-hardware";
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export const demoAdapter = {
  id: "demo",
  contract: GATE_CONTRACT,
  needsHold: true,

  async probe() {
    return { available: true, method: METHOD, assurance: ASSURANCE.NONE, label: "Demo mode (no hardware gate)" };
  },

  async enroll() {
    const secret = random(32);
    const handle = { id: toB64(random(16)), demoSecret: toB64(secret) };
    return { handle, bindingId: handle.id, secret, interrupt: interruptRecord(METHOD, "enroll", ASSURANCE.NONE) };
  },

  async release(handle, purpose) {
    return { secret: fromB64(handle.demoSecret), interrupt: interruptRecord(METHOD, purpose, ASSURANCE.NONE) };
  },

  async forget() {},
};
