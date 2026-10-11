// @humid/gate — picks the strongest available biometric gate for the runtime.
// Adding a gate (e.g. a FIDO2 security key) is a new adapter file plus one
// line in ADAPTERS; nothing else in the app changes.

import { assertAdapter } from "./contract.js";
import { nativeAdapter, inTauri } from "./adapters/native.js";
import { webauthnAdapter } from "./adapters/webauthn.js";
import { demoAdapter } from "./adapters/demo.js";

export * from "./contract.js";
export { inTauri };

const ADAPTERS = new Map([nativeAdapter, webauthnAdapter, demoAdapter].map((a) => [a.id, assertAdapter(a)]));

export const adapter = (id) => {
  const a = ADAPTERS.get(id);
  if (!a) throw new Error(`Unknown gate "${id}". This identity was created by a newer HumID.`);
  return a;
};

/** Hardware gate candidates for this runtime, strongest first. */
export async function bestHardwareGate() {
  const order = inTauri() ? [nativeAdapter] : [webauthnAdapter];
  let last;
  for (const a of order) {
    const p = await a.probe();
    if (p.available) return { adapter: a, probe: p };
    last = { adapter: a, probe: p };
  }
  return last;
}

export const demoGate = () => demoAdapter;
