// @humid/gate — the live-biometric gate for this runtime.
// Release builds contain only the native gate. The demo gate (no sensor) is
// compiled in only when the app is built with HUMID_ALLOW_DEMO=1.

import { assertAdapter } from "./contract.js";
import { nativeAdapter, inTauri, enabledAccessibilityServices as nativeServices } from "./adapters/native.js";
import { demoAdapter } from "./adapters/demo.js";

export * from "./contract.js";
export { inTauri };

/* global __HUMID_ALLOW_DEMO__ */
export const DEMO_BUILD = typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true;

const ADAPTERS = new Map([nativeAdapter, ...(DEMO_BUILD ? [demoAdapter] : [])].map((a) => [a.id, assertAdapter(a)]));

export const adapter = (id) => {
  const a = ADAPTERS.get(id);
  if (!a) throw Object.assign(new Error(id === "webauthn-prf" || id === "demo"
    ? "This HumID was set up without a live biometric sensor. Set it up again in the HumID app."
    : `Unknown gate "${id}". This identity was created by a newer HumID.`), { code: "unknown_identity" });
  return a;
};

/** The device's live-biometric gate and what it can do here. */
export async function bestHardwareGate() {
  return { adapter: nativeAdapter, probe: await nativeAdapter.probe() };
}

export const demoGate = () => (DEMO_BUILD ? demoAdapter : null);

/**
 * The accessibility services that could read the screen (Android; [] elsewhere). Development
 * builds can pretend one is on with globalThis.__humidDemoA11y = [{ label }], for the browser test.
 */
export async function enabledAccessibilityServices() {
  // inline test, so a release build folds it away (a const imported from here isn't folded)
  if (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true && Array.isArray(globalThis.__humidDemoA11y)) return globalThis.__humidDemoA11y.map((s) => ({ id: s.id || s.label, label: s.label, canRead: s.canRead !== false, canAct: !!s.canAct }));
  return nativeServices();
}
