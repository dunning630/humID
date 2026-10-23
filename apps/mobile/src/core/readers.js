// Another app that can read the screen (APP-09, R15). On Android an enabled accessibility
// service can read every word HumID shows and tap its buttons; FLAG_SECURE, hidden overlays and
// filtered touches don't stop it. So before HumID shows a document, a card or messages, it asks
// the phone which services are on, and if any can read the screen, it says which, by name, and
// lets the holder decide. Once per session for the same set of services. Nothing is stored.
//
// Needs a device to confirm: the native list (plugins/humid-gate, enabledAccessibilityServices)
// can't be built here; development builds can pretend with globalThis.__humidDemoA11y.
import { enabledAccessibilityServices } from "@humid/gate";
import * as S from "./state.js";

let pending = null; // the question on screen: its resolve
S.readerWarning.subscribe((v) => { if (!v && pending) { const p = pending; pending = null; p(false); } }); // a lock answers "no"

/**
 * Before showing `what` ("this document", "your recovery card", "your messages"): true to go
 * on, false if the holder chose not to. Asks only when a service that can read the screen is on
 * and this session hasn't already said yes to that same set.
 */
export async function screenReadersOk(what, { list = enabledAccessibilityServices } = {}) {
  const readers = (await list()).filter((s) => s.canRead);
  if (!readers.length) return true;
  const key = readers.map((s) => s.id).sort().join("\n");
  if (S.readersAccepted.value === key) return true;
  const older = pending; // a question already on screen: this one replaces it, that one is a no
  pending = null;
  older?.(false);
  return new Promise((resolve) => {
    pending = (ok) => { if (ok) S.readersAccepted.value = key; S.readerWarning.value = null; resolve(ok); };
    S.readerWarning.value = { what, services: readers };
  });
}

/** The holder's answer, from the warning sheet. */
export function answerReaders(ok) {
  const p = pending;
  pending = null;
  if (p) p(ok); else S.readerWarning.value = null;
}
