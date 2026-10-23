// Ending things: closing the HumID (the vault erased for good), or forgetting this
// device's copy (server reset, device removed, an old test identity).
import { batch } from "@preact/signals";
import { adapter as gateAdapter } from "@humid/gate";
import * as S from "./state.js";
import { PINNED_KID } from "./config.js";
import { R } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, clearKeys } from "./interrupt.js";
import { connectServer } from "./session.js";
import { dropDrafts } from "./drafts.js";
import { closeViewer } from "./vault.js";
import { clearIdentity } from "./identity.js";

export async function eraseEverything() {
  const id = S.identity.value;
  try {
    await withStepUp("closeIdentity", [], "erase", "Close HumID and erase vault", async ({ proof }) => R.api.closeIdentity(proof));
  } catch (e) {
    if (cancelled(e)) return false;
    toast(`${friendly(e) || "Your session ended."} Local data was kept.`, "error");
    return false;
  }
  R.epoch++; // anything in flight (a public-log check, a loader) is dropped when it lands
  try { await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await clearIdentity();
  await R.store.clearVault();
  clearKeys(); R.offline = null; S.offlineReady.value = false;
  R.knownNames.clear();
  dropDrafts();
  closeViewer();
  batch(() => { S.resetSession(); S.identity.value = null; S.view.value = "welcome"; });
  R.api.htp.pinnedKid = PINNED_KID;
  toast("Your HumID was closed and your vault erased.");
  return true;
}

/** Forget this device's HumID locally and start over. */
export async function resetLocal() {
  const id = S.identity.value;
  R.epoch++;
  try { if (id) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await clearIdentity();
  await R.store.clearVault();
  S.offlineReady.value = false;
  dropDrafts();
  clearKeys(); R.offline = null; R.knownNames.clear();
  closeViewer();
  R.api.htp.close();
  R.api.htp.pinnedKid = PINNED_KID;
  R.api.htp.server = null;
  batch(() => { S.resetSession(); S.identity.value = null; S.lockIssue.value = null; S.view.value = "welcome"; });
  connectServer();
}
