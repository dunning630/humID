// This account's devices: list, add (approve a link), remove.
import { accountCheck } from "@humid/recovery";
import * as S from "./state.js";
import { R, KEY_TYPE, epoch, stale } from "./runtime.js";
import { toast, friendly, cancelled, quietly } from "./notify.js";
import { withStepUp, showInterrupt, needVault } from "./interrupt.js";
import { keepOffline } from "./session.js";

export async function loadDevices() {
  if (S.offline.value) { S.devices.value = R.offline?.devices || null; return; }
  const ep = epoch();
  const me = await quietly(R.api.me());
  if (me && !stale(ep)) { S.devices.value = me.devices; keepOffline({ devices: me.devices }); }
}

/** This account's match code, shown when adding a device. */
export const myAccountCheck = () => { const a = S.identity.value?.server?.id; return a ? accountCheck(a) : null; };

/** Look up the code a new device is showing. The API checks the code against the keys. */
export async function findLink(code) {
  try { needVault(); return await R.api.getLink(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Hand this account's seed to the new device, sealed to the keys its code commits to. */
export async function approveLink(req) {
  const id = S.identity.value;
  try {
    await withStepUp("approveLink", [req.code], "link", `Add ${req.platform}`, async ({ keys, seed, rec, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: "Sealing your account key to the new device…" });
      const { envelope } = await Suite.seal({ bytes: seed, name: "HumID account key", type: KEY_TYPE }, keys, { kemPk: req.kemPk, xPk: req.xPk }, { identityCommit: id.commit, interrupt: rec });
      return R.api.approveLink(req.code, envelope, proof);
    });
    toast("Approved. Compare the match code on the new device.");
    setTimeout(loadDevices, 4000);
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function removeDevice(d) {
  try {
    await withStepUp("removeDevice", [d.id], "remove", `Remove ${d.platform || "device"}`, async ({ proof }) => R.api.removeDevice(d.id, proof));
    toast(`${d.platform || "Device"} removed. It can no longer reach your vault.`);
    loadDevices();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}
