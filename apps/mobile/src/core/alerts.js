// What the first paint needs from recovery: alerts about recoveries of this account (the
// vault's banner, Cancel it), and a new recovery card kept across a lock (shown again after a
// real unlock). The rest of recovery (core/recovery.js and @humid/recovery) loads with the
// screens that use it (core/setup.js).
import * as S from "./state.js";
import { R, epoch, stale } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp } from "./interrupt.js";
import { clearDraft, current as draftNow, CARD_DRAFT } from "./drafts.js";

/* ---------------- alerts: recoveries of this account ---------------- */

export async function loadAlerts() {
  if (S.decoy.value) { S.alerts.value = []; return; } // a decoy session sees a calm account
  if (S.offline.value) return; // recoveries in progress are a live question: shown once back online
  const ep = epoch();
  const a = await R.api.alerts().catch(() => null);
  if (stale(ep)) return;
  if (a) S.alerts.value = a;
  R.api.protectingAlerts().then((p) => { if (!stale(ep)) S.protecting.value = p; }).catch(() => {});
}

export async function cancelRecovery(alert) {
  try {
    await withStepUp("cancelAlert", [alert.ref], "cancel", "Cancel this recovery", async ({ proof }) => R.api.cancelAlert(alert.ref, proof));
    toast("Cancelled. That device gets nothing.");
    loadAlerts();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/** The new card was checked (or the holder chose to close it unsaved): forget it everywhere. */
export function forgetNewCard() {
  S.cardCode.value = null;
  clearDraft(CARD_DRAFT);
}

/** After a real unlock: show the new card kept across the lock (takeDraft has checked its age). */
export function resumeNewCard(d) {
  if (d?.kind !== CARD_DRAFT || !d.state?.code || S.decoy.value) return false;
  draftNow.value = d; // its original time: the ten minutes run from when the card was made
  S.cardCode.value = d.state.code;
  S.push.value = null;
  S.tab.value = "you";
  return true;
}
