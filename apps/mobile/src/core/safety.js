// Safety under force: the duress gesture and the Heartbeat timer (docs/CHECKIN.md; the
// server and its API still call it check-in).
//
// Duress: the setting lives on this device (which gesture), sealed under a key from the
// account seed (core/duress.js): nothing on disk says whether it's on or which gesture
// it is. What it changes lives on the server (lockdown, slower recoveries, witness
// alerts). Screens read the opened setting from S.duressInfo.value.setting.
//
// Heartbeat: a timer the holder arms before a high-stakes situation: one live check
// before each deadline, or the vault locks, then is erased for good. The server holds
// the clock and the keys; this keeps the app's view fresh and asks for the checks.
import { suite } from "@humid/crypto";
import * as S from "./state.js";
import { sealDuress, openDuress, DEFAULT as DURESS_OFF } from "./duress.js";
import { R, epoch, stale } from "./runtime.js";
import { toast, friendly, cancelled, buzz } from "./notify.js";
import { withStepUp, needVault } from "./interrupt.js";
import { keepOffline } from "./session.js";
import { updateIdentity } from "./identity.js";

/* ---------------- duress ---------------- */

/** Inside a live check: the setting this device sealed, re-sealing one an older release left in the clear. */
export async function loadDuressSetting(Suite) {
  const id = S.identity.value;
  const { setting, record, unreadable } = await openDuress(Suite, R.settingsKey, id);
  R.duressUnreadable = !!unreadable;
  if (record) {
    // Only the sealed setting changes, and only if nothing sealed a newer one meanwhile.
    try {
      await updateIdentity((cur) => {
        if (cur.duressSealed !== id.duressSealed) return null;
        cur.duressSealed = record.duressSealed;
        cur.duressSealedAt = record.duressSealedAt;
        delete cur.duress;
      });
    } catch { /* next unlock tries again */ }
  }
  R.duressSetting = setting;
  return setting;
}

/**
 * The setting as the session opened it ({ enabled, gesture }); "off" before unlock. A decoy
 * session sees "off" (the screen promises nothing will say duress is on), or what it saved itself.
 */
const currentDuress = () => {
  if (S.decoy.value) { const e = S.decoyEcho.value; return e ? { enabled: !!e.enabled, gesture: e.gesture === "hold" ? "hold" : "taps" } : { ...DURESS_OFF }; }
  return R.duressSetting ? { ...R.duressSetting } : { ...DURESS_OFF };
};

export async function saveDuress({ enabled, gesture }) {
  if (S.decoy.value) {
    // the same words as a real save; nothing is saved, the screen only echoes it until the lock
    S.decoyEcho.value = { ...(S.decoyEcho.value || {}), enabled: !!enabled, gesture };
    S.duressInfo.value = { ...(S.duressInfo.value || {}), setting: currentDuress() };
    toast(enabled ? "Duress protection is on." : "Duress protection is off.");
    return true;
  }
  try {
    await updateIdentity((cur) => sealDuress(suite(cur.suite), R.settingsKey, cur, { enabled, gesture }));
    R.duressSetting = { enabled: !!enabled, gesture: gesture === "hold" ? "hold" : "taps" };
    S.duressInfo.value = { ...(S.duressInfo.value || {}), setting: currentDuress() };
  } catch (e) { toast(friendly(e), "error"); return false; }
  toast(enabled ? "Duress protection is on." : "Duress protection is off.");
  return true;
}

export async function loadDuress() {
  if (S.decoy.value) { S.duressInfo.value = { lockdown: false, setting: currentDuress() }; return; }
  if (S.offline.value) { S.duressInfo.value = { ...(R.offline?.duress || { lockdown: false }), setting: currentDuress() }; return; }
  const ep = epoch();
  const [st, settings] = await Promise.all([R.api.duressStatus().catch(() => null), R.api.settings().catch(() => null)]);
  if (stale(ep)) return;
  const info = { ...(st || {}), alert: !!settings?.duressAlert };
  S.duressInfo.value = { ...info, setting: currentDuress() };
  if (st && settings) keepOffline({ duress: info });
}

export async function setWitnessAlert(on) {
  try {
    await withStepUp("setSettings", [], "settings", on ? "Let witnesses see duress" : "Stop duress alerts", async ({ proof }) => R.api.setSettings({ duressAlert: !!on }, proof));
    toast(on ? "Your witnesses will see a duress signal when they open HumID." : "Witnesses won't be told.");
    loadDuress();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function clearLockdown() {
  try {
    const r = await withStepUp("clearDuress", [], "duress", "Lift lockdown", async ({ proof }) => R.api.clearDuress(proof));
    toast(r.cleared ? "Lockdown lifted." : "There was no lockdown.");
    loadDuress();
  } catch (e) { if (!cancelled(e)) toast(e?.code === "too_soon" ? "Lockdown can be lifted once things have been calm for a while. Try again later." : friendly(e), "error"); }
}

/* ---------------- Heartbeat (the server's "check-in") ---------------- */

let checkinTimer = null;
const warned = { deadline: 0, at: new Set() };
/** Is Heartbeat armed (or locked by a missed beat)? While it is, nothing is kept on this device. */
export const checkinArmed = () => ["armed", "locked"].includes(S.checkin.value?.state);
/** Does this server offer Heartbeat? (Its policy hint; the gateway enforces it.) */
export const checkinOffered = () => !!S.server.value?.policy?.checkin;
R.hooks.stopCheckinWatch = () => clearTimeout(checkinTimer);
R.hooks.loadCheckin = () => loadCheckin();

/** The offline copy goes, and none is written, while Heartbeat is armed: a phone held offline must show nothing. */
function dropOfflineCopy() {
  R.offline = null;
  R.store?.clearOffline().catch(() => {});
  S.offlineReady.value = false;
}

/**
 * The server's clock against this phone's, from the Date header of the last answer: the
 * countdown is shown in server time, so a skewed phone can't mislead about an erase.
 */
export const clockOffset = () => R.api?.htp?.clockOffsetMs?.() ?? 0;

export async function loadCheckin() {
  if (!checkinOffered() || S.offline.value || !S.session.value) { S.checkin.value = null; return; }
  const ep = epoch();
  try {
    const st = await R.api.checkin();
    if (stale(ep)) return;
    S.checkin.value = { ...st, offsetMs: clockOffset() };
    if (checkinArmed()) dropOfflineCopy();
  } catch { /* keep what's shown; the next look tries again */ }
  watchCheckin();
}

/** Look again around the next moment that matters (the deadline, the erase); otherwise every five minutes. Warn as it nears. */
function watchCheckin() {
  clearTimeout(checkinTimer);
  const st = S.checkin.value;
  if (!st || !checkinArmed()) return;
  const now = Date.now() + (st.offsetMs || 0);
  const next = st.state === "armed" ? st.deadline : st.erasesAt;
  const left = next - now;
  // near a deadline look every minute; otherwise the warnings below are local, so five minutes is enough
  checkinTimer = setTimeout(loadCheckin, Math.max(1000, Math.min(left <= 35 * 60_000 ? 60_000 : 300_000, left + 500)));
  if (S.view.value !== "app") return;
  if (warned.deadline !== st.deadline) { warned.deadline = st.deadline; warned.at.clear(); }
  if (st.state === "locked") {
    if (!warned.at.has("missed")) { warned.at.add("missed"); buzz([60, 80, 60]); toast(`Heartbeat missed. Check in now, or your vault is erased at ${clock(st.erasesAt)}.`, "error"); }
    return;
  }
  const toDeadline = st.deadline - now;
  for (const m of [2, 10, 30]) {
    if (toDeadline <= m * 60_000 && !warned.at.has(m)) {
      for (const k of [2, 10, 30]) if (k >= m) warned.at.add(k);
      buzz([40, 60, 40]);
      toast(`Heartbeat due within ${m} minutes, by ${clock(st.deadline)}.`, "warn");
      break;
    }
  }
}
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

/**
 * Turn Heartbeat on, or change its settings (which starts a new window). Documents marked
 * for the decoy view are kept out of the erase. Returns { ok } or { unsplit: [{ id, name }] }.
 */
export async function armCheckin({ windowMs, maxWindowMs, graceMs }) {
  const was = S.checkin.value?.state;
  try {
    needVault();
    const keep = S.decoy.value ? [] : S.items.value.filter((i) => i.decoy).map((i) => i.id);
    const st = await withStepUp("armCheckin", [], "checkin", checkinArmed() ? "Change Heartbeat" : "Turn on Heartbeat",
      async ({ proof }) => R.api.armCheckin({ windowMs, maxWindowMs, graceMs, keep }, proof));
    S.checkin.value = { ...st, offsetMs: clockOffset() };
    dropOfflineCopy();
    watchCheckin();
    toast(was === "armed" || was === "locked" ? `Heartbeat changed. Next by ${clock(st.deadline)}.` : `Heartbeat is on. Next by ${clock(st.deadline)}.`);
    return { ok: true };
  } catch (e) {
    if (cancelled(e)) return { ok: false };
    if (e?.code === "unsplit_items") return { ok: false, unsplit: (e.details?.items || []).map((id) => ({ id, name: R.knownNames.get(id) || "An older document" })) };
    toast(friendly(e), "error");
    return { ok: false };
  }
}

/** A heartbeat: one live check, and the next deadline from now (nextWindowMs: a longer one, up to the maximum). */
export async function checkIn(nextWindowMs) {
  try {
    needVault();
    const st = await withStepUp("checkIn", [], "checkin", "Heartbeat", async ({ proof }) => R.api.checkIn({ nextWindowMs }, proof));
    S.checkin.value = { ...st, offsetMs: clockOffset() };
    watchCheckin();
    toast(`Heartbeat sent. Next by ${clock(st.deadline)}.`);
    return true;
  } catch (e) {
    if (!cancelled(e)) toast(friendly(e), "error");
    loadCheckin();
    return false;
  }
}

export async function disarmCheckin() {
  try {
    needVault();
    const st = await withStepUp("disarmCheckin", [], "checkin", "Turn off Heartbeat", async ({ proof }) => R.api.disarmCheckin(proof));
    S.checkin.value = { ...st, offsetMs: clockOffset() };
    watchCheckin();
    toast("Heartbeat is off. Nothing will be erased.");
    return true;
  } catch (e) {
    if (!cancelled(e)) toast(friendly(e), "error");
    loadCheckin();
    return false;
  }
}
