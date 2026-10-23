// Boot, the connection to the vault server, unlock and lock, the offline copy, and
// the rules for leaving the screen. The one place the app's view changes hands.
import { batch, effect } from "@preact/signals";
import { fromB64 } from "@humid/codec";
import { suite } from "@humid/crypto";
import { adapter as gateAdapter, demoGate, bestHardwareGate, ASSURANCE } from "@humid/gate";
import { openStore } from "@humid/store";
import { HumidApi } from "@humid/api";
import { ml_dsa87 } from "@humid/htp";
import { sealedWallet } from "@humid/pass/atrest";
import { isDuress } from "./duress.js";
import { probeNfc } from "./nfc.js";
import { createLink, isNetworkFailure } from "./link.js";
import * as S from "./state.js";
import { savePrefs, applyPrefs, idleLabel } from "./prefs.js";
import { SERVER_URL, PINNED_KID } from "./config.js";
import { R, wipe } from "./runtime.js";
import { toast, friendly, cancelled, unreachable } from "./notify.js";
import { showInterrupt, endInterrupt, withKeys, sessionKeys, clearKeys } from "./interrupt.js";
import { refresh, closeViewer } from "./vault.js";
import { loadLedger } from "./ledger.js";
import { loadDevices } from "./devices.js";
import { loadRecovery, loadAlerts } from "./recovery.js";
import { loadDuressSetting, loadDuress, loadCheckin, checkinArmed } from "./safety.js";
import { pollJoin } from "./join.js";
import { resumePass } from "./enroll.js";
import { keepDraft, dropDrafts } from "./drafts.js";

/* global __HUMID_SIM__, __HUMID_ALLOW_DEMO__ */

const idleMs = () => S.prefs.value.idleMs; // 1, 2 or 5 minutes (prefs.js caps it at 5)
let link = null;                // the connection monitor (core/link.js)
let idleTimer = null;
let picking = false;            // a system file picker is open: HumID leaves the screen without locking
let pickingTimer = null;
let hiddenAt = 0;               // when HumID last left the screen, while picking
let pickHiddenMs = 0;           // how long this picker may keep HumID off the screen
const PICK_MS = 60_000;         // a picker that hasn't come back by then no longer excuses leaving the screen
const PICK_HIDDEN_MS = 20_000;  // behind the picker for longer than this (another app, the home screen) locks anyway
const PICK_MAX_MS = 90_000;
const PICK_HIDDEN_MAX_MS = 60_000;
let offlineWrite = Promise.resolve();

export const wallet = () => sealedWallet(R.store);

/* ---------------- simulation build: the server inside the app ---------------- */
// Release builds have none of this: with the flag false, startSim is `null` and the
// sim server chunk is never emitted (a conditional expression, not a function
// declaration, so esbuild can drop the dynamic import).
const startSim = (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) ? async () => {
  const { createSimServer } = await import("../sim/server.js");
  R.sim = await createSimServer({
    platformPolicy: (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) ? "demo" : "biometric",
    onCheck: (report) => {
      S.simLog.value = [report, ...S.simLog.value].slice(0, 40);
      if (!report.quiet) setTimeout(() => { S.simShow.value = report; }, report.kind === "enrol" ? 1600 : 900);
    },
  });
  return R.sim;
} : null;

/** Wipe the simulated server and this phone's HumID, and start over. */
export async function resetSimulation() {
  const id = S.identity.value;
  try { if (id?.gate) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await R.store.clearIdentity();
  await R.store.clearVault();
  await R.sim?.reset();
  location.reload();
}

/* ---------------- boot ---------------- */

/**
 * 4.0 messaging: loaded and started once the vault is open, if this server runs a relay
 * (never in the first paint, never offline). Locking stops it and forgets what it decrypted.
 */
function watchMessaging() {
  effect(() => {
    if (S.view.value === "app" && S.messagingOn.value && !S.offline.value && R.msgKey) {
      import("./messaging.js").then((m) => m.start()).catch(() => {});
    }
  });
}

export async function boot() {
  R.store = await openStore();
  watchMessaging();
  R.hooks.keyGone = keyGone;
  S.hwGate.value = await bestHardwareGate();
  probeNfc().then((n) => { S.nfc.value = n; });
  try { S.identity.value = await R.store.getIdentity(); } catch { S.identity.value = null; }
  try { S.pass.value = await wallet().get(); } catch { S.pass.value = null; }
  try { S.offlineReady.value = !!(await R.store.getOffline()); } catch { S.offlineReady.value = false; }
  const id = S.identity.value;
  const raw = (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) ? (await startSim()).fetch : globalThis.fetch.bind(globalThis);
  // A pin compiled into the app always wins over one the record remembers (a record is
  // writable storage; the pin is not).
  R.api = new HumidApi({ baseUrl: id?.server?.url ?? SERVER_URL, pinnedKid: PINNED_KID || id?.server?.kid || null, fetch: watchConnection(raw) });
  // The newest signed policy this device has accepted: an older one served later is a replay.
  R.api.htp.policySeen = id?.policySeen || null;
  // The server no longer knows this session (it expired, or the server restarted and the
  // reconnected channel isn't signed in): either way, one live check signs back in.
  R.api.onSignedOut = () => { if (S.view.value === "app" && !S.offline.value) lock("Your session ended. Unlock to continue."); };
  connectServer();
  if (S.pass.value?.state === "draft" && !id) resumePass(); // an access code was sent but the answer never arrived
  if (id?.pending) { S.joinMethod.value = id.pending.method; S.joinStep.value = 3; S.view.value = "join"; pollJoin(); }
  else S.view.value = id ? "locked" : "welcome";
  wireGlobalEvents();
}

/* ---------------- the connection to the server ---------------- */

/**
 * Every request the app makes goes through here, so the connection monitor hears
 * about each answer and each failure as it happens. 502-504 is a proxy saying the
 * server behind it didn't answer, so it counts as down too.
 */
function watchConnection(raw) {
  const unanswered = (r) => r.status >= 502 && r.status <= 504;
  link = createLink({
    // the server's public key bundle: unauthenticated, cheap, and touches no session
    probe: () => raw(`${R.api.htp.base}/htp/v1/keys`, { cache: "no-store", headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) })
      .then((r) => { if (unanswered(r)) throw new Error(`HTTP ${r.status}`); }),
    onChange: (st) => { S.link.value = st; },
    onUp: reconnected,
  });
  return (...args) => raw(...args).then(
    (r) => { if (unanswered(r)) link.down("unreachable"); else link.up(); return r; },
    (e) => { if (isNetworkFailure(e)) link.down(S.online.value ? "unreachable" : "offline"); throw e; },
  );
}

/** Back in touch with the server: pick up where things were, without asking for anything. */
function reconnected({ downFor }) {
  if (!S.server.value) connectServer();
  const v = S.view.value;
  if (v === "app" && S.offline.value) {
    toast("Your vault is reachable again. Tap Reconnect to sign back in.");
  } else if (v === "app" && S.session.value) {
    // one request first: if the server forgot the session, that's the only one to find out
    refresh().then(() => {
      if (S.view.value !== "app" || !S.session.value) return;
      loadAlerts();
      reloadTab();
      if (downFor > 3000) toast("Reconnected to your vault.");
    });
  } else if (v === "join") {
    pollJoin();
  }
  if (S.pass.value?.state === "draft" && !S.identity.value) resumePass();
}

/** "Reconnect now" on the connection bar. */
export const retryConnection = () => link?.retryNow();

export async function connectServer() {
  S.serverError.value = null;
  try {
    const s = await R.api.server();
    S.server.value = { ...s, url: SERVER_URL || (typeof location !== "undefined" ? location.origin : ""), simulated: (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) };
    await rememberPolicy();
  } catch (e) {
    S.server.value = null;
    S.serverError.value = friendly(e);
  }
}

/**
 * Keep the newest signed policy in the identity record, so a replayed older one is refused
 * after a restart too (round 2 of CRYPTO-07). It's the server's signed statement, checked
 * again on every load, so it needs no sealing; it's read before unlock, to draw the screens.
 */
async function rememberPolicy() {
  const id = S.identity.value, seen = R.api.htp.policySeen;
  if (!id || !seen || (id.policySeen && id.policySeen.at >= seen.at)) return;
  // TODO(merge): route through updateIdentity (core/identity.js, PR #71) once both are on one branch.
  const record = { ...id, policySeen: { policy: seen.policy, at: seen.at, sig: seen.sig } };
  delete record.schema;
  try { await R.store.putIdentity(record); S.identity.value = { ...record, schema: id.schema ?? 4 }; } catch { /* next connection tries again */ }
}

/**
 * App builds pin their server at build time, so there's no trust decision to ask a person
 * to make: skip that step when the server answering is the pinned one.
 */
export const serverPinned = () => !!PINNED_KID && String(S.server.value?.kid || "").toLowerCase() === PINNED_KID.toLowerCase();

/** The gate to bind on this device: the live-biometric gate, or demo in a development build. */
export function chooseGate(useDemo) {
  if (useDemo) {
    if (!S.demoAllowed.value) { toast("HumID needs a face or fingerprint check.", "warn"); return null; }
    return demoGate();
  }
  const hw = S.hwGate.value;
  if (!hw?.probe.available) { toast(hw?.probe.reason || "This device has no face or fingerprint sensor HumID can use.", "warn"); return null; }
  return hw.adapter;
}
export const serverRecord = (srv, extra = {}) => ({ url: SERVER_URL, kid: srv.kid, fingerprint: srv.fingerprint, ...extra });
export const gateClaim = (gate) => (gate.needsHold
  ? { gateMethod: "demo-no-hardware", assurance: ASSURANCE.NONE }
  : { gateMethod: S.hwGate.value?.probe.method, assurance: S.hwGate.value?.probe.assurance });

/* ---------------- leaving the screen, idling ---------------- */

let resetIdle = () => {};
function wireGlobalEvents() {
  const reset = () => {
    clearTimeout(idleTimer);
    if (S.view.value === "app") {
      idleTimer = setTimeout(idleLock, idleMs());
      S.idleDeadline.value = Date.now() + idleMs();
    }
  };
  // The idle lock waits for a running check to finish rather than skipping: a prompt left
  // open on the table still ends in a locked app.
  const idleLock = () => { if (R.busy) { idleTimer = setTimeout(idleLock, 5000); return; } lock(`Locked after ${idleLabel(idleMs())} without activity.`); };
  // Opening the app (unlock, a finished setup or join) always starts at the vault.
  let wasApp = false;
  S.view.subscribe((v) => {
    if (v === "app") { if (!wasApp) S.tab.value = "vault"; reset(); }
    wasApp = v === "app";
  });
  resetIdle = reset;
  for (const ev of ["pointerdown", "keydown"]) document.addEventListener(ev, reset, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      // back from the picker (or another app) while picking: if it was away long, lock anyway
      if (picking && hiddenAt && Date.now() - hiddenAt > (pickHiddenMs || PICK_HIDDEN_MS) && S.view.value === "app") { stopPicking(); lock("Locked when HumID left the screen."); }
      hiddenAt = 0;
      return;
    }
    if (S.view.value !== "app" || R.busy) return;
    if (!picking) return lock("Locked when HumID left the screen.");
    // the file picker is up (it normally comes back within seconds): lock if that's not what this is
    hiddenAt = Date.now();
    setTimeout(() => { if (document.hidden && picking && hiddenAt && S.view.value === "app") { stopPicking(); lock("Locked when HumID left the screen."); } }, pickHiddenMs || PICK_HIDDEN_MS);
  });
  // leaving the page entirely (closed, navigated, suspended) is never a file picker
  addEventListener("pagehide", () => { stopPicking(); if (S.view.value === "app" && !R.busy) lock(); });
  addEventListener("focus", () => setTimeout(stopPicking, 1200));
  addEventListener("online", () => { S.online.value = true; link?.online(true); if (!S.server.value) connectServer(); });
  addEventListener("offline", () => { S.online.value = false; link?.online(false); });
  // retries pause while HumID is off the screen, and resume when it's back
  document.addEventListener("visibilitychange", () => link?.visible(!document.hidden));
  if (!S.online.value) link?.online(false);
}

/**
 * A system screen HumID opened is about to cover it (a file picker, the phone's document
 * scanner): leaving the screen for it isn't leaving HumID. Bounded: it clears itself after
 * forMs (a minute), and HumID locks if it stays off the screen longer than hiddenMs (20 s).
 */
export const markPicking = ({ forMs = PICK_MS, hiddenMs = PICK_HIDDEN_MS } = {}) => {
  picking = true;
  pickHiddenMs = Math.min(hiddenMs, PICK_HIDDEN_MAX_MS);
  clearTimeout(pickingTimer);
  pickingTimer = setTimeout(stopPicking, Math.min(forMs, PICK_MAX_MS));
};
function stopPicking() { picking = false; hiddenAt = 0; pickHiddenMs = 0; clearTimeout(pickingTimer); pickingTimer = null; }

/** Change preferences: saved on this device, applied now. */
export function setPref(patch) {
  const p = savePrefs({ ...S.prefs.value, ...patch });
  S.prefs.value = p;
  applyPrefs(p);
  if ("idleMs" in patch) resetIdle();
}

/* ---------------- unlock / lock ---------------- */

/**
 * Unlock. `used` is what the Lock screen saw: false for a plain unlock, "hold" or "taps"
 * when that gesture was made, or true for "the duress gesture, whichever it is" (a
 * decoy session reconnecting). Which gesture means duress is sealed on the device
 * (core/duress.js) and opens only inside the live check, so the decision decoy-or-real
 * is made AFTER the check: the session opens exactly the same way, then shows only
 * decoy documents while the server silently locks sensitive changes. Every unlock
 * reports presence, so the two look the same on the wire.
 */
export async function unlock(used = false) {
  const id = S.identity.value;
  if (!id?.server?.id) return toast("This identity is not registered with a vault server.", "error");
  const wasOffline = !!S.offline.value;
  if (!wasOffline && !S.online.value && S.offlineReady.value) return unlockOffline(used);
  let duress = false;
  try {
    showInterrupt({ purpose: "launch", label: "Unlock HumID", state: "scanning", progress: 0.04, needsHold: false, message: "Connecting to your vault…" });
    const sess = await R.api.login({
      id: id.server.id,
      device: id.device?.id || "dev_" + "0".repeat(24),
      // The secure chip signs the server's sign-in challenge during the live check.
      // The duress decision is made inside the check and signed into the sign-in itself
      // (PC-01), so it can't be sent, or forged, by anything that only holds a session.
      sign: (message, { presence }) => withKeys("launch", "Unlock HumID", async ({ dkeys, seed, interrupt, live, Suite }) => {
        sessionKeys(Suite, seed);
        duress = isDuress(await loadDuressSetting(Suite), used, { unreadable: R.duressUnreadable });
        showInterrupt({ progress: 0.75, message: "Signing in with this device's key…" });
        const d = duress ? 1 : 0;
        return { sig: ml_dsa87.sign(presence(d), dkeys.dsaSk), d, interrupt, live: live?.sig };
      }, { keepOpen: true, challenge: message }),
    });
    batch(() => { S.session.value = sess; S.offline.value = null; S.decoy.value = duress; });
    if (!S.server.value) await connectServer(); // its policy says whether it offers Heartbeat
    await loadCheckin(); // before anything is saved on this device: while Heartbeat is armed, nothing is
    R.offline = duress || checkinArmed() ? null : await readOffline();
    batch(() => { S.lockIssue.value = null; S.view.value = "app"; });
    await endInterrupt(true, wasOffline ? "Back online." : "Welcome back.", 500);
    refresh();
    loadAlerts();
    if (wasOffline) reloadTab();
  } catch (e) {
    const issue = ["unknown_identity", "server_identity_changed", "device_removed", "device_not_proven", "key_invalidated"].includes(e?.code);
    // This device was removed, or the server isn't the one it trusted: its offline copy goes too.
    if (issue) { await R.store.clearOffline().catch(() => {}); S.offlineReady.value = false; dropDrafts(); }
    if (wasOffline && !issue) {
      if (S.interrupt.value && S.interrupt.value.state !== "failed") await endInterrupt(false, cancelled(e) ? friendly(e) : "Still can't reach your vault server.", 1400);
      else if (!S.interrupt.value && !cancelled(e)) toast("Still can't reach your vault server.", "warn");
      return;
    }
    clearKeys();
    batch(() => { S.session.value = null; S.decoy.value = false; S.checkin.value = null; });
    if (wasOffline) lock();
    if (issue) S.lockIssue.value = e.code;
    // No connection: open the offline copy with a live check of its own.
    if (!issue && unreachable(e) && S.offlineReady.value) { S.interrupt.value = null; return unlockOffline(used); }
    if (S.interrupt.value && S.interrupt.value.state !== "failed") await endInterrupt(false, friendly(e), 1600);
    else if (!S.interrupt.value && !cancelled(e) && !issue) toast(friendly(e), "error");
  }
}

/**
 * Android or iOS deleted this device's biometric key (its fingerprints or face changed,
 * or HumID was reinstalled and its data came back from a backup). Nothing can unlock
 * this identity here again, so say so and offer to set this device up again.
 */
function keyGone() {
  R.store?.clearOffline().catch(() => {});
  S.offlineReady.value = false;
  dropDrafts();
  if (S.view.value === "app") lock();
  if (S.view.value === "join") { S.view.value = "locked"; }
  S.lockIssue.value = "key_invalidated";
}

/* ---------------- offline ---------------- */
// While HumID can't reach the vault, a live check still opens a read-only copy kept on
// this device: the document list, devices, recovery status, duress status and recent
// activity, as of the last time it was online. Never a document, never a document's key.

/** The offline copy for this account, opened with the session's key; null if there's none (or it doesn't open). */
async function readOffline() {
  try {
    const rec = await R.store.getOffline();
    if (!rec || !R.offlineKey || rec.account !== S.identity.value?.server?.id) return null;
    const copy = await suite(S.identity.value?.suite).openOffline(R.offlineKey, rec.blob);
    return copy?.v === 1 && copy.account === rec.account ? copy : null;
  } catch { return null; }
}

/** Update part of the offline copy. Only from a real, online session. */
export function keepOffline(patch) {
  const account = S.identity.value?.server?.id;
  if (S.offline.value || S.decoy.value || checkinArmed() || !R.offlineKey || !account || !R.store) return;
  R.offline = { ...(R.offline || {}), ...patch, v: 1, account, savedAt: new Date().toISOString() };
  const copy = R.offline, key = R.offlineKey.slice();
  offlineWrite = offlineWrite.then(async () => {
    try {
      const blob = await suite(S.identity.value?.suite).sealOffline(key, copy);
      if (S.identity.value?.server?.id !== account) return; // erased or reset meanwhile
      await R.store.putOffline(blob, account);
      S.offlineReady.value = true;
    }
    catch { /* best effort: the vault is still the source of truth */ }
    finally { wipe(key); }
  });
}

/** Read-only, from the copy on this device, after a live check on this device. */
async function unlockOffline(used) {
  let duress = false;
  try {
    await withKeys("launch", "Unlock HumID (offline)", async ({ seed, Suite }) => {
      showInterrupt({ progress: 0.7, message: "No connection to your vault. Opening the copy saved on this device…" });
      sessionKeys(Suite, seed);
      duress = isDuress(await loadDuressSetting(Suite), used, { unreadable: R.duressUnreadable });
    });
    const copy = await readOffline();
    if (!copy) {
      clearKeys();
      return toast("Nothing is saved on this device yet. Connect once to use HumID offline.", "warn");
    }
    R.offline = copy;
    batch(() => {
      S.session.value = null; S.lockIssue.value = null; S.decoy.value = duress;
      S.offline.value = { savedAt: copy.savedAt };
      S.view.value = "app";
    });
    refresh();
    loadAlerts();
  } catch (e) {
    clearKeys();
    if (!cancelled(e) && !S.interrupt.value) toast(friendly(e), "error");
  }
}

/** Back online: one live check signs in and replaces the offline copy with the vault. A decoy session stays a decoy session. */
export function reconnect() { return unlock(S.decoy.value); }

/** After reconnecting, load what the open tab shows from the vault instead of the copy. */
export function reloadTab() {
  if (S.tab.value === "activity") loadLedger();
  if (S.tab.value === "you") { loadRecovery(); loadDuress(); }
  loadDevices();
  if (S.tab.value === "vault" && !S.decoy.value) loadRecovery();
}

/**
 * Lock: keys wiped, session ended, everything the vault showed forgotten. What survives
 * is a draft of what the person was in the middle of (core/drafts.js): typed text for
 * ten minutes, a captured page for two, so an incoming call doesn't cost them the form.
 */
export function lock(reason) {
  if (S.view.value !== "app") return;
  if (!S.offline.value) R.api.logout();
  R.epoch++; // anything still in flight for this session is dropped when it lands
  clearKeys(); R.offline = null;
  R.knownNames.clear();
  clearTimeout(idleTimer);
  R.hooks.stopCheckinWatch?.();
  R.hooks.stopMessaging?.();
  keepDraft();
  batch(() => {
    S.view.value = "locked";
    S.checkin.value = null;
    S.session.value = null;
    S.items.value = [];
    S.ledger.value = null;
    S.devices.value = null;
    S.recovery.value = null;
    S.alerts.value = [];
    S.protecting.value = [];
    S.station.value = null;
    S.duressInfo.value = null;
    S.continuity.value = null;
    S.decoy.value = false;
    S.offline.value = null;
    S.sheet.value = null;
    S.push.value = null;
    closeViewer();
  });
  if (reason) toast(reason, "warn");
}
export const lockNow = () => lock("Locked.");
