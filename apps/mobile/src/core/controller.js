// Everything the app does, in one place. Screens call these functions and read
// the signals in state.js. Rules enforced here:
//   - private keys exist only inside one biometric check (withKeys, or a
//     registration / join step) and are wiped right after;
//   - every check is a LIVE biometric (face or fingerprint): no PIN, no
//     password. On phones the secure chip's liveness key signs a challenge
//     known BEFORE the prompt opens — the sign-in message, a step-up ticket
//     naming the exact request, or a sealed file's hash — so the server can
//     verify that a live check approved precisely that.
//
// Keys on a device (docs/RECOVERY.md):
//   account seed A   shared by all of the holder's devices. Its keys seal and open
//                    documents, encrypt the index, and authorise new devices.
//   device seed D    this device only. Its ML-DSA-87 key signs in and signs every
//                    step-up proof, so one device can be removed without the others.
// The biometric gate releases one secret that unwraps A ‖ D.

import { batch } from "@preact/signals";
import { toB64, fromB64, toHex, MEDIA_TYPE, EXTENSION } from "@humid/codec";
import { suite, random, splitWrap, splitUnwrap, isSplit } from "@humid/crypto";
import { adapter as gateAdapter, demoGate, bestHardwareGate, CANCELLED, ASSURANCE } from "@humid/gate";
import { openStore } from "@humid/store";
import { saveBytes, readFile } from "@humid/io";
import { HumidApi, ApiError } from "@humid/api";
import { ml_dsa87, identityId, sealLiveMessage, b64u } from "@humid/htp";
import {
  newCard, parseCard, cardTag, sealCard, openCard, formatCode,
  split, combine, thresholdFor, encodeShare, decodeShare, MIN_CONTACTS, MAX_CONTACTS,
  quorumParts, encodeQuorumPart, decodeQuorumPart, combineQuorum, sealCardPart, openCardPart, QUORUM, accountCheck,
} from "@humid/recovery";
import { readDocument } from "@humid/emrtd";
import { MEDIA_TYPE as ID_TYPE, encodeRecord, decodeRecord, summary as idSummary, readDg1, readDg2, checkIntegrity, applyChip, setImage } from "@humid/idscan";
import { MEDIA_TYPE as CARD_TYPE, encodeCard, decodeCard, summary as cardSummary, readContactless, readCardText, readCardBack } from "@humid/cards";
import { parseAccessCode } from "@humid/pass";
import { probeNfc, openChip } from "./nfc.js";
import { textReader } from "./scan.js";
import { readPkpass, passIndex, MEDIA_TYPE as PASS_TYPE, APPLE_ROOTS, WalletError } from "@humid/wallet";
import { createLink, isNetworkFailure } from "./link.js";
import * as S from "./state.js";
import { savePrefs, applyPrefs, idleLabel } from "./prefs.js";
import { validStamp, REASONS } from "./place.js";
import { sealDuress, openDuress, isDuress, DEFAULT as DURESS_OFF } from "./duress.js";
import { SERVER_URL, PINNED_KID, PLATFORM } from "./config.js";

/* global __HUMID_SIM__, __HUMID_ALLOW_DEMO__ */
// Build flags (build.mjs `define`, always a literal true/false; `tools/dev.mjs` sets both):
//   __HUMID_SIM__          simulation build: the vault server runs inside the app
//   __HUMID_ALLOW_DEMO__   development build: demo gate, demo passports, /dev endpoints
// They're tested INLINE below (the spelled-out `typeof … && … === true`), never through
// an imported or local constant or a helper: esbuild folds a define only where it
// appears, at parse time, and that's what makes every simulation and demo branch,
// startSim and the ../sim/server.js chunk disappear from release builds
// (tests/bundle.test.js). Under Node (tests) the defines don't exist: false.

const idleMs = () => S.prefs.value.idleMs; // 1, 2 or 5 minutes (prefs.js caps it at 5)
const MAX_FILE = 50 * 1024 * 1024;
const SEED = 64;
const CARD = 15;          // a seal card's secret
const DURESS_HOLD_MS = 1800;
export { DURESS_HOLD_MS };
const KEY_TYPE = "application/x-humid-key";
const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const utf8 = (s) => new TextEncoder().encode(s);
/** For checks no server verifies (seeing whose pieces you hold): still a live check, fresh challenge. */
const localChallenge = (purpose) => concat(utf8(`HUMID-LOCAL-v1 ${purpose} `), random(32));

let store = null;
let api = null;
let indexKey = null;        // decrypts item names while unlocked; wiped on lock
let offlineKey = null;      // seals this device's offline copy while unlocked; wiped on lock
let settingsKey = null;     // opens this device's sealed settings (duress gesture) while unlocked; wiped on lock
let duressSetting = null;   // { enabled, gesture } once a live check opened it; cleared on lock
let offline = null;         // the offline copy, as last saved (in memory while unlocked)
let offlineWrite = Promise.resolve();
let busy = false;
let picking = false;        // a system file picker is open: HumID leaves the screen without locking
let pickingTimer = null;
let hiddenAt = 0;           // when HumID last left the screen, while picking
const PICK_MS = 60_000;     // a picker that hasn't come back by then no longer excuses leaving the screen
const PICK_HIDDEN_MS = 20_000; // behind the picker for longer than this (another app, the home screen) locks anyway
let idleTimer = null;
let holdWaiter = null;
let joinTimer = null;
let link = null;            // the connection monitor (core/link.js)
const knownNames = new Map(); // object id -> name, so the activity log can show names of deleted items

/* ---------------- toasts ---------------- */

export function toast(text, kind = "ok") {
  if (!text) return; // e.g. a lost session: the lock screen says it once, not every failed request
  if (text === UNREACHABLE && S.link.value.state === "down") return; // the connection bar already says so
  const id = Math.random().toString(36).slice(2);
  S.toasts.value = [...S.toasts.value, { id, text, kind }].slice(-3);
  setTimeout(() => { S.toasts.value = S.toasts.value.filter((t) => t.id !== id); }, kind === "error" ? 5200 : 3600);
}

const UNREACHABLE = "Can't reach your vault server. Check your connection.";
// The server has forgotten this session (it expired or restarted). The app locks with
// "Your session ended"; the requests that hit it say nothing more.
const SESSION_LOST = new Set(["session_unknown", "session_expired", "sign_in_required"]);
const friendly = (e) => {
  if (SESSION_LOST.has(e?.code)) return null;
  if (e?.name === "NotAllowedError" || e?.message === CANCELLED) return "The biometric check was cancelled.";
  if (e?.code === "server_identity_changed") return "This server's identity changed. HumID refused to connect.";
  if (e?.code === "key_invalidated") return "This phone's HumID key is gone: its fingerprints or face changed, or HumID was reinstalled.";
  if (e?.code === "offline") return "You're offline. Opening or changing anything needs a connection to your vault.";
  if (e instanceof TypeError || e?.code === "server_unreachable") return UNREACHABLE;
  return e?.message || "Something went wrong.";
};
const cancelled = (e) => e?.name === "NotAllowedError" || e?.message === CANCELLED;
const quietly = (p) => p.catch((e) => { if (!cancelled(e)) toast(friendly(e), "error"); return null; });

/* ---------------- the biological interrupt ---------------- */

function gateLabel(method) {
  return ({
    "ios-keychain-biometry": "Face ID or Touch ID",
    "android-keystore-biometric": "your face or fingerprint",
    "macos-keychain-biometry": "Touch ID",
    "windows-winbio-fingerprint": "your fingerprint",
    "linux-fprintd-keyring": "your fingerprint",
  })[method] || "your face or fingerprint";
}

function showInterrupt(patch) { S.interrupt.value = { ...(S.interrupt.value || {}), ...patch }; }
const holdMessage = "Demo mode has no sensor. Press and hold to stand in for it.";

/** Called by the overlay's press-and-hold control (demo gate, development builds only). */
export function holdComplete() { holdWaiter?.resolve(); holdWaiter = null; }
export function holdCancel() { holdWaiter?.reject(new Error(CANCELLED)); holdWaiter = null; }
const waitForHold = (gate) => gate.needsHold ? new Promise((resolve, reject) => { holdWaiter = { resolve, reject }; }) : null;

/** A short buzz when a check passes, a distinct one when it fails (Android; iPhones have no web vibration). */
function haptic(ok) {
  buzz(ok ? 18 : [40, 70, 40]);
}

async function endInterrupt(ok, message, ms) {
  if (ok || message !== "The biometric check was cancelled.") haptic(ok);
  showInterrupt({ state: ok ? "verified" : "failed", needsHold: false, progress: 1, message });
  await sleep(ms);
  S.interrupt.value = null;
}

/**
 * Run fn with this device's keys, inside ONE live biometric check. The gate
 * signs `challenge` with the device's liveness key during that check.
 * fn gets { keys (account), dkeys (device), seed (account seed), interrupt, rec, live, Suite }.
 */
async function withKeys(purpose, label, fn, { keepOpen = false, challenge, attest } = {}) {
  const id = S.identity.value;
  const Suite = suite(id.suite);
  let gate;
  busy = true;
  let secret, both, keys, dkeys;
  try {
    gate = gateAdapter(id.gate.adapter);
    showInterrupt({ purpose, label, state: "scanning", progress: 0.08, needsHold: !!gate.needsHold,
      message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
    if (!id.device) throw Object.assign(new Error("This HumID was made by an earlier test version and has to be set up again."), { code: "unknown_identity" });
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose, prompt: label, challenge: challenge ?? localChallenge(purpose), attest });
    secret = rel.secret;
    showInterrupt({ needsHold: false, progress: 0.45, message: rel.live ? "Your phone's secure chip confirmed a live check. Unlocking your keys…" : "Unlocking your keys on this device…" });
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    const seed = both.subarray(0, SEED);
    keys = Suite.deriveKeys(seed);
    dkeys = Suite.deriveKeys(both.subarray(SEED, 2 * SEED));
    if (toB64(keys.dsaPk) !== id.pub.dsaPk || toB64(dkeys.dsaPk) !== id.device.dsaPk) throw new Error("Unlocked keys do not match this identity.");
    const interrupt = { method: rel.interrupt.method, assurance: rel.interrupt.assurance };
    const out = await fn({ keys, dkeys, seed, interrupt, rec: rel.interrupt, live: rel.live, Suite });
    if (keepOpen) showInterrupt({ progress: 0.85, message: "Keys wiped from memory. Waiting for your vault to confirm…" });
    else await endInterrupt(true, "Verified. Keys wiped from memory.", 620);
    return out;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1600);
    if (e?.code === "key_invalidated") keyGone();
    throw e;
  } finally {
    wipe(secret, both);
    if (keys) Suite.wipeKeys(keys);
    if (dkeys) Suite.wipeKeys(dkeys);
    setTimeout(() => { busy = false; }, 600);
  }
}

/**
 * A step-up: reserve the request slot first, let the liveness key sign that
 * slot during the check, then send the request with both signatures.
 * fn gets withKeys' arguments plus `proof`, to pass as the API call's stepUp.
 */
async function withStepUp(op, args, purpose, label, fn) {
  needVault();
  const ticket = await api.ticket(op, ...args);
  return withKeys(purpose, label, (k) => fn({
    ...k,
    proof: { ticket, sign: async (message) => ({ sig: ml_dsa87.sign(message, k.dkeys.dsaSk), interrupt: k.interrupt, live: k.live?.sig }) },
  }), { challenge: ticket.live });
}

/* ---------------- simulation build: the server inside the app ---------------- */

// Release builds have none of this: with the flag false, startSim is `null` and the
// sim server chunk is never emitted (a conditional expression, not a function
// declaration, so esbuild can drop the dynamic import).
let sim = null;
const startSim = (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) ? async () => {
  const { createSimServer } = await import("../sim/server.js");
  sim = await createSimServer({
    platformPolicy: (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) ? "demo" : "biometric",
    onCheck: (report) => {
      S.simLog.value = [report, ...S.simLog.value].slice(0, 40);
      if (!report.quiet) setTimeout(() => { S.simShow.value = report; }, report.kind === "enrol" ? 1600 : 900);
    },
  });
  return sim;
} : null;

/** Wipe the simulated server and this phone's HumID, and start over. */
export async function resetSimulation() {
  const id = S.identity.value;
  try { if (id?.gate) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  await sim?.reset();
  location.reload();
}

/* ---------------- boot ---------------- */

export async function boot() {
  store = await openStore();
  S.hwGate.value = await bestHardwareGate();
  probeNfc().then((n) => { S.nfc.value = n; });
  try { S.identity.value = await store.getIdentity(); } catch { S.identity.value = null; }
  try { S.pass.value = await store.getPass(); } catch { S.pass.value = null; }
  try { S.offlineReady.value = !!(await store.getOffline()); } catch { S.offlineReady.value = false; }
  const id = S.identity.value;
  const raw = (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) ? (await startSim()).fetch : globalThis.fetch.bind(globalThis);
  api = new HumidApi({ baseUrl: id?.server?.url ?? SERVER_URL, pinnedKid: id?.server?.kid || PINNED_KID, fetch: watchConnection(raw) });
  // The server no longer knows this session (it expired, or the server restarted and the
  // reconnected channel isn't signed in): either way, one live check signs back in.
  api.onSignedOut = () => { if (S.view.value === "app" && !S.offline.value) lock("Your session ended. Unlock to continue."); };
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
    probe: () => raw(`${api.htp.base}/htp/v1/keys`, { cache: "no-store", headers: { accept: "application/json" }, signal: AbortSignal.timeout(15_000) })
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
    // the read-only copy is open: signing back in needs a live check, so offer it rather than start one
    toast("Your vault is reachable again. Tap Reconnect to sign back in.");
  } else if (v === "app" && S.session.value) {
    // the same session carries on; if the server restarted and forgot it, the first call
    // ends it the usual way (locked, "Unlock to continue")
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
    const s = await api.server();
    S.server.value = { ...s, url: SERVER_URL || location.origin, simulated: (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) };
  } catch (e) {
    S.server.value = null;
    S.serverError.value = friendly(e);
  }
}

function wireGlobalEvents() {
  const reset = () => {
    clearTimeout(idleTimer);
    if (S.view.value === "app") {
      idleTimer = setTimeout(() => lock(`Locked after ${idleLabel(idleMs())} without activity.`), idleMs());
      S.idleDeadline.value = Date.now() + idleMs();
    }
  };
  // Opening the app (unlock, a finished setup or join) shows the tab the person chose.
  let wasApp = false;
  S.view.subscribe((v) => {
    if (v === "app") { if (!wasApp) S.tab.value = S.prefs.value.startTab; reset(); }
    wasApp = v === "app";
  });
  resetIdle = reset;
  for (const ev of ["pointerdown", "keydown"]) document.addEventListener(ev, reset, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      // back from the picker (or another app) while picking: if it was away long, lock anyway
      if (picking && hiddenAt && Date.now() - hiddenAt > PICK_HIDDEN_MS && S.view.value === "app") { stopPicking(); lock("Locked when HumID left the screen."); }
      hiddenAt = 0;
      return;
    }
    if (S.view.value !== "app" || busy) return;
    if (!picking) return lock("Locked when HumID left the screen.");
    // the file picker is up (it normally comes back within seconds): lock if that's not what this is
    hiddenAt = Date.now();
    setTimeout(() => { if (document.hidden && picking && hiddenAt && S.view.value === "app") { stopPicking(); lock("Locked when HumID left the screen."); } }, PICK_HIDDEN_MS);
  });
  // leaving the page entirely (closed, navigated, suspended) is never a file picker
  addEventListener("pagehide", () => { stopPicking(); if (S.view.value === "app" && !busy) lock(); });
  addEventListener("focus", () => setTimeout(stopPicking, 1200));
  addEventListener("online", () => { S.online.value = true; link?.online(true); if (!S.server.value) connectServer(); });
  addEventListener("offline", () => { S.online.value = false; link?.online(false); });
  // retries pause while HumID is off the screen, and resume when it's back
  document.addEventListener("visibilitychange", () => link?.visible(!document.hidden));
  if (!S.online.value) link?.online(false);
}

/** A system file picker is about to open: leaving the screen for it isn't leaving HumID. Bounded: it clears itself after a minute. */
export const markPicking = () => {
  picking = true;
  clearTimeout(pickingTimer);
  pickingTimer = setTimeout(stopPicking, PICK_MS);
};
function stopPicking() { picking = false; hiddenAt = 0; clearTimeout(pickingTimer); pickingTimer = null; }

let resetIdle = () => {};
/** Change preferences: saved on this device, applied now. */
export function setPref(patch) {
  const p = savePrefs({ ...S.prefs.value, ...patch });
  S.prefs.value = p;
  applyPrefs(p);
  if ("idleMs" in patch) resetIdle();
}
/** A short buzz, unless the person turned haptics off. */
export const buzz = (pattern) => { if (!S.prefs.value.haptics) return; try { globalThis.navigator?.vibrate?.(pattern); } catch {} };

/** The gate to bind on this device: the live-biometric gate, or demo in a development build. */
function chooseGate(useDemo) {
  if (useDemo) {
    if (!S.demoAllowed.value) { toast("HumID needs a live face or fingerprint check.", "warn"); return null; }
    return demoGate();
  }
  const hw = S.hwGate.value;
  if (!hw?.probe.available) { toast(hw?.probe.reason || "This device has no face or fingerprint sensor HumID can use.", "warn"); return null; }
  return hw.adapter;
}

const serverRecord = (srv, extra = {}) => ({ url: SERVER_URL, kid: srv.kid, fingerprint: srv.fingerprint, ...extra });
const gateClaim = (gate) => (gate.needsHold
  ? { gateMethod: "demo-no-hardware", assurance: ASSURANCE.NONE }
  : { gateMethod: S.hwGate.value?.probe.method, assurance: S.hwGate.value?.probe.assurance });

/* ---------------- enrolment: the first device ---------------- */

/**
 * App builds pin their server at build time, so there's no trust decision to ask a person
 * to make: skip that step when the server answering is the pinned one. (Web and
 * self-hosted builds without a pin still show it.)
 */
export const serverPinned = () => !!PINNED_KID && String(S.server.value?.kid || "").toLowerCase() === PINNED_KID.toLowerCase();

export function startEnroll() {
  S.enrollStep.value = serverPinned() ? (S.passNeeded.value ? "access" : "bind") : "connect";
  S.view.value = "enroll";
  if (!S.server.value) connectServer();
}

/* ---------------- anonymous payment: access code → access pass ---------------- */
// The pass is signed blind (RFC 9474): the vault signs it without seeing it, so when
// registration spends it, the vault can't tell which access code, purchase or person it
// came from. Before the code is sent, the request is saved here, so a crash or a lost
// connection never loses a paid-for code: the same request is simply sent again.

const PASS_REFUSED = new Set(["code_invalid", "code_unknown", "code_used", "too_many_keys", "no_keys", "bad_key"]);

export async function redeemAccessCode(input) {
  const code = parseAccessCode(input);
  if (!code) { toast("That access code isn't valid. Check it and try again.", "error"); return false; }
  if (S.pass.value?.state === "ready") return true;
  if (S.pass.value?.state === "draft") return resumePass();
  S.passBusy.value = true;
  let saved = false;
  try {
    const pass = await api.getPass(code, {
      saveDraft: async (draft) => {
        const rec = { state: "draft", code, draft, savedAt: new Date().toISOString().slice(0, 10) };
        await store.putPass(rec);
        S.pass.value = rec;
        saved = true;
      },
    });
    await keepPass(pass); // the screen shows "Access pass ready"; no toast on top of it
    return true;
  } catch (e) {
    // A definite refusal: nothing was signed, so the saved request is worthless.
    if (saved && PASS_REFUSED.has(e?.code)) { await store.clearPass(); S.pass.value = null; }
    toast(saved && !PASS_REFUSED.has(e?.code) ? "Your access code is saved on this phone. HumID will finish your pass when it can reach the vault." : friendly(e), "error");
    return false;
  } finally { S.passBusy.value = false; }
}

/** Finish a pass whose request was sent but whose answer never arrived. */
export async function resumePass() {
  const rec = S.pass.value;
  if (rec?.state !== "draft" || S.passBusy.value) return rec?.state === "ready";
  S.passBusy.value = true;
  try {
    await keepPass(await api.getPass(rec.code, { draft: rec.draft }));
    return true;
  } catch (e) {
    if (PASS_REFUSED.has(e?.code)) { await store.clearPass(); S.pass.value = null; toast(friendly(e), "error"); }
    return false;
  } finally { S.passBusy.value = false; }
}

/** Keep the finished pass, and drop the access code: from here on, nothing ties the pass to it. */
async function keepPass(pass) {
  const rec = { state: "ready", pass };
  await store.putPass(rec);
  S.pass.value = rec;
}

/** A demo access code: in the simulation build, or from a local development server. Release builds: nothing. */
export async function demoAccessCode() {
  if (!(typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) && !(typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) return false;
  try {
    if ((typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true)) return redeemAccessCode(sim.demoAccessCode());
    const r = await fetch("/dev/access-code", { method: "POST" });
    if (!r.ok) throw new Error("This server has no demo access codes.");
    return redeemAccessCode((await r.json()).code);
  } catch (e) { toast(friendly(e), "error"); return false; }
}

export async function enroll(useDemo, { soleBiometric = false } = {}) {
  const pass = S.passNeeded.value ? S.pass.value?.pass : undefined;
  if (S.passNeeded.value && S.pass.value?.state !== "ready") { S.enrollStep.value = "access"; return toast("Add an access pass first.", "warn"); }
  const gate = chooseGate(useDemo);
  if (!gate) return;
  const Suite = suite();
  busy = true;
  showInterrupt({ purpose: "enroll", label: "Create your HumID", state: "scanning", progress: 0.06, needsHold: false, message: "Generating your post-quantum keys…" });
  let secret, seed, dseed, both, keys, dkeys, card, enrolled;
  try {
    // Keys and the recovery card are made before the check; the check binds them to you.
    seed = random(SEED); dseed = random(SEED);
    keys = Suite.deriveKeys(seed);
    dkeys = Suite.deriveKeys(dseed);
    const pub = Suite.publicOf(keys);
    const accountId = identityId(pub.dsaPk);
    const commit = toHex(Suite.identityCommit(pub, Suite.sha3_256(dkeys.dsaPk)));
    // The seal card holds one of the three recovery parts; recovery always needs a second proof.
    card = newCard();
    const parts = quorumParts(seed);
    const cardBody = { tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, accountId) };
    for (const p of Object.values(parts)) wipe(p.y);
    showInterrupt({ progress: 0.2, message: "Opening a post-quantum channel to your vault…" });

    const sess = await api.register({
      pub, commit, card: cardBody, soleBiometric, pass,
      device: { dsaPk: dkeys.dsaPk, platform: PLATFORM, ...gateClaim(gate) },
      // One live check: the secure chip makes a liveness key for this session (th),
      // proves it, and signs the device statement with it.
      sign: async ({ register, device, th }) => {
        showInterrupt({ progress: 0.3, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : "Look at your phone or touch the sensor to bind HumID to you." });
        await waitForHold(gate);
        enrolled = await gate.enroll({ prompt: "Bind HumID to your face or fingerprint", challenge: device, attest: th });
        secret = enrolled.secret;
        showInterrupt({ needsHold: false, progress: 0.6, message: enrolled.live?.attestation ? "Your phone's secure chip vouched for the check. Registering…" : "Registering your public keys with the vault…" });
        return {
          registerSig: ml_dsa87.sign(register, keys.dsaSk),
          sigAccount: ml_dsa87.sign(device, keys.dsaSk),
          sigDevice: ml_dsa87.sign(device, dkeys.dsaSk),
          live: enrolled.live, gateMethod: enrolled.interrupt.method, assurance: enrolled.interrupt.assurance,
        };
      },
    });

    both = concat(seed, dseed);
    const wrapped = await Suite.wrapSeed(secret, both, fromB64(enrolled.bindingId));
    const srv = await api.server();
    const record = {
      mode: sess.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance: sess.assurance, proof: sess.proof, method: enrolled.interrupt.method,
      gate: { adapter: gate.id, handle: enrolled.handle }, bindingId: enrolled.bindingId, wrapped, commit,
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      device: { id: sess.device, dsaPk: toB64(dkeys.dsaPk) },
      enrolledAt: new Date().toISOString(), suite: Suite.ID, pending: null,
      server: serverRecord(srv, { id: sess.id, registeredAt: new Date().toISOString() }),
    };
    await store.putIdentity(record);
    sessionKeys(Suite, seed);
    batch(() => {
      S.identity.value = { ...record, schema: 4 };
      S.session.value = sess;
      S.items.value = [];
      S.cardCode.value = sess.cardSet ? card.code : null;
      S.enrollStep.value = "done";
    });
    api.htp.pinnedKid = srv.kid;
    if (pass) { await store.clearPass(); S.pass.value = null; } // spent: nothing to keep
    await endInterrupt(true, "Your HumID is bound to this device.", 700);
  } catch (err) {
    if (enrolled) try { await gate.forget(enrolled.handle); } catch {}
    // The vault refused the pass itself: it's no use to keep, so ask for another code.
    if (["pass_spent", "pass_invalid", "pass_expired", "pass_required"].includes(err?.code)) {
      await store.clearPass();
      batch(() => { S.pass.value = null; S.enrollStep.value = "access"; });
    }
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 2200);
  } finally {
    wipe(secret, seed, dseed, both, card?.secret);
    if (keys) Suite.wipeKeys(keys);
    if (dkeys) Suite.wipeKeys(dkeys);
    busy = false;
  }
}

export function finishEnroll() { S.cardCode.value = null; S.view.value = "app"; S.tab.value = "vault"; refresh(); loadAlerts(); }

/* ---------------- recovery card: show, save, copy ---------------- */

const cardText = (code) => [
  "HumID seal card", "",
  code, "",
  "One of the two proofs that bring your HumID back on a new phone if you lose all your devices.",
  "On its own it opens nothing: recovery also needs your witnesses or your ID, then waits and alerts your devices.",
  "Keep it somewhere safe and offline, away from your ID.",
  "", `Created ${new Date().toLocaleDateString()}`,
].join("\n");

export async function saveCard(code) {
  markPicking();
  try { await saveBytes(utf8(cardText(code)), "HumID seal card.txt", "text/plain"); toast("Saved your seal card."); }
  catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

// No "copy" for the seal card or ID numbers: other apps (and keyboards, and clipboard
// sync to other devices) can read the clipboard, and nothing can reliably clear it.

/* ---------------- unlock / lock ---------------- */

/**
 * Unlock. `used` is what the Lock screen saw: false for a plain unlock, "hold" or "taps"
 * when that gesture was made, or true for "the duress gesture, whichever it is" (a
 * decoy session reconnecting). Which gesture means duress is sealed on the device
 * (core/duress.js) and opens only inside the live check, so the decision decoy-or-real
 * is made AFTER the check: the session opens exactly the same way, then shows only
 * decoy documents while the server silently locks sensitive changes. Every unlock
 * reports presence, so the two look the same on the wire, and nothing on disk says
 * whether duress is set up or how it's triggered.
 *
 * With no connection, the same live check opens the offline copy instead (unlockOffline).
 */
export async function unlock(used = false) {
  const id = S.identity.value;
  if (!id?.server?.id) return toast("This identity is not registered with a vault server.", "error");
  const wasOffline = !!S.offline.value;
  if (!wasOffline && !S.online.value && S.offlineReady.value) return unlockOffline(used);
  let duress = false;
  try {
    showInterrupt({ purpose: "launch", label: "Unlock HumID", state: "scanning", progress: 0.04, needsHold: false, message: "Opening a post-quantum channel to your vault…" });
    const sess = await api.login({
      id: id.server.id,
      device: id.device?.id || "dev_" + "0".repeat(24),
      // The secure chip signs the server's sign-in challenge during the live check.
      sign: (message) => withKeys("launch", "Unlock HumID", async ({ dkeys, seed, interrupt, live, Suite }) => {
        sessionKeys(Suite, seed);
        duress = isDuress(await loadDuressSetting(Suite), used);
        showInterrupt({ progress: 0.75, message: "Signing in with this device's key…" });
        return { sig: ml_dsa87.sign(message, dkeys.dsaSk), interrupt, live: live?.sig };
      }, { keepOpen: true, challenge: message }),
    });
    await reportPresence(duress);
    offline = duress ? null : await readOffline();
    batch(() => { S.session.value = sess; S.lockIssue.value = null; S.offline.value = null; S.decoy.value = duress; S.view.value = "app"; });
    await endInterrupt(true, wasOffline ? "Back online." : "Welcome back.", 500);
    refresh();
    loadAlerts();
    if (wasOffline) reloadTab();
  } catch (e) {
    const issue = ["unknown_identity", "server_identity_changed", "device_removed", "device_not_proven", "key_invalidated"].includes(e?.code);
    // This device was removed, or the server isn't the one it trusted: its offline copy goes too.
    if (issue) { await store.clearOffline().catch(() => {}); S.offlineReady.value = false; }
    if (wasOffline && !issue) {
      // Reconnecting failed: stay in the offline copy (its keys are still needed to show it).
      if (S.interrupt.value && S.interrupt.value.state !== "failed") await endInterrupt(false, cancelled(e) ? friendly(e) : "Still can't reach your vault server.", 1400);
      else if (!S.interrupt.value && !cancelled(e)) toast("Still can't reach your vault server.", "warn");
      return;
    }
    clearKeys();
    if (wasOffline) lock();
    if (issue) S.lockIssue.value = e.code;
    // No connection: open the offline copy with a live check of its own.
    if (!issue && unreachable(e) && S.offlineReady.value) { S.interrupt.value = null; return unlockOffline(used); }
    if (S.interrupt.value && S.interrupt.value.state !== "failed") await endInterrupt(false, friendly(e), 1600);
    else if (!S.interrupt.value && !cancelled(e) && !issue) toast(friendly(e), "error"); // an issue has its own screen
  }
}

/**
 * Android or iOS deleted this device's biometric key (its fingerprints or face changed,
 * or HumID was reinstalled and its data came back from a backup). Nothing can unlock
 * this identity here again, so say so and offer to set this device up again, instead
 * of failing every unlock with the same error.
 */
function keyGone() {
  store?.clearOffline().catch(() => {});
  S.offlineReady.value = false;
  if (S.view.value === "app") lock();
  if (S.view.value === "join") { clearTimeout(joinTimer); S.view.value = "locked"; }
  S.lockIssue.value = "key_invalidated";
}

/** The vault didn't answer at all (as opposed to answering "no"). */
const unreachable = (e) => e instanceof TypeError || e?.code === "server_unreachable" || e?.name === "AbortError" || [502, 503, 504].includes(e?.status);

/* ---------------- offline ---------------- */
// While HumID can't reach the vault, a live check still opens a read-only copy kept on
// this device: the document list (each entry still sealed under the index key), devices,
// recovery status, duress status and recent activity, as of the last time it was online.
// Never a document, and never a document's key: opening one needs the vault, and both
// halves of a split key, exactly as before. The copy is sealed under a key derived from
// the account seed, so it reads only inside a live check. It's never written during a
// duress session, and it's deleted when the server says this device was removed.

function sessionKeys(Suite, seed) {
  wipe(indexKey, offlineKey, settingsKey);
  indexKey = Suite.indexKey(seed);
  offlineKey = Suite.offlineKey ? Suite.offlineKey(seed) : null;
  settingsKey = Suite.settingsKey ? Suite.settingsKey(seed) : null;
}
function clearKeys() {
  wipe(indexKey, offlineKey, settingsKey);
  indexKey = null; offlineKey = null; settingsKey = null; duressSetting = null;
}

/** The offline copy for this account, opened with the session's key; null if there's none (or it doesn't open). */
async function readOffline() {
  try {
    const rec = await store.getOffline();
    if (!rec || !offlineKey || rec.account !== S.identity.value?.server?.id) return null;
    const copy = await suite(S.identity.value?.suite).openOffline(offlineKey, rec.blob);
    return copy?.v === 1 && copy.account === rec.account ? copy : null;
  } catch { return null; }
}

/** Update part of the offline copy. Only from a real, online session. */
function keepOffline(patch) {
  const account = S.identity.value?.server?.id;
  if (S.offline.value || S.decoy.value || !offlineKey || !account || !store) return;
  offline = { ...(offline || {}), ...patch, v: 1, account, savedAt: new Date().toISOString() };
  const copy = offline, key = offlineKey.slice();
  offlineWrite = offlineWrite.then(async () => {
    try {
      const blob = await suite(S.identity.value?.suite).sealOffline(key, copy);
      if (S.identity.value?.server?.id !== account) return; // erased or reset meanwhile
      await store.putOffline(blob, account);
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
      duress = isDuress(await loadDuressSetting(Suite), used);
    });
    const copy = await readOffline();
    if (!copy) {
      clearKeys();
      return toast("Nothing is saved on this device yet. Connect once to use HumID offline.", "warn");
    }
    offline = copy;
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

/** Throws when the app is showing the offline copy: anything that needs the vault waits for a connection. */
function needVault() {
  if (S.offline.value) throw Object.assign(new Error("offline"), { code: "offline" });
}

/** After reconnecting, load what the open tab shows from the vault instead of the copy. */
function reloadTab() {
  if (S.tab.value === "activity") loadLedger();
  if (S.tab.value === "security") { loadRecovery(); loadDuress(); }
  loadDevices();
  if (S.tab.value === "vault" && !S.decoy.value) loadRecovery();
}

async function reportPresence(duress) {
  for (let i = 0; i < 2; i++) {
    try { await api.presence(duress); return; } catch { /* try once more; never block the unlock */ }
  }
}

export function lock(reason) {
  if (S.view.value !== "app") return;
  if (!S.offline.value) api.logout();
  clearKeys(); offline = null;
  knownNames.clear();
  clearTimeout(idleTimer);
  batch(() => {
    S.view.value = "locked";
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
    closeViewer();
  });
  if (reason) toast(reason, "warn");
}

/* ---------------- vault ---------------- */

async function decodeIndex(raw) {
  try { return await suite().openIndex(indexKey, fromB64u(raw)); }
  catch { return { name: "Unreadable item", type: "", category: "other" }; }
}
const fromB64u = (s) => fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

export async function refresh() {
  if (!indexKey) return;
  S.loading.value = true;
  try {
    const { items, usage } = S.offline.value ? { items: offline?.items || [], usage: offline?.usage || null } : await api.list();
    keepOffline({ items, usage });
    const decoded = await Promise.all(items.map(async (it) => {
      const meta = await decodeIndex(it.index);
      return { ...it, ...meta, id: it.id, size: meta.size ?? it.size, envelopeSize: it.size };
    }));
    // A decoy session shows only the documents marked for it, and their usage; only
    // their names are kept in memory (for Activity), never the others'.
    const shown = S.decoy.value ? decoded.filter((i) => i.decoy) : decoded;
    for (const i of shown) knownNames.set(i.id, i.name);
    const u = S.decoy.value ? { ...usage, bytes: shown.reduce((n, i) => n + (i.envelopeSize || 0), 0), count: shown.length } : usage;
    batch(() => { S.items.value = shown; S.usage.value = u; });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 401)) toast(friendly(e), "error");
  } finally { S.loading.value = false; }
}

export async function addDocument({ file, name, category, place = null }) {
  if (file.size > MAX_FILE) { toast(`${file.name} is over 50 MB. This POC seals files up to 50 MB.`, "warn"); return false; }
  const bytes = await readFile(file);
  return sealAndStore({ bytes, type: file.type || "application/octet-stream", name: (name || file.name || "Document").trim().slice(0, 120), category, place });
}

/**
 * Seal an identity document record (@humid/idscan) into the vault: one sealed JSON
 * with its photos, and a summary (kind, issuer, expiry) inside the encrypted index
 * so the list can show when it expires without opening it.
 */
export async function addIdRecord(record, name, place = null) {
  const bytes = encodeRecord(record);
  if (bytes.length > MAX_FILE) { toast("Those photos are too large to seal. Retake them and try again.", "warn"); return false; }
  return sealAndStore({ bytes, type: ID_TYPE, name: (name || "ID").trim().slice(0, 120), category: "identity", extra: { idInfo: idSummary(record) }, place });
}

/**
 * Seal a payment card record (@humid/cards) into the vault. The encrypted index
 * carries only network, last four digits, expiry and nickname, never the number.
 */
export async function addCardRecord(record, name) {
  let bytes;
  try { bytes = encodeCard(record); } catch (e) { toast(e.message, "warn"); return false; }
  return sealAndStore({ bytes, type: CARD_TYPE, name: (name || "Card").trim().slice(0, 120), category: "money", extra: { cardInfo: cardSummary(record) } });
}

/** Tap a contactless card (Android NFC, or a USB reader on a computer): number and expiry. No payment is made. */
export async function readCardTap() {
  let t;
  try {
    t = await openChip({ prompt: "Hold your card flat against the back of your phone." });
    const r = await readContactless(t);
    await t.end({ message: "Card read." });
    return r;
  } catch (e) {
    await t?.end({ error: "Couldn't read the card." });
    if (e?.code !== "cancelled") toast(e?.message || "Couldn't read the card. Try the camera, or type it.", "warn");
    return null;
  }
}

/**
 * Read a card from a photo with the on-device text reader. front: number, expiry, name
 * (and an American Express code); back: the security code and the bank's phone number.
 * Best effort: the holder checks what was read. The photo of the back is never kept.
 */
export async function readCardPhoto(canvas, { side = "front", pan = null } = {}) {
  try {
    const ocr = await textReader();
    const text = await ocr.read(canvas, { front: side === "front" });
    return side === "front" ? readCardText(text) : readCardBack(text, { pan });
  } catch { return null; }
}

/* ---------------- Apple Wallet passes ---------------- */

/**
 * Apple's roots, pinned (@humid/wallet). A development build also trusts test roots a
 * browser check puts in globalThis.__humidExtraPassRoots; a release build never does.
 */
const passRoots = () => ((typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) && Array.isArray(globalThis.__humidExtraPassRoots)
  ? [...APPLE_ROOTS, ...globalThis.__humidExtraPassRoots.map((d, i) => ({ name: `Test root ${i + 1}`, der: fromB64(d) }))]
  : APPLE_ROOTS);

/**
 * Check a .pkpass: its files, its issuer's signature, Apple's chain.
 * → { ok, result, bytes } (the exact bytes checked, which are what gets sealed) | { ok: false, reason }
 */
export async function checkPass(file) {
  try {
    if (file.size > 20 * 1024 * 1024) return { ok: false, reason: "That pass is too big." };
    const bytes = await readFile(file);
    return { ok: true, result: await readPkpass(bytes, { roots: passRoots() }), bytes };
  } catch (e) {
    return { ok: false, reason: e instanceof WalletError ? e.message : "That pass can't be read." };
  }
}

/** Seal a checked pass: exactly the bytes that were checked (the signed original, so it can go back into Wallet), with its summary in the encrypted index. */
export async function addPass({ checked, name, place = null }) {
  const { result, bytes } = checked;
  return sealAndStore({ bytes: Uint8Array.from(bytes), type: PASS_TYPE, name: (name || result.pass.description || "Pass").trim().slice(0, 120), category: "passes", extra: { passInfo: passIndex(result.pass, result.issuer) }, place });
}

/**
 * Encrypt on this device, one live check signs it, upload. The sheet shows the stages.
 * place: a location watch (core/place.js) when the person chose to stamp where it was
 * sealed; the freshest fix at this moment goes into the encrypted index, beside the name.
 */
async function sealAndStore({ bytes, type, name: finalName, category, extra = {}, place = null }) {
  const id = S.identity.value;
  if (S.offline.value) { toast(friendly({ code: "offline" }), "warn"); return false; }
  S.sheet.value = { ...S.sheet.value, stage: "seal" };
  let share = null, prepared;
  try {
    // where it's being sealed (waits a few seconds at most for a first fix)
    let stamp = null;
    if (place) {
      const got = await place.take(5000);
      if (got.stamp && validStamp(got.stamp)) stamp = got.stamp;
      else toast(`Sealing without a location: ${REASONS[got.reason] || REASONS.unavailable}`, "warn");
    }
    if (stamp) extra = { ...extra, place: stamp };
    // Encrypt first (public keys only), then one live check signs the ciphertext's hash
    // in hardware and releases the key that signs the envelope.
    const Suite = suite(id.suite);
    const size = bytes.length;
    const plainHash = toHex(Suite.sha3_512(bytes));
    // Split keys: the document is first encrypted under its own key, which goes to the
    // keyshare service and is forgotten here. The account keys alone then open nothing.
    if (S.server.value?.policy?.splitKeys) {
      const w = await splitWrap({ bytes, name: finalName, type });
      wipe(bytes);
      bytes = w.file.bytes; share = w.share;
      prepared = await Suite.prepareSeal(w.file, { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) });
    } else prepared = await Suite.prepareSeal({ bytes, name: finalName, type }, { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) });
    wipe(bytes); bytes = null;
    const { envelope, index } = await withKeys("seal", `Seal ${finalName}`, async ({ keys, rec, live }) => {
      const sealed = Suite.finishSeal(prepared, keys, { identityCommit: id.commit, interrupt: { ...rec, ...(live ? { live: b64u(live.sig) } : {}) } });
      const idx = await Suite.sealIndex(indexKey, { name: finalName, type, size, category, addedAt: new Date().toISOString(), plainHash, ...(share ? { split: true } : {}), ...extra });
      return { envelope: sealed.envelope, index: idx };
    }, { challenge: sealLiveMessage(prepared.ciphertextHash) });
    S.sheet.value = { ...S.sheet.value, stage: "upload" };
    await api.upload(envelope, index, share);
    wipe(share); share = null;
    S.sheet.value = { ...S.sheet.value, stage: "done" };
    await refresh();
    await sleep(650);
    S.sheet.value = null;
    toast(`${finalName} sealed. Only your face or fingerprint can open it.`);
    return true;
  } catch (e) {
    wipe(bytes, share);
    S.sheet.value = { ...S.sheet.value, stage: null };
    if (!cancelled(e)) toast(friendly(e), "error");
    return false;
  }
}

/**
 * Download, verify, decrypt — all under one live check. Returns { bytes, meta }.
 * The download can't come before the check: GET /vault/objects/:id IS the step-up
 * request, and the server releases the envelope (and, for a split document, its key)
 * only on the proof the liveness key signs during the check. Every request has a
 * 45 s timeout (@humid/htp), so a server that stops answering ends the check instead
 * of holding the keys in memory.
 */
async function fetchPlain(item, purpose, label) {
  return withStepUp("download", [item.id], purpose, label, async ({ keys, proof, Suite }) => {
    showInterrupt({ progress: 0.65, message: "Fetching sealed copy over HTP/1…" });
    const { envelope, share } = await api.downloadWithShare(item.id, proof);
    showInterrupt({ progress: 0.85, message: share ? "Verifying, then opening with both keys…" : "Verifying ML-DSA-87 signature and decrypting…" });
    const out = await Suite.open(envelope, keys);
    if (!isSplit(out.meta)) { wipe(share); return out; }
    try { return await splitUnwrap(out.bytes, share); }
    finally { wipe(out.bytes, share); }
  });
}

export async function openItem(item) {
  try {
    needVault();
    const { bytes, meta } = await fetchPlain(item, "decrypt", `Open ${item.name}`);
    const type = meta.type || item.type || "application/octet-stream";
    let url = null, text = null, idRecord = null, cardRecord = null, pass = null, passError = null;
    if (type === ID_TYPE) {
      try { idRecord = decodeRecord(bytes); } catch { text = new TextDecoder().decode(bytes); }
    } else if (type === CARD_TYPE) {
      try { cardRecord = decodeCard(bytes); } catch { text = "This card record can't be read."; }
      wipe(bytes); // the card lives only in the viewer, masked until revealed
    } else if (type === PASS_TYPE) {
      // checked again on every open: what's shown is what the issuer signed
      // a pass that states no signing time is judged at the time it was first checked, not today
      const at = Date.parse(item.passInfo?.checkedAt || "");
      try { pass = await readPkpass(bytes, { roots: passRoots(), now: Number.isNaN(at) ? new Date() : new Date(Math.min(at, Date.now())) }); }
      catch (e) { passError = e instanceof WalletError ? e.message : "This pass can't be read."; }
    } else if (type.startsWith("text/") || type === "application/json") { text = new TextDecoder().decode(bytes); wipe(bytes); }
    else url = URL.createObjectURL(new Blob([bytes], { type }));
    batch(() => { S.sheet.value = null; S.viewer.value = { name: meta.name, type, url, text, idRecord, cardRecord, pass, passError, bytes: url || idRecord || pass || passError ? bytes : null, item }; });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export function closeViewer() {
  const v = S.viewer.value;
  if (!v) return;
  if (v.url) URL.revokeObjectURL(v.url);
  wipe(v.bytes);
  S.viewer.value = null;
}

export async function saveCopy(item) {
  try {
    needVault();
    const v = S.viewer.value;
    if (v?.item?.id === item.id && v.bytes) {
      await saveBytes(v.bytes, v.name, v.type);
    } else {
      const { bytes, meta } = await fetchPlain(item, "export", `Save ${item.name}`);
      await saveBytes(bytes, meta.name, meta.type);
      wipe(bytes);
    }
    toast("Saved a decrypted copy to your device.");
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function exportSealed(item) {
  try {
    needVault();
    const env = await withStepUp("download", [item.id], "export", `Export sealed ${item.name}`, async ({ proof }) => api.download(item.id, proof));
    await saveBytes(env, `${item.name}${EXTENSION}`, MEDIA_TYPE);
    toast("Exported the sealed envelope. It stays encrypted.");
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

const indexEntry = (item, patch = {}) => ({
  name: item.name, type: item.type, size: item.size, category: item.category, addedAt: item.addedAt, plainHash: item.plainHash,
  ...(item.decoy ? { decoy: true } : {}), ...(item.pinned ? { pinned: true } : {}), ...(item.idInfo ? { idInfo: item.idInfo } : {}),
  ...(item.split ? { split: true } : {}), ...(item.place ? { place: item.place } : {}),
  ...(item.cardInfo ? { cardInfo: item.cardInfo } : {}), ...(item.passInfo ? { passInfo: item.passInfo } : {}), ...patch,
});

/**
 * Pin an item to the top of the vault. The pin is sealed in the item's encrypted index
 * entry, so it shows on every device and the server can't see which items are pinned.
 * In a decoy session it changes only what's on screen.
 */
export async function setPinned(item, on) {
  const show = () => { S.items.value = S.items.value.map((i) => (i.id === item.id ? { ...i, pinned: on || undefined } : i)); };
  if (S.decoy.value) { show(); return; }
  try {
    needVault();
    const entry = indexEntry(item);
    if (on) entry.pinned = true; else delete entry.pinned;
    await api.rename(item.id, await suite().sealIndex(indexKey, entry));
    show();
    toast(on ? `${item.name} is pinned to the top.` : `${item.name} is unpinned.`);
  } catch (e) { toast(friendly(e), "error"); }
}

/** Show (or stop showing) a document in the decoy view. Stored inside the encrypted index. */
export async function setDecoy(item, on) {
  if (S.decoy.value) return toast("Updated.");
  try {
    needVault();
    const entry = indexEntry(item);
    if (on) entry.decoy = true; else delete entry.decoy;
    await api.rename(item.id, await suite().sealIndex(indexKey, entry));
    await refresh();
    toast(on ? `${item.name} will show in the decoy view.` : `${item.name} is hidden from the decoy view.`);
  } catch (e) { toast(friendly(e), "error"); }
}

export async function renameItem(item, name, category) {
  try {
    needVault();
    const idx = await suite().sealIndex(indexKey, indexEntry(item, { name: name.trim().slice(0, 120) || item.name, category }));
    await api.rename(item.id, idx);
    await refresh();
    S.sheet.value = null;
    toast("Updated.");
  } catch (e) { toast(friendly(e), "error"); }
}

export async function deleteItem(item) {
  try {
    await withStepUp("remove", [item.id], "delete", `Delete ${item.name}`, async ({ proof }) => api.remove(item.id, proof));
    S.sheet.value = null;
    await refresh();
    toast(`${item.name} deleted from your vault.`);
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- activity ---------------- */

/** In a decoy session, Activity shows only what a calm account with these documents would show. */
const DECOY_TYPES = new Set(["identity.created", "session.opened", "session.closed", "device.added", "device.removed", "object.sealed", "object.opened", "object.updated", "object.deleted"]);
function decoyView(l) {
  const ids = new Set(S.items.value.map((i) => i.id));
  const entries = l.entries.filter((e) => DECOY_TYPES.has(e.type) && (!e.type.startsWith("object.") || ids.has(e.detail?.id)));
  return { ...l, entries };
}

export async function loadLedger() {
  S.ledgerLoading.value = true;
  try {
    const l = S.offline.value ? (offline?.ledger || { ok: true, reason: "Empty", entries: [] }) : await api.ledger({ limit: 300 });
    keepOffline({ ledger: l });
    for (const it of S.items.value) knownNames.set(it.id, it.name);
    S.ledger.value = { ...(S.decoy.value && l.ok ? decoyView(l) : l), names: new Map(knownNames) };
    checkContinuity();
  } catch (e) { toast(friendly(e), "error"); }
  finally { S.ledgerLoading.value = false; }
}

/**
 * The public transparency log: prove this account's latest entry is in it, and that it
 * extends the log this device saw last time. The checkpoint is remembered on success.
 */
export async function checkContinuity() {
  const id = S.identity.value;
  if (S.offline.value) { S.continuity.value = { ok: false, pending: true, reason: "Checked when you're back online" }; return; }
  try {
    const r = await api.continuity({ previous: id?.tlog || null });
    S.continuity.value = r;
    if (r.ok && (!id.tlog || r.size >= id.tlog.size)) {
      const record = { ...id, tlog: { size: r.size, root: r.root, at: r.at } };
      delete record.schema;
      await store.putIdentity(record);
      S.identity.value = { ...record, schema: id.schema ?? 4 };
    }
  } catch (e) {
    // Not reaching the server is not evidence of tampering: check again once it's back.
    if (isNetworkFailure(e) || SESSION_LOST.has(e?.code)) { S.continuity.value = { ok: false, pending: true, reason: "Checked when your vault is reachable" }; return; }
    S.continuity.value = { ok: false, reason: e?.code === "not_in_log" ? "Not published yet" : friendly(e), pending: e?.code === "not_in_log" };
  }
}

/* ---------------- devices ---------------- */

export async function loadDevices() {
  if (S.offline.value) { S.devices.value = offline?.devices || null; return; }
  const me = await quietly(api.me());
  if (me) { S.devices.value = me.devices; keepOffline({ devices: me.devices }); }
}

/** This account's check string, shown when adding a device. */
export const myAccountCheck = () => { const a = S.identity.value?.server?.id; return a ? accountCheck(a) : null; };

/** Look up the code a new device is showing. The API checks the code against the keys. */
export async function findLink(code) {
  try { needVault(); return await api.getLink(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Hand this account's seed to the new device, sealed to the keys its code commits to. */
export async function approveLink(req) {
  const id = S.identity.value;
  try {
    await withStepUp("approveLink", [req.code], "link", `Add ${req.platform}`, async ({ keys, seed, rec, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: "Sealing your account key to the new device…" });
      const { envelope } = await Suite.seal({ bytes: seed, name: "HumID account key", type: KEY_TYPE }, keys, { kemPk: req.kemPk, xPk: req.xPk }, { identityCommit: id.commit, interrupt: rec });
      return api.approveLink(req.code, envelope, proof);
    });
    toast("Approved. Compare the account check on the new device.");
    setTimeout(loadDevices, 4000);
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function removeDevice(d) {
  try {
    await withStepUp("removeDevice", [d.id], "remove", `Remove ${d.platform || "device"}`, async ({ proof }) => api.removeDevice(d.id, proof));
    S.sheet.value = null;
    toast(`${d.platform || "Device"} removed. It can no longer reach your vault.`);
    loadDevices();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- recovery card & contacts (owner) ---------------- */

export async function loadRecovery() {
  if (S.offline.value) { S.recovery.value = offline?.recovery || null; return; }
  const [card, contacts, anchor, settings] = await Promise.all([quietly(api.card()), quietly(api.contacts()), quietly(api.anchor()), quietly(api.settings())]);
  if (!card || !contacts) return;
  const names = [];
  for (const g of contacts.guardians || []) {
    let name = "A witness";
    try { if (g.label && indexKey) name = (await suite().openIndex(indexKey, g.label)).name; } catch {}
    names.push(name);
  }
  // Two-proof recovery is ready when at least two of the three proofs are set up (v2).
  const proofs = {
    witness: contacts.n > 0 && contacts.scheme === "quorum",
    anchor: !!anchor?.exists,
    card: card.exists && card.scheme === "quorum",
  };
  const legacy = (card.exists && card.scheme !== "quorum") || (contacts.n > 0 && contacts.scheme !== "quorum");
  S.recovery.value = {
    card, anchor: anchor || { available: false, exists: false }, settings: settings || {},
    contacts: { n: contacts.n, threshold: contacts.threshold, createdAt: contacts.createdAt, names, scheme: contacts.scheme },
    proofs, ready: Object.values(proofs).filter(Boolean).length >= 2, legacy,
  };
  keepOffline({ recovery: S.recovery.value });
  if (!S.decoy.value) {
    api.protectingAlerts().then((a) => { S.protecting.value = a; }).catch(() => {});
    api.station().then((st) => { S.station.value = st; }).catch(() => {});
  }
}

/** The part of two-proof recovery this flow needs, made from the seed inside a live check. */
const partOf = (seed, kind) => {
  const parts = quorumParts(seed);
  const p = parts[kind];
  for (const k of Object.keys(parts)) if (k !== kind) wipe(parts[k].y);
  return p;
};

export async function makeNewCard() {
  const accountId = S.identity.value.server.id;
  let card;
  try {
    await withStepUp("setCard", [], "card", "Make a seal card", async ({ seed, proof }) => {
      card = newCard();
      const part = partOf(seed, "card");
      try { await api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, part, accountId) }, proof); }
      finally { wipe(part.y); }
    });
    // "recoveryCard", not "card": the vault's "card" sheet is the payment-card form.
    S.sheet.value = { type: "recoveryCard", code: card.code };
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
  finally { wipe(card?.secret); }
}

export async function removeCard() {
  try {
    await withStepUp("removeCard", [], "card", "Remove seal card", async ({ proof }) => api.removeCard(proof));
    S.sheet.value = null;
    toast("Seal card removed. The old card no longer works.");
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/** Look up a contact code someone showed you. The API checks it against their keys. */
export async function findContact(code) {
  try { needVault(); return await api.getOffer(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/**
 * Split the account seed among 2–5 contacts; a majority rebuilds it.
 * contacts: [{ code, name, offer }] where offer came from findContact.
 * ownerName: how the contacts know you, shown to them when you ask for help.
 */
export async function saveContacts(contacts, ownerName) {
  const id = S.identity.value;
  const n = contacts.length;
  if (n < MIN_CONTACTS || n > MAX_CONTACTS) return toast(`Choose ${MIN_CONTACTS} to ${MAX_CONTACTS} recovery contacts.`, "warn");
  const t = thresholdFor(n);
  try {
    await withStepUp("setContacts", [], "contacts", "Save your witnesses", async ({ keys, seed, rec, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: `Splitting your witness part into ${n} pieces…` });
      const part = partOf(seed, "witness");
      const shares = split(part.y, n, t);
      wipe(part.y);
      const guardians = [];
      for (let i = 0; i < n; i++) {
        const c = contacts[i];
        const piece = encodeShare({ owner: id.server.id, label: ownerName, ...shares[i], t, n });
        const { envelope } = await Suite.seal({ bytes: piece, name: "HumID recovery piece", type: KEY_TYPE }, keys, { kemPk: c.offer.kemPk, xPk: c.offer.xPk }, { identityCommit: id.commit, interrupt: rec });
        guardians.push({ contact: c.offer.account, offer: c.code, envelope, label: await Suite.sealIndex(indexKey, { name: c.name.trim().slice(0, 40) || "Contact" }) });
        wipe(piece, shares[i].y);
      }
      await api.setContacts({ threshold: t, guardians, scheme: "quorum" }, proof);
    });
    S.sheet.value = null;
    toast(`Saved. Any ${t} of your ${n} witnesses count as one proof.`);
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function removeContacts() {
  try {
    await withStepUp("removeContacts", [], "contacts", "Remove your witnesses", async ({ proof }) => api.removeContacts(proof));
    S.sheet.value = null;
    toast("Witnesses removed. Their pieces no longer work.");
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- being someone's recovery contact ---------------- */

/** Show a code someone types to make you their recovery contact. Public keys only. */
export async function offerToBeContact() {
  const p = S.identity.value.pub;
  try {
    needVault();
    const r = await api.offerContact({ kemPk: fromB64(p.kemPk), xPk: fromB64(p.xPk), dsaPk: fromB64(p.dsaPk) });
    S.sheet.value = { type: "offer", code: r.code, expiresAt: r.expiresAt };
  } catch (e) { toast(friendly(e), "error"); }
}

export async function findHelpRequest(code) {
  try { needVault(); return await api.getHelp(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Live check 1: open the pieces you hold to see whose they are. Only names leave the check. */
export async function whoDoIProtect() {
  try {
    needVault();
    return await withKeys("help", "See who you protect", async ({ keys, Suite }) => {
      const held = await api.protecting();
      const people = [];
      for (const h of held) {
        try {
          const { bytes } = await Suite.open(h.envelope, keys);
          const s = decodeShare(bytes);
          people.push({ owner: s.owner, label: s.label || "Someone", since: h.createdAt });
          wipe(bytes, s.y);
        } catch { /* skip a piece that doesn't open */ }
      }
      return people;
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/** Live check 2: release your piece for `owner`, re-sealed to the device that asked. */
export async function releasePiece(req, person) {
  const id = S.identity.value;
  try {
    return await withStepUp("help", [req.code], "help", `Help ${person.label} recover`, async ({ keys, rec, proof, Suite }) => {
      const held = (await api.protecting()).find((h) => h.owner === person.owner);
      if (!held) throw new Error("You no longer hold a piece for this person.");
      const { bytes } = await Suite.open(held.envelope, keys);
      const { envelope } = await Suite.seal({ bytes, name: "HumID recovery piece", type: KEY_TYPE }, keys, { kemPk: req.kemPk, xPk: req.xPk }, { identityCommit: id.commit, interrupt: rec });
      wipe(bytes);
      return api.help(req.code, { owner: person.owner, envelope }, proof);
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/* ---------------- alerts: recoveries of this account ---------------- */

export async function loadAlerts() {
  if (S.decoy.value) { S.alerts.value = []; return; } // a decoy session sees a calm account
  if (S.offline.value) return; // recoveries in progress are a live question: shown once back online
  const a = await api.alerts().catch(() => null);
  if (a) S.alerts.value = a;
  api.protectingAlerts().then((p) => { S.protecting.value = p; }).catch(() => {});
}

export async function cancelRecovery(alert) {
  try {
    await withStepUp("cancelAlert", [alert.ref], "cancel", "Cancel this recovery", async ({ proof }) => api.cancelAlert(alert.ref, proof));
    S.sheet.value = null;
    toast("Cancelled. That device gets nothing.");
    loadAlerts();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- joining: a new device for an existing HumID ---------------- */
// The new device binds its biometric first, then waits (minutes for a link,
// 72 hours for a card or contacts). What it needs at the end is wrapped under
// its gate the whole time: its device seed D, plus the link or recovery key
// seed, or the card. The record is saved, so the wait survives restarts.
// Finishing is one more live check, in which the secure chip makes and
// attests a fresh liveness key for the session that adds the device.

export function startJoin() { S.joinStep.value = serverPinned() ? 1 : 0; S.joinMethod.value = null; S.joinStatus.value = null; S.view.value = "join"; if (!S.server.value) connectServer(); }

/**
 * Bind this device and start the chosen route.
 * method: "link" | "quorum" (two proofs) | "card" | "contacts" (older single-proof routes).
 * cardInput: what the person typed (card; optional for quorum).
 * What's wrapped under this device's gate while it waits: D ‖ x ‖ card?, where x is
 * the link key seed, the recovery key seed (quorum, contacts) or the card (v1 card).
 */
export async function beginJoin(method, { useDemo = false, cardInput = "", soleBiometric = false } = {}) {
  let cardSecret = null;
  if (method === "card" || (method === "quorum" && cardInput.trim())) {
    try { cardSecret = parseCard(cardInput); } catch (e) { toast(e.message, "warn"); return; }
  }
  const gate = chooseGate(useDemo);
  if (!gate) return;
  const Suite = suite();
  busy = true;
  showInterrupt({ purpose: "enroll", label: "Bind this device", state: "scanning", progress: 0.06, needsHold: !!gate.needsHold,
    message: gate.needsHold ? holdMessage : "Look at your phone or touch the sensor. Your HumID will open only for you on this device." });
  let secret, dseed, x, both, dkeys;
  try {
    await waitForHold(gate);
    const e = await gate.enroll({ prompt: "Bind HumID to your face or fingerprint", challenge: localChallenge("bind") });
    secret = e.secret;
    showInterrupt({ needsHold: false, progress: 0.4, message: "Generating this device's keys…" });
    dseed = random(SEED);
    dkeys = Suite.deriveKeys(dseed);
    x = method === "card" ? cardSecret : random(SEED);
    both = method === "quorum" && cardSecret ? concat(concat(dseed, x), cardSecret) : concat(dseed, x);
    const wrapped = await Suite.wrapSeed(secret, both, fromB64(e.bindingId));
    showInterrupt({ progress: 0.7, message: method === "link" ? "Getting a code for your other device…" : "Asking your vault to start a recovery…" });
    let pending;
    if (method === "link") {
      const lk = Suite.deriveKeys(x);
      const r = await api.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: PLATFORM });
      Suite.wipeKeys(lk);
      pending = { method, code: r.code, expiresAt: r.expiresAt };
    } else if (method === "card") {
      const r = await api.startRecovery({ method: "card", tag: cardTag(cardSecret), platform: PLATFORM });
      pending = { method, requestId: r.id, account: r.account, releaseAt: r.releaseAt, expiresAt: r.expiresAt };
    } else if (method === "quorum") {
      const rk = Suite.deriveKeys(x);
      const r = await api.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, platform: PLATFORM, ...(cardSecret ? { tag: cardTag(cardSecret) } : {}) });
      Suite.wipeKeys(rk);
      pending = { method, requestId: r.id, code: r.code, account: r.account, expiresAt: r.expiresAt, hasCard: !!cardSecret };
    } else {
      const rk = Suite.deriveKeys(x);
      const r = await api.startRecovery({ method: "contacts", kemPk: rk.kemPk, xPk: rk.xPk, platform: PLATFORM });
      Suite.wipeKeys(rk);
      pending = { method, requestId: r.id, code: r.code, expiresAt: r.expiresAt };
    }
    const srv = await api.server();
    const record = {
      mode: e.interrupt.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance: e.interrupt.assurance, method: e.interrupt.method,
      gate: { adapter: gate.id, handle: e.handle }, bindingId: e.bindingId, wrapped,
      suite: Suite.ID, enrolledAt: new Date().toISOString(),
      pending: { ...pending, devicePub: toB64(dkeys.dsaPk), startedAt: Date.now(), soleBiometric }, device: null, pub: null, commit: null,
      server: serverRecord(srv),
    };
    await store.putIdentity(record);
    batch(() => { S.identity.value = { ...record, schema: 4 }; S.joinMethod.value = method; S.joinStep.value = 3; S.joinStatus.value = null; });
    api.htp.pinnedKid = srv.kid;
    await endInterrupt(true, "This device is bound. Keys wiped from memory.", 650);
    pollJoin();
  } catch (err) {
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 1800);
  } finally {
    wipe(secret, dseed, x, both, cardSecret);
    if (dkeys) Suite.wipeKeys(dkeys);
    busy = false;
  }
}

/** Check on a join. Links are polled every few seconds; long waits every 30 s. */
export async function pollJoin() {
  clearTimeout(joinTimer);
  const p = S.identity.value?.pending;
  if (!p || S.view.value !== "join") return;
  let st;
  try {
    st = p.method === "link" ? await api.linkResult(p.code) : await api.recoveryStatus(p.requestId);
    S.joinStatus.value = st;
  } catch (e) {
    S.joinStatus.value = { status: "error", message: friendly(e) };
  }
  if (st && ["approved", "released"].includes(st.status)) {
    // Adding a device: the person compares the account check on both screens first.
    if (p.method === "link") { S.joinStatus.value = { ...st, check: accountCheck(st.account) }; return; }
    return finishJoin(st);
  }
  if (st && ["expired", "cancelled", "completed"].includes(st.status)) return;
  const quick = p.method === "link" || st?.status === "collecting" || (st?.releaseAt && st.releaseAt - Date.now() < 60_000);
  if (p.method === "quorum" && st?.status === "collecting") { joinTimer = setTimeout(pollJoin, 5000); return; }
  joinTimer = setTimeout(pollJoin, quick ? 2500 : 30_000);
}

/** The account seed has arrived (sealed, as a card blob, or as contact pieces): unlock it and join. */
async function finishJoin(st) {
  const id = S.identity.value;
  const p = id.pending;
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  const account = st.account;
  busy = true;
  showInterrupt({ purpose: "launch", label: "Open your HumID here", state: "scanning", progress: 0.08, needsHold: false, message: "Opening a post-quantum channel to your vault…" });
  let secret, both, seed, keys, dkeys, xkeys, released;
  const pieces = [];
  try {
    const sess = await api.enrollDevice({
      account, via: p.method, recoveryId: p.requestId, soleBiometric: !!p.soleBiometric,
      device: { dsaPk: fromB64(p.devicePub), platform: PLATFORM, gateMethod: id.method, assurance: id.assurance },
      // One live check unlocks what arrived, and the secure chip attests a fresh liveness key to this session.
      sign: async (message, th) => {
        showInterrupt({ progress: 0.2, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)} to finish.` });
        await waitForHold(gate);
        released = await gate.release(id.gate.handle, { purpose: "enroll", prompt: "Open your HumID here", challenge: message, attest: th });
        secret = released.secret;
        both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
        const x = both.subarray(SEED, p.method === "quorum" ? 2 * SEED : undefined);
        showInterrupt({ needsHold: false, progress: 0.4, message: "Unsealing your account key…" });
        if (p.method === "link") {
          xkeys = Suite.deriveKeys(x);
          const opened = await Suite.open(st.envelope, xkeys);
          seed = opened.bytes;
          keys = Suite.deriveKeys(seed);
          if (opened.manifest.signer.mldsa87Pk !== toB64(keys.dsaPk)) throw new Error("The key that arrived was not sealed by its own account. Nothing was added.");
        } else if (p.method === "card") {
          seed = await openCard(x, st.blob, account);
          keys = Suite.deriveKeys(seed);
        } else if (p.method === "quorum") {
          // Two of: the witnesses' pieces, the seal card part, the anchor part.
          const parts = [];
          if (st.shares?.length) {
            xkeys = Suite.deriveKeys(x);
            for (const env of st.shares) pieces.push(decodeShare((await Suite.open(env, xkeys)).bytes));
            parts.push({ x: QUORUM.witness, y: combine(pieces) });
          }
          if (st.blob && both.length >= 2 * SEED + CARD) parts.push(await openCardPart(both.subarray(2 * SEED, 2 * SEED + CARD), st.blob, account));
          if (st.anchorPart) parts.push(decodeQuorumPart(st.anchorPart));
          seed = combineQuorum(parts);
          for (const pt of parts) wipe(pt.y);
          keys = Suite.deriveKeys(seed);
        } else {
          xkeys = Suite.deriveKeys(x);
          for (const env of st.shares) pieces.push(decodeShare((await Suite.open(env, xkeys)).bytes));
          seed = combine(pieces);
          keys = Suite.deriveKeys(seed);
        }
        if (identityId(keys.dsaPk) !== account) throw new Error("The pieces didn't rebuild this HumID. Ask your contacts to check the code and try again.");
        dkeys = Suite.deriveKeys(both.subarray(0, SEED));
        if (toB64(dkeys.dsaPk) !== p.devicePub) throw new Error("This device's keys changed while it waited. Start again.");
        showInterrupt({ progress: 0.65, message: "Adding this device to your HumID…" });
        return {
          sigAccount: ml_dsa87.sign(message, keys.dsaSk), sigDevice: ml_dsa87.sign(message, dkeys.dsaSk),
          live: released.live, gateMethod: released.interrupt.method, assurance: released.interrupt.assurance,
        };
      },
    });
    const rewrapped = concat(seed, both.subarray(0, SEED));
    const wrapped = await Suite.wrapSeed(secret, rewrapped, fromB64(id.bindingId));
    wipe(rewrapped);
    const pub = Suite.publicOf(keys);
    // pending (the link or recovery code, the request id) is spent here and dropped from the record.
    const record = {
      ...id, wrapped, pending: null,
      commit: toHex(Suite.identityCommit(pub, Suite.sha3_256(dkeys.dsaPk))),
      assurance: sess.assurance, proof: sess.proof,
      mode: sess.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      device: { id: sess.device, dsaPk: p.devicePub },
      server: { ...id.server, id: account, registeredAt: new Date().toISOString() },
    };
    delete record.schema;
    await store.putIdentity(record);
    sessionKeys(Suite, seed);
    batch(() => {
      S.identity.value = { ...record, schema: 4 };
      S.session.value = sess;
      S.joinStatus.value = null;
      S.view.value = "app";
      S.tab.value = "vault";
    });
    await endInterrupt(true, "Welcome back. This device is part of your HumID.", 900);
    refresh();
    loadAlerts();
    if (p.method !== "link") toast("Recovered. Check your proofs in Security, and make a new seal card if you used it.", "warn");
  } catch (err) {
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 2200);
    if (!cancelled(err)) S.joinStatus.value = { ...st, status: "error", message: friendly(err) };
  } finally {
    wipe(secret, both, seed);
    for (const s of pieces) wipe(s.y);
    for (const k of [keys, dkeys, xkeys]) if (k) Suite.wipeKeys(k);
    busy = false;
  }
}

/** Two proofs, while waiting: add the seal card. One live check re-wraps it with this device's keys. */
export async function addCardToJoin(cardInput) {
  const id = S.identity.value;
  const p = id?.pending;
  if (p?.method !== "quorum") return false;
  if (p.hasCard) { toast("Your seal card is already part of this recovery.", "warn"); return false; }
  let cardSecret;
  try { cardSecret = parseCard(cardInput); } catch (e) { toast(e.message, "warn"); return false; }
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  busy = true;
  showInterrupt({ purpose: "card", label: "Add your seal card", state: "scanning", progress: 0.1, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
  let secret, both, next;
  try {
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose: "card", prompt: "Add your seal card", challenge: localChallenge("card") });
    secret = rel.secret;
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    next = concat(both.subarray(0, 2 * SEED), cardSecret);
    showInterrupt({ needsHold: false, progress: 0.6, message: "Telling your vault you have your seal card…" });
    const r = await api.recoveryAddCard(p.requestId, cardTag(cardSecret));
    const wrapped = await Suite.wrapSeed(secret, next, fromB64(id.bindingId));
    const record = { ...id, wrapped, pending: { ...p, hasCard: true, account: r.account } };
    delete record.schema;
    await store.putIdentity(record);
    S.identity.value = { ...record, schema: 4 };
    S.joinStatus.value = { ...(S.joinStatus.value || {}), ...r };
    await endInterrupt(true, "Seal card added.", 600);
    pollJoin();
    return true;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1800);
    return false;
  } finally {
    wipe(secret, both, next, cardSecret);
    busy = false;
  }
}

/**
 * Two proofs, while waiting: the ID chip, live. The chip must answer a fresh challenge
 * from the server, so a copy of its data isn't enough.
 * source(nonce) → { chip: { dg1, sod, dg15 }, signature }: reads the chip and has it sign
 * the nonce in the same session (readChipLive), or a demo passport in development builds.
 */
export async function addChipToJoin(source) {
  const p = S.identity.value?.pending;
  if (p?.method !== "quorum") return false;
  try {
    const nonce = await api.recoveryChallenge(p.requestId);
    const got = await source(nonce);
    if (!got) return false;
    const { chip, signature } = got;
    if (!signature) throw new Error("This ID's chip can't answer challenges. Verify at a HumID station instead.");
    const r = await api.recoveryAddAnchor(p.requestId, { chip, signature });
    S.joinStatus.value = { ...(S.joinStatus.value || {}), ...r };
    toast("Your ID chip is verified.");
    pollJoin();
    return true;
  } catch (e) { if (e?.code !== "cancelled") toast(friendly(e), "error"); return false; }
}

/** Development builds: a demo passport as a live chip source for addChipToJoin. */
export const demoChipSource = (name) => async (nonce) => {
  const c = await demoPassport(name);
  return c ? { chip: c, signature: await c.answer(nonce) } : null;
};

/** A real chip as a live source for addChipToJoin: one read that also answers the nonce. */
export const nfcChipSource = (access) => async (nonce) => {
  const r = await readChip(access, { nonce, purpose: "recover" });
  return r ? { chip: r, signature: r.aaSignature } : null;
};

/** Adding a device: the account check matched the other device's screen. */
export function confirmJoin() {
  const st = S.joinStatus.value;
  if (st?.check && st.status === "approved") return finishJoin(st);
}

/** The account check didn't match: someone else's account was offered. Join nothing. */
export async function rejectJoin() {
  await cancelJoin();
  toast("Nothing was added. The account offered wasn't yours: don't use this server until you know why.", "error");
}

/** Give up on a join: forget the half-made device and go back to the start. */
export async function cancelJoin() {
  clearTimeout(joinTimer);
  const id = S.identity.value;
  try { if (id?.gate) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  batch(() => { S.identity.value = null; S.joinStatus.value = null; S.joinStep.value = 1; S.joinMethod.value = null; });
}

export const prettyCode = formatCode;

/* ---------------- security ---------------- */

export async function eraseEverything() {
  const id = S.identity.value;
  try {
    await withStepUp("closeIdentity", [], "erase", "Close HumID and erase vault", async ({ proof }) => api.closeIdentity(proof));
  } catch (e) {
    if (cancelled(e)) return;
    toast(`${friendly(e) || "Your session ended."} Local data was kept.`, "error");
    return;
  }
  try { await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  clearKeys(); offline = null; S.offlineReady.value = false;
  knownNames.clear();
  batch(() => {
    S.identity.value = null; S.session.value = null; S.items.value = []; S.ledger.value = null; S.sheet.value = null;
    S.devices.value = null; S.recovery.value = null; S.alerts.value = []; S.protecting.value = []; S.decoy.value = false; S.view.value = "welcome";
  });
  api.htp.pinnedKid = PINNED_KID;
  toast("Your HumID was closed and your vault erased.");
}

export const lockNow = () => lock("Locked.");

/** Forget this device's HumID locally and start over (server reset, device removed, old test identity). */
export async function resetLocal() {
  const id = S.identity.value;
  try { if (id) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  S.offlineReady.value = false;
  api.htp.close();
  api.htp.pinnedKid = PINNED_KID;
  api.htp.server = null;
  batch(() => { S.identity.value = null; S.lockIssue.value = null; S.view.value = "welcome"; });
  connectServer();
}

/* ---------------- identity anchor: your passport or ID chip ---------------- */
// Reading a chip needs NFC (next update). Until then the chip's data comes from a
// file, or, in local development builds, from the dev server's demo passports.

const fromAny = (s) => {
  const t = String(s || "").trim();
  if (/^[0-9a-f]+$/i.test(t) && t.length % 2 === 0) return Uint8Array.from(t.match(/../g), (h) => parseInt(h, 16));
  return fromB64(t.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((t.length + 3) % 4));
};

/**
 * Chip data from files: one JSON file { dg1, sod, dg15? } (base64 or hex), or the
 * raw files a chip reader exports (names containing DG1, SOD and DG15).
 */
export async function readChipFiles(files) {
  const list = [...(files || [])];
  if (!list.length) return null;
  try {
    if (list.length === 1 && /\.json$/i.test(list[0].name)) {
      const j = JSON.parse(new TextDecoder().decode(await readFile(list[0])));
      const get = (k) => j[k] ?? j[k.toUpperCase()] ?? j[`EF_${k.toUpperCase()}`];
      const chip = { dg1: fromAny(get("dg1")), sod: fromAny(get("sod")), ...(get("dg15") ? { dg15: fromAny(get("dg15")) } : {}) };
      if (!chip.dg1.length || !chip.sod.length) throw new Error();
      return chip;
    }
    const chip = {};
    for (const f of list) {
      const n = f.name.toUpperCase();
      const key = /DG15/.test(n) ? "dg15" : /DG1(?!\d)/.test(n) ? "dg1" : /SOD/.test(n) ? "sod" : null;
      if (key) chip[key] = await readFile(f);
    }
    if (!chip.dg1 || !chip.sod) throw new Error();
    return chip;
  } catch {
    toast("Those files aren't ID chip data. Choose the DG1 and SOD files (and DG15 if there is one), or one .json with them.", "warn");
    return null;
  }
}

/** Development builds only: a demo passport from the local dev server, with a chip that answers challenges. */
export async function demoPassport(name = "Demo Person") {
  if (!(typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) return null;
  try {
    const res = await fetch(`${SERVER_URL}/dev/passport?name=${encodeURIComponent(name)}`, { method: "POST" });
    if (!res.ok) throw new Error("This server has no demo passports.");
    const j = await res.json();
    return {
      dg1: fromAny(j.dg1), sod: fromAny(j.sod), dg15: j.dg15 ? fromAny(j.dg15) : undefined, demo: true, name,
      answer: async (nonce) => {
        const r = await fetch(`${SERVER_URL}/dev/passport/answer?name=${encodeURIComponent(name)}&nonce=${toHex(nonce)}`, { method: "POST" });
        return r.ok ? fromAny((await r.json()).signature) : null;
      },
    };
  } catch (e) { toast(friendly(e), "error"); return null; }
}

/** Bind your passport or ID to your HumID: the anchor part, stored under the chip's identity. */
export async function setAnchor(chip) {
  try {
    const r = await withStepUp("setAnchor", [], "anchor", "Anchor your HumID to your ID", async ({ seed, proof }) => {
      showInterrupt({ progress: 0.6, message: "Checking your ID chip's signature with its issuing country…" });
      const part = partOf(seed, "anchor");
      try { return await api.setAnchor({ chip, part: encodeQuorumPart(part) }, proof); }
      finally { wipe(part.y); }
    });
    S.sheet.value = null;
    toast(`Anchored to your ${r.document}${r.country ? ` (${r.country})` : ""}.`);
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function removeAnchor() {
  try {
    await withStepUp("removeAnchor", [], "anchor", "Remove your ID anchor", async ({ proof }) => api.removeAnchor(proof));
    S.sheet.value = null;
    toast("ID anchor removed.");
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- duress ---------------- */
// The duress setting itself lives on this device (which gesture you use), sealed under
// a key from the account seed (core/duress.js): nothing on disk says whether it's on
// or which gesture it is. What it changes lives on the server (lockdown, slower
// recoveries, witness alerts). Screens read the opened setting from
// S.duressInfo.value.setting, never from the identity record.

/** Inside a live check: the setting this device sealed, re-sealing one an older release left in the clear. */
async function loadDuressSetting(Suite) {
  const id = S.identity.value;
  const { setting, record } = await openDuress(Suite, settingsKey, id);
  if (record) {
    try {
      delete record.schema;
      await store.putIdentity(record);
      S.identity.value = { ...record, schema: id.schema ?? 4 };
    } catch { /* next unlock tries again */ }
  }
  duressSetting = setting;
  return setting;
}

/** The setting as the session opened it ({ enabled, gesture }); "off" in a decoy session or before unlock. */
const currentDuress = () => (S.decoy.value || !duressSetting ? { ...DURESS_OFF } : { ...duressSetting });

export async function saveDuress({ enabled, gesture }) {
  const id = S.identity.value;
  if (S.decoy.value) { S.sheet.value = null; return toast("Saved."); }
  try {
    const record = await sealDuress(suite(id.suite), settingsKey, id, { enabled, gesture });
    delete record.schema;
    await store.putIdentity(record);
    duressSetting = { enabled: !!enabled, gesture: gesture === "taps" ? "taps" : "hold" };
    S.identity.value = { ...record, schema: id.schema ?? 4 };
    S.duressInfo.value = { ...(S.duressInfo.value || {}), setting: currentDuress() };
  } catch (e) { return toast(friendly(e), "error"); }
  toast(enabled ? "Duress protection is on. Practise the gesture once so it's natural." : "Duress protection is off.");
}

export async function loadDuress() {
  if (S.decoy.value) { S.duressInfo.value = { lockdown: false, setting: currentDuress() }; return; }
  if (S.offline.value) { S.duressInfo.value = { ...(offline?.duress || { lockdown: false }), setting: currentDuress() }; return; }
  const [st, settings] = await Promise.all([api.duressStatus().catch(() => null), api.settings().catch(() => null)]);
  const info = { ...(st || {}), alert: !!settings?.duressAlert };
  S.duressInfo.value = { ...info, setting: currentDuress() };
  if (st && settings) keepOffline({ duress: info });
}

export async function setWitnessAlert(on) {
  try {
    await withStepUp("setSettings", [], "settings", on ? "Let witnesses see duress" : "Stop duress alerts", async ({ proof }) => api.setSettings({ duressAlert: !!on }, proof));
    toast(on ? "Your witnesses will see a duress signal when they open HumID." : "Witnesses won't be told.");
    loadDuress();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function clearLockdown() {
  try {
    const r = await withStepUp("clearDuress", [], "duress", "Lift lockdown", async ({ proof }) => api.clearDuress(proof));
    toast(r.cleared ? "Lockdown lifted." : "There was no lockdown.");
    loadDuress();
  } catch (e) { if (!cancelled(e)) toast(e?.code === "too_soon" ? "Lockdown can be lifted once things have been calm for a while. Try again later." : friendly(e), "error"); }
}

/* ---------------- verification station (operators) ---------------- */

export async function stationLookup(code) {
  try { needVault(); return await api.stationRequest(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/**
 * The station reads the chip in front of it, and the chip answers a fresh challenge
 * from the server in the same session. source: a real reader (access details) or,
 * in development builds, a demo passport's name.
 */
export async function stationReadChip(code, { access, demo } = {}) {
  try {
    const nonce = await api.stationChallenge(code);
    if (demo != null) {
      const c = await demoPassport(demo);
      return c ? { ...c, aaSignature: await c.answer(nonce) } : null;
    }
    return await readChip(access, { nonce, purpose: "station" });
  } catch (e) { toast(friendly(e), "error"); return null; }
}

/** The operator vouches: document genuine, face matches, person present. Their own live check signs it. */
export async function stationVerify(code, chip, checks) {
  try {
    return await withStepUp("stationVerify", [code], "station", "Vouch for this person", async ({ proof }) => {
      showInterrupt({ progress: 0.6, message: "Checking the chip with its issuing country…" });
      return api.stationVerify(code, { chip, checks, signature: chip.aaSignature }, proof);
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/* ---------------- reading an ID chip (NFC on phones, USB reader on desktops) ---------------- */

const CHIP_PROMPT = {
  phone: "Hold the top of your phone flat against the photo page of your passport, or against your ID card.",
  reader: "Place the passport's photo page, or the ID card, flat on the card reader.",
};

/**
 * Read a passport or ID card chip. access: { number, birth, expiry } (YYMMDD) or { can }.
 * nonce: a server challenge for the chip to sign (live proof). The access details live only
 * in this call; nothing read is stored on the device.
 * Returns { dg1, sod, dg15?, aaSignature?, access } or null if cancelled or failed (shown to the person).
 */
export async function readChip(access, { nonce, purpose = "anchor", photo = false } = {}) {
  const n = S.nfc.value || await probeNfc();
  S.nfc.value = n;
  if (!n.available) { toast(n.reason || "This device can't read ID chips.", "warn"); return null; }
  const show = (patch) => { S.chipRead.value = { ...(S.chipRead.value || {}), ...patch }; };
  show({ stage: "waiting", fraction: 0, message: CHIP_PROMPT[n.kind] || CHIP_PROMPT.phone, error: null, kind: n.kind, purpose });
  let chip = null;
  try {
    chip = await openChip({ prompt: CHIP_PROMPT[n.kind] });
    show({ stage: "reading", fraction: 0.05, message: "Keep holding still…" });
    let said = "";
    const r = await readDocument(chip, {
      access, nonce, photo,
      onProgress: ({ fraction, message }) => { show({ stage: "reading", fraction, message }); if (message !== said) { said = message; chip.message(message); } },
    });
    await chip.end({ message: "Done. You can move your document away." });
    show({ stage: "done", fraction: 1, message: "Read and checked. You can move your document away." });
    await sleep(700);
    S.chipRead.value = null;
    return r;
  } catch (e) {
    const cancelledRead = e?.code === "cancelled";
    const message = cancelledRead ? "Cancelled." : friendly(e);
    await chip?.end({ error: message });
    if (cancelledRead) { S.chipRead.value = null; return null; }
    show({ stage: "error", message, error: e?.code || "error" });
    return null;
  }
}

export const dismissChipRead = () => { S.chipRead.value = null; };

/** Is there a chip reader here (phone NFC, or a USB reader on a desktop)? Cached in S.nfc. */
export async function chipReader({ fresh = false } = {}) {
  if (!S.nfc.value || fresh) S.nfc.value = await probeNfc();
  return S.nfc.value;
}

/**
 * Read a passport or ID card chip for the holder's own vault copy: the MRZ data,
 * the photo, and the signed hashes, checked against each other. Fills the record
 * in place. Returns true if it read. The chip data stays in the record (sealed).
 */
export async function readChipInto(record, access, { portrait } = {}) {
  const r = await readChip(access, { purpose: "vault", photo: true });
  if (!r) return false;
  const b64 = (b) => toB64(b);
  let mrz = null;
  try { mrz = readDg1(r.dg1).mrz; } catch { /* shown as unread below */ }
  const integrity = (() => { try { return checkIntegrity(r.sod, { 1: r.dg1, ...(r.dg2 ? { 2: r.dg2 } : {}), ...(r.dg15 ? { 15: r.dg15 } : {}) }); } catch { return null; } })();
  applyChip(record, r, { mrz, integrity, b64 });
  // A photo whose hash doesn't match the chip's own signed list isn't decoded or shown:
  // the decoder would be parsing bytes no one vouches for.
  if (r.dg2 && portrait && integrity?.ok !== false) {
    try { setImage(record, "portrait", await portrait(readDg2(r.dg2))); }
    catch { toast("Read the chip, but its photo is in a format HumID can't show yet. It's kept with the record.", "warn"); }
  }
  if (integrity && !integrity.ok) toast("The chip's data doesn't match its own signed hashes. Check the document.", "warn");
  return true;
}
