// Everything the app does, in one place. Screens call these functions and read
// the signals in state.js. Rule enforced here: private keys exist only inside
// withKeys(), i.e. during a biological interrupt, and are wiped right after.

import { batch } from "@preact/signals";
import { toB64, fromB64, toHex, MEDIA_TYPE, EXTENSION } from "@humid/codec";
import { suite, random } from "@humid/crypto";
import { adapter as gateAdapter, bestHardwareGate, demoGate, CANCELLED, ASSURANCE } from "@humid/gate";
import { openStore } from "@humid/store";
import { saveBytes, readFile } from "@humid/io";
import { HumidApi, ApiError } from "@humid/api";
import { ml_dsa87 } from "@humid/htp";
import * as S from "./state.js";
import { SERVER_URL, PINNED_KID, PLATFORM } from "./config.js";

const IDLE_LOCK_MS = 5 * 60 * 1000;
const MAX_FILE = 50 * 1024 * 1024;
const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let store = null;
let api = null;
let indexKey = null;        // decrypts item names while unlocked; wiped on lock
let busy = false;
let picking = false;
let idleTimer = null;
let holdWaiter = null;
const knownNames = new Map(); // object id -> name, so the activity log can show names of deleted items

/* ---------------- toasts ---------------- */

export function toast(text, kind = "ok") {
  const id = Math.random().toString(36).slice(2);
  S.toasts.value = [...S.toasts.value, { id, text, kind }].slice(-3);
  setTimeout(() => { S.toasts.value = S.toasts.value.filter((t) => t.id !== id); }, kind === "error" ? 5200 : 3600);
}

const friendly = (e) => {
  if (e?.name === "NotAllowedError" || e?.message === CANCELLED) return "The biometric check was cancelled.";
  if (e?.code === "server_identity_changed") return "This server's identity changed. HumID refused to connect.";
  if (e instanceof TypeError || e?.code === "server_unreachable") return "Can't reach your vault server. Check your connection.";
  return e?.message || "Something went wrong.";
};
const cancelled = (e) => e?.name === "NotAllowedError" || e?.message === CANCELLED;

/* ---------------- the biological interrupt ---------------- */

function gateLabel(method) {
  return ({
    "ios-keychain-biometry": "Face ID / Touch ID",
    "android-keystore-biometric": "your fingerprint or face",
    "macos-keychain-biometry": "Touch ID",
    "windows-hello-keycredential": "Windows Hello",
    "linux-fprintd-keyring": "your fingerprint",
    "webauthn-platform-uv-prf": "your device passkey",
  })[method] || "your device biometric";
}

function showInterrupt(patch) { S.interrupt.value = { ...(S.interrupt.value || {}), ...patch }; }

/** Called by the overlay's press-and-hold control (demo gate only). */
export function holdComplete() { holdWaiter?.resolve(); holdWaiter = null; }
export function holdCancel() { holdWaiter?.reject(new Error(CANCELLED)); holdWaiter = null; }

/**
 * Run fn with the identity's private keys. Shows the interrupt overlay, asks
 * the gate (Face ID, fingerprint, Windows Hello, passkey, or demo hold) to
 * release the seed, and wipes everything afterwards — success or failure.
 */
async function withKeys(purpose, label, fn, { keepOpen = false } = {}) {
  const id = S.identity.value;
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  busy = true;
  showInterrupt({ purpose, label, state: "scanning", progress: 0.08, needsHold: !!gate.needsHold,
    message: gate.needsHold ? "Demo mode has no sensor. Press and hold to stand in for it." : `Confirm with ${gateLabel(id.method)}.` });
  let secret, seed, keys;
  try {
    if (gate.needsHold) await new Promise((resolve, reject) => { holdWaiter = { resolve, reject }; });
    const rel = await gate.release(id.gate.handle, purpose, label);
    secret = rel.secret;
    showInterrupt({ needsHold: false, progress: 0.45, message: "Unlocking your keys on this device…" });
    seed = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    keys = Suite.deriveKeys(seed);
    if (toB64(keys.dsaPk) !== id.pub.dsaPk) throw new Error("Unlocked keys do not match this identity.");
    const out = await fn({ keys, seed, interrupt: { method: rel.interrupt.method, assurance: rel.interrupt.assurance }, rec: rel.interrupt, Suite });
    if (keepOpen) showInterrupt({ progress: 0.85, message: "Keys wiped from memory. Waiting for your vault to confirm…" });
    else {
      showInterrupt({ state: "verified", progress: 1, message: "Verified. Keys wiped from memory." });
      await sleep(620);
      S.interrupt.value = null;
    }
    return out;
  } catch (e) {
    showInterrupt({ state: "failed", needsHold: false, progress: 1, message: friendly(e) });
    await sleep(cancelled(e) ? 700 : 1600);
    S.interrupt.value = null;
    throw e;
  } finally {
    wipe(secret, seed);
    if (keys) Suite.wipeKeys(keys);
    setTimeout(() => { busy = false; }, 600);
  }
}

/* ---------------- boot ---------------- */

export async function boot() {
  store = await openStore();
  S.hwGate.value = await bestHardwareGate();
  try { S.identity.value = await store.getIdentity(); } catch { S.identity.value = null; }
  const pinned = S.identity.value?.server?.kid || PINNED_KID;
  api = new HumidApi({ baseUrl: S.identity.value?.server?.url ?? SERVER_URL, pinnedKid: pinned });
  api.onSignedOut = (why) => { if (S.view.value === "app") lock(why === "expired" ? "Your session ended. Unlock to continue." : null); };
  connectServer();
  S.view.value = S.identity.value ? "locked" : "welcome";
  wireGlobalEvents();
}

export async function connectServer() {
  S.serverError.value = null;
  try {
    const s = await api.server();
    S.server.value = { ...s, url: SERVER_URL || location.origin };
  } catch (e) {
    S.server.value = null;
    S.serverError.value = friendly(e);
  }
}

function wireGlobalEvents() {
  const reset = () => {
    clearTimeout(idleTimer);
    if (S.view.value === "app") {
      idleTimer = setTimeout(() => lock("Locked after 5 minutes without activity."), IDLE_LOCK_MS);
      S.idleDeadline.value = Date.now() + IDLE_LOCK_MS;
    }
  };
  S.view.subscribe((v) => { if (v === "app") reset(); });
  for (const ev of ["pointerdown", "keydown"]) document.addEventListener(ev, reset, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && S.view.value === "app" && !busy && !picking) lock("Locked when HumID left the screen.");
  });
  addEventListener("focus", () => setTimeout(() => { picking = false; }, 1200));
  addEventListener("online", () => { S.online.value = true; if (!S.server.value) connectServer(); });
  addEventListener("offline", () => { S.online.value = false; });
}

export const markPicking = () => { picking = true; };

/* ---------------- enrolment ---------------- */

export function startEnroll() { S.enrollStep.value = 0; S.view.value = "enroll"; if (!S.server.value) connectServer(); }

export async function enroll(useDemo) {
  const gate = useDemo ? demoGate() : S.hwGate.value?.adapter;
  if (!gate) return toast("No biometric gate on this device. Use demo mode.", "warn");
  const Suite = suite();
  busy = true;
  showInterrupt({ purpose: "enroll", label: "Create your HumID", state: "scanning", progress: 0.06, needsHold: !!gate.needsHold,
    message: gate.needsHold ? "Demo mode has no sensor. Press and hold to stand in for it." : "Confirm with your device biometric to bind HumID to it." });
  let secret, seed, keys;
  try {
    if (gate.needsHold) await new Promise((resolve, reject) => { holdWaiter = { resolve, reject }; });
    const e = await gate.enroll();
    secret = e.secret;
    showInterrupt({ needsHold: false, progress: 0.35, message: "Generating your post-quantum keys…" });
    await sleep(30);
    seed = random(64);
    const wrapped = await Suite.wrapSeed(secret, seed, fromB64(e.bindingId));
    keys = Suite.deriveKeys(seed);
    const pub = Suite.publicOf(keys);
    const commit = toHex(Suite.identityCommit(pub, Suite.sha3_256(fromB64(e.bindingId))));
    showInterrupt({ progress: 0.7, message: "Registering your public keys with the vault…" });
    const device = { platform: PLATFORM, gateMethod: e.interrupt.method, assurance: e.interrupt.assurance };
    const sess = await api.register({ pub, commit, device, sign: async (m) => ml_dsa87.sign(m, keys.dsaSk) });
    const srv = await api.server();
    const record = {
      mode: e.interrupt.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance: e.interrupt.assurance, method: e.interrupt.method,
      gate: { adapter: gate.id, handle: e.handle }, bindingId: e.bindingId, wrapped, commit,
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      enrolledAt: new Date().toISOString(), suite: Suite.ID,
      server: { url: SERVER_URL, kid: srv.kid, fingerprint: srv.fingerprint, id: sess.id, registeredAt: new Date().toISOString() },
    };
    await store.putIdentity(record);
    indexKey = Suite.indexKey(seed);
    batch(() => {
      S.identity.value = { ...record, schema: 3 };
      S.session.value = sess;
      S.items.value = [];
      S.enrollStep.value = 2;
    });
    api.htp.pinnedKid = srv.kid;
    showInterrupt({ state: "verified", progress: 1, message: "Your HumID is bound to this device." });
    await sleep(700);
    S.interrupt.value = null;
  } catch (err) {
    showInterrupt({ state: "failed", needsHold: false, progress: 1, message: friendly(err) });
    await sleep(cancelled(err) ? 700 : 1800);
    S.interrupt.value = null;
  } finally {
    wipe(secret, seed);
    if (keys) Suite.wipeKeys(keys);
    busy = false;
  }
}

export function finishEnroll() { S.view.value = "app"; S.tab.value = "vault"; refresh(); }

/* ---------------- unlock / lock ---------------- */

export async function unlock() {
  const id = S.identity.value;
  if (!id?.server?.id) return toast("This identity is not registered with a vault server.", "error");
  try {
    showInterrupt({ purpose: "launch", label: "Unlock HumID", state: "scanning", progress: 0.04, needsHold: false, message: "Opening a post-quantum channel to your vault…" });
    const sess = await api.login({
      id: id.server.id,
      device: { platform: PLATFORM },
      sign: (message) => withKeys("launch", "Unlock HumID", async ({ keys, seed, interrupt, Suite }) => {
        indexKey = Suite.indexKey(seed);
        showInterrupt({ progress: 0.75, message: "Signing in with your identity key…" });
        return { sig: ml_dsa87.sign(message, keys.dsaSk), interrupt };
      }, { keepOpen: true }),
    });
    batch(() => { S.session.value = sess; S.lockIssue.value = null; S.view.value = "app"; });
    showInterrupt({ state: "verified", progress: 1, message: "Welcome back." });
    await sleep(500);
    S.interrupt.value = null;
    refresh();
  } catch (e) {
    wipe(indexKey); indexKey = null;
    if (e?.code === "unknown_identity" || e?.code === "server_identity_changed") S.lockIssue.value = e.code;
    if (S.interrupt.value && S.interrupt.value.state !== "failed") {
      showInterrupt({ state: "failed", progress: 1, needsHold: false, message: friendly(e) });
      await sleep(1600);
      S.interrupt.value = null;
    } else if (!S.interrupt.value && !cancelled(e)) toast(friendly(e), "error");
  }
}

export function lock(reason) {
  if (S.view.value !== "app") return;
  api.logout();
  wipe(indexKey); indexKey = null;
  clearTimeout(idleTimer);
  batch(() => {
    S.view.value = "locked";
    S.session.value = null;
    S.items.value = [];
    S.ledger.value = null;
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
    const { items, usage } = await api.list();
    const decoded = await Promise.all(items.map(async (it) => {
      const meta = await decodeIndex(it.index);
      knownNames.set(it.id, meta.name);
      return { ...it, ...meta, id: it.id, size: meta.size ?? it.size, envelopeSize: it.size };
    }));
    batch(() => { S.items.value = decoded; S.usage.value = usage; });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 401)) toast(friendly(e), "error");
  } finally { S.loading.value = false; }
}

export async function addDocument({ file, name, category }) {
  if (file.size > MAX_FILE) { toast(`${file.name} is over 50 MB. This POC seals files up to 50 MB.`, "warn"); return false; }
  const id = S.identity.value;
  let bytes = await readFile(file);
  const type = file.type || "application/octet-stream";
  const finalName = (name || file.name || "Document").trim().slice(0, 120);
  S.sheet.value = { ...S.sheet.value, stage: "seal" };
  try {
    const { envelope, index } = await withKeys("seal", `Seal ${finalName}`, async ({ keys, rec, Suite }) => {
      const pub = { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) };
      const sealed = await Suite.seal({ bytes, name: finalName, type }, keys, pub, { identityCommit: id.commit, interrupt: rec });
      const idx = await Suite.sealIndex(indexKey, { name: finalName, type, size: bytes.length, category, addedAt: new Date().toISOString(), plainHash: sealed.plainHash });
      return { envelope: sealed.envelope, index: idx };
    });
    wipe(bytes); bytes = null;
    S.sheet.value = { ...S.sheet.value, stage: "upload" };
    await api.upload(envelope, index);
    S.sheet.value = { ...S.sheet.value, stage: "done" };
    await refresh();
    await sleep(650);
    S.sheet.value = null;
    toast(`${finalName} sealed. Only your biometric can open it.`);
    return true;
  } catch (e) {
    wipe(bytes);
    S.sheet.value = { ...S.sheet.value, stage: null };
    if (!cancelled(e)) toast(friendly(e), "error");
    return false;
  }
}

/** Download, verify, decrypt — all under one biometric check. Returns { bytes, meta }. */
async function fetchPlain(item, purpose, label) {
  return withKeys(purpose, label, async ({ keys, interrupt, Suite }) => {
    showInterrupt({ progress: 0.65, message: "Fetching sealed copy over HTP/1…" });
    const env = await api.download(item.id, async ({ message }) => ({ sig: ml_dsa87.sign(message, keys.dsaSk), interrupt }));
    showInterrupt({ progress: 0.85, message: "Verifying ML-DSA-87 signature and decrypting…" });
    return Suite.open(env, keys);
  });
}

export async function openItem(item) {
  try {
    const { bytes, meta } = await fetchPlain(item, "decrypt", `Open ${item.name}`);
    const type = meta.type || item.type || "application/octet-stream";
    let url = null, text = null;
    if (type.startsWith("text/") || type === "application/json") { text = new TextDecoder().decode(bytes); wipe(bytes); }
    else url = URL.createObjectURL(new Blob([bytes], { type }));
    batch(() => { S.sheet.value = null; S.viewer.value = { name: meta.name, type, url, text, bytes: url ? bytes : null, item }; });
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
    const env = await withKeys("export", `Export sealed ${item.name}`, async ({ keys, interrupt }) =>
      api.download(item.id, async ({ message }) => ({ sig: ml_dsa87.sign(message, keys.dsaSk), interrupt })));
    await saveBytes(env, `${item.name}${EXTENSION}`, MEDIA_TYPE);
    toast("Exported the sealed envelope. It stays encrypted.");
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function renameItem(item, name, category) {
  try {
    const idx = await suite().sealIndex(indexKey, { name: name.trim().slice(0, 120) || item.name, type: item.type, size: item.size, category, addedAt: item.addedAt, plainHash: item.plainHash });
    await api.rename(item.id, idx);
    await refresh();
    S.sheet.value = null;
    toast("Updated.");
  } catch (e) { toast(friendly(e), "error"); }
}

export async function deleteItem(item) {
  try {
    await withKeys("delete", `Delete ${item.name}`, async ({ keys, interrupt }) =>
      api.remove(item.id, async ({ message }) => ({ sig: ml_dsa87.sign(message, keys.dsaSk), interrupt })));
    S.sheet.value = null;
    await refresh();
    toast(`${item.name} deleted from your vault.`);
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- activity ---------------- */

export async function loadLedger() {
  S.ledgerLoading.value = true;
  try {
    const l = await api.ledger({ limit: 300 });
    for (const it of S.items.value) knownNames.set(it.id, it.name);
    S.ledger.value = { ...l, names: new Map(knownNames) };
  } catch (e) { toast(friendly(e), "error"); }
  finally { S.ledgerLoading.value = false; }
}

/* ---------------- security ---------------- */

export async function eraseEverything() {
  const id = S.identity.value;
  try {
    await withKeys("erase", "Close HumID and erase vault", async ({ keys, interrupt }) =>
      api.closeIdentity(async ({ message }) => ({ sig: ml_dsa87.sign(message, keys.dsaSk), interrupt })));
  } catch (e) {
    if (cancelled(e)) return;
    toast(`${friendly(e)} Local data was kept.`, "error");
    return;
  }
  try { await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  wipe(indexKey); indexKey = null;
  batch(() => {
    S.identity.value = null; S.session.value = null; S.items.value = []; S.ledger.value = null; S.sheet.value = null; S.view.value = "welcome";
  });
  api.htp.pinnedKid = PINNED_KID;
  toast("Your HumID was closed and your vault erased.");
}

export const lockNow = () => lock("Locked.");

/** The server no longer knows this identity (e.g. it was reset): forget it locally and start over. */
export async function resetLocal() {
  const id = S.identity.value;
  try { if (id) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  api.htp.close();
  api.htp.pinnedKid = PINNED_KID;
  api.htp.server = null;
  batch(() => { S.identity.value = null; S.lockIssue.value = null; S.view.value = "welcome"; });
  connectServer();
}
