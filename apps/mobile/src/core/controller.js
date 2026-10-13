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
import { suite, random } from "@humid/crypto";
import { adapter as gateAdapter, demoGate, bestHardwareGate, CANCELLED, ASSURANCE } from "@humid/gate";
import { openStore } from "@humid/store";
import { saveBytes, readFile } from "@humid/io";
import { HumidApi, ApiError } from "@humid/api";
import { ml_dsa87, identityId, sealLiveMessage, b64u } from "@humid/htp";
import {
  newCard, parseCard, cardTag, sealCard, openCard, formatCode,
  split, combine, thresholdFor, encodeShare, decodeShare, MIN_CONTACTS, MAX_CONTACTS,
} from "@humid/recovery";
import * as S from "./state.js";
import { SERVER_URL, PINNED_KID, PLATFORM } from "./config.js";

const IDLE_LOCK_MS = 5 * 60 * 1000;
const MAX_FILE = 50 * 1024 * 1024;
const SEED = 64;
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
let busy = false;
let picking = false;
let idleTimer = null;
let holdWaiter = null;
let joinTimer = null;
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

async function endInterrupt(ok, message, ms) {
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
  const ticket = await api.ticket(op, ...args);
  return withKeys(purpose, label, (k) => fn({
    ...k,
    proof: { ticket, sign: async (message) => ({ sig: ml_dsa87.sign(message, k.dkeys.dsaSk), interrupt: k.interrupt, live: k.live?.sig }) },
  }), { challenge: ticket.live });
}

/* ---------------- boot ---------------- */

export async function boot() {
  store = await openStore();
  S.hwGate.value = await bestHardwareGate();
  try { S.identity.value = await store.getIdentity(); } catch { S.identity.value = null; }
  const id = S.identity.value;
  api = new HumidApi({ baseUrl: id?.server?.url ?? SERVER_URL, pinnedKid: id?.server?.kid || PINNED_KID });
  api.onSignedOut = (why) => { if (S.view.value === "app") lock(why === "expired" ? "Your session ended. Unlock to continue." : null); };
  connectServer();
  if (id?.pending) { S.joinMethod.value = id.pending.method; S.joinStep.value = 3; S.view.value = "join"; pollJoin(); }
  else S.view.value = id ? "locked" : "welcome";
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

export function startEnroll() { S.enrollStep.value = 0; S.view.value = "enroll"; if (!S.server.value) connectServer(); }

export async function enroll(useDemo) {
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
    card = newCard();
    const cardBody = { tag: cardTag(card.secret), blob: await sealCard(card.secret, seed, accountId) };
    showInterrupt({ progress: 0.2, message: "Opening a post-quantum channel to your vault…" });

    const sess = await api.register({
      pub, commit, card: cardBody,
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
    indexKey = Suite.indexKey(seed);
    batch(() => {
      S.identity.value = { ...record, schema: 4 };
      S.session.value = sess;
      S.items.value = [];
      S.cardCode.value = sess.cardSet ? card.code : null;
      S.enrollStep.value = 2;
    });
    api.htp.pinnedKid = srv.kid;
    await endInterrupt(true, "Your HumID is bound to this device.", 700);
  } catch (err) {
    if (enrolled) try { await gate.forget(enrolled.handle); } catch {}
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
  "HumID recovery card", "",
  code, "",
  "This card restores your HumID on a new phone if you lose all your devices.",
  "Recovery waits 72 hours and alerts your other devices, so a stolen card alone is not enough.",
  "Keep it somewhere safe and offline. Anyone with this card and 72 hours unnoticed could open your vault.",
  "", `Created ${new Date().toLocaleDateString()}`,
].join("\n");

export async function saveCard(code) {
  markPicking();
  try { await saveBytes(utf8(cardText(code)), "HumID recovery card.txt", "text/plain"); toast("Saved your recovery card."); }
  catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function copyCard(code) {
  try { await navigator.clipboard.writeText(code); toast("Copied. Paste it somewhere safe, then clear your clipboard."); }
  catch { toast("Couldn't copy. Write the code down instead.", "warn"); }
}

/* ---------------- unlock / lock ---------------- */

export async function unlock() {
  const id = S.identity.value;
  if (!id?.server?.id) return toast("This identity is not registered with a vault server.", "error");
  try {
    showInterrupt({ purpose: "launch", label: "Unlock HumID", state: "scanning", progress: 0.04, needsHold: false, message: "Opening a post-quantum channel to your vault…" });
    const sess = await api.login({
      id: id.server.id,
      device: id.device?.id || "dev_" + "0".repeat(24),
      // The secure chip signs the server's sign-in challenge during the live check.
      sign: (message) => withKeys("launch", "Unlock HumID", async ({ dkeys, seed, interrupt, live, Suite }) => {
        indexKey = Suite.indexKey(seed);
        showInterrupt({ progress: 0.75, message: "Signing in with this device's key…" });
        return { sig: ml_dsa87.sign(message, dkeys.dsaSk), interrupt, live: live?.sig };
      }, { keepOpen: true, challenge: message }),
    });
    batch(() => { S.session.value = sess; S.lockIssue.value = null; S.view.value = "app"; });
    await endInterrupt(true, "Welcome back.", 500);
    refresh();
    loadAlerts();
  } catch (e) {
    wipe(indexKey); indexKey = null;
    if (["unknown_identity", "server_identity_changed", "device_removed", "device_not_proven"].includes(e?.code)) S.lockIssue.value = e.code;
    if (S.interrupt.value && S.interrupt.value.state !== "failed") await endInterrupt(false, friendly(e), 1600);
    else if (!S.interrupt.value && !cancelled(e)) toast(friendly(e), "error");
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
    S.devices.value = null;
    S.recovery.value = null;
    S.alerts.value = [];
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
    // Encrypt first (public keys only), then one live check signs the ciphertext's hash
    // in hardware and releases the key that signs the envelope.
    const Suite = suite(id.suite);
    const prepared = await Suite.prepareSeal({ bytes, name: finalName, type }, { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) });
    const size = bytes.length;
    wipe(bytes); bytes = null;
    const { envelope, index } = await withKeys("seal", `Seal ${finalName}`, async ({ keys, rec, live }) => {
      const sealed = Suite.finishSeal(prepared, keys, { identityCommit: id.commit, interrupt: { ...rec, ...(live ? { live: b64u(live.sig) } : {}) } });
      const idx = await Suite.sealIndex(indexKey, { name: finalName, type, size, category, addedAt: new Date().toISOString(), plainHash: sealed.plainHash });
      return { envelope: sealed.envelope, index: idx };
    }, { challenge: sealLiveMessage(prepared.ciphertextHash) });
    S.sheet.value = { ...S.sheet.value, stage: "upload" };
    await api.upload(envelope, index);
    S.sheet.value = { ...S.sheet.value, stage: "done" };
    await refresh();
    await sleep(650);
    S.sheet.value = null;
    toast(`${finalName} sealed. Only your face or fingerprint can open it.`);
    return true;
  } catch (e) {
    wipe(bytes);
    S.sheet.value = { ...S.sheet.value, stage: null };
    if (!cancelled(e)) toast(friendly(e), "error");
    return false;
  }
}

/** Download, verify, decrypt — all under one live check. Returns { bytes, meta }. */
async function fetchPlain(item, purpose, label) {
  return withStepUp("download", [item.id], purpose, label, async ({ keys, proof, Suite }) => {
    showInterrupt({ progress: 0.65, message: "Fetching sealed copy over HTP/1…" });
    const env = await api.download(item.id, proof);
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
    const env = await withStepUp("download", [item.id], "export", `Export sealed ${item.name}`, async ({ proof }) => api.download(item.id, proof));
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
    await withStepUp("remove", [item.id], "delete", `Delete ${item.name}`, async ({ proof }) => api.remove(item.id, proof));
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

/* ---------------- devices ---------------- */

export async function loadDevices() {
  const me = await quietly(api.me());
  if (me) S.devices.value = me.devices;
}

/** Look up the code a new device is showing. The API checks the code against the keys. */
export async function findLink(code) {
  try { return await api.getLink(code); }
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
    S.sheet.value = null;
    toast(`Approved. Finish on the ${req.platform}.`);
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
  const [card, contacts] = await Promise.all([quietly(api.card()), quietly(api.contacts())]);
  if (!card || !contacts) return;
  const names = [];
  for (const g of contacts.guardians || []) {
    let name = "A recovery contact";
    try { if (g.label && indexKey) name = (await suite().openIndex(indexKey, g.label)).name; } catch {}
    names.push(name);
  }
  S.recovery.value = { card, contacts: { n: contacts.n, threshold: contacts.threshold, createdAt: contacts.createdAt, names } };
}

export async function makeNewCard() {
  const accountId = S.identity.value.server.id;
  let card;
  try {
    await withStepUp("setCard", [], "card", "Make a recovery card", async ({ seed, proof }) => {
      card = newCard();
      await api.setCard({ tag: cardTag(card.secret), blob: await sealCard(card.secret, seed, accountId) }, proof);
    });
    S.sheet.value = { type: "card", code: card.code };
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
  finally { wipe(card?.secret); }
}

export async function removeCard() {
  try {
    await withStepUp("removeCard", [], "card", "Remove recovery card", async ({ proof }) => api.removeCard(proof));
    S.sheet.value = null;
    toast("Recovery card removed. The old card no longer works.");
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/** Look up a contact code someone showed you. The API checks it against their keys. */
export async function findContact(code) {
  try { return await api.getOffer(code); }
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
    await withStepUp("setContacts", [], "contacts", "Save recovery contacts", async ({ keys, seed, rec, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: `Splitting your account key into ${n} pieces…` });
      const shares = split(seed, n, t);
      const guardians = [];
      for (let i = 0; i < n; i++) {
        const c = contacts[i];
        const piece = encodeShare({ owner: id.server.id, label: ownerName, ...shares[i], t, n });
        const { envelope } = await Suite.seal({ bytes: piece, name: "HumID recovery piece", type: KEY_TYPE }, keys, { kemPk: c.offer.kemPk, xPk: c.offer.xPk }, { identityCommit: id.commit, interrupt: rec });
        guardians.push({ contact: c.offer.account, offer: c.code, envelope, label: await Suite.sealIndex(indexKey, { name: c.name.trim().slice(0, 40) || "Contact" }) });
        wipe(piece, shares[i].y);
      }
      await api.setContacts({ threshold: t, guardians }, proof);
    });
    S.sheet.value = null;
    toast(`Saved. Any ${t} of your ${n} contacts can help you recover.`);
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function removeContacts() {
  try {
    await withStepUp("removeContacts", [], "contacts", "Remove recovery contacts", async ({ proof }) => api.removeContacts(proof));
    S.sheet.value = null;
    toast("Recovery contacts removed. Their pieces no longer work.");
    loadRecovery();
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- being someone's recovery contact ---------------- */

/** Show a code someone types to make you their recovery contact. Public keys only. */
export async function offerToBeContact() {
  const p = S.identity.value.pub;
  try {
    const r = await api.offerContact({ kemPk: fromB64(p.kemPk), xPk: fromB64(p.xPk), dsaPk: fromB64(p.dsaPk) });
    S.sheet.value = { type: "offer", code: r.code, expiresAt: r.expiresAt };
  } catch (e) { toast(friendly(e), "error"); }
}

export async function findHelpRequest(code) {
  try { return await api.getHelp(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Live check 1: open the pieces you hold to see whose they are. Only names leave the check. */
export async function whoDoIProtect() {
  try {
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
  const a = await api.alerts().catch(() => null);
  if (a) S.alerts.value = a;
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

export function startJoin() { S.joinStep.value = 0; S.joinMethod.value = null; S.joinStatus.value = null; S.view.value = "join"; if (!S.server.value) connectServer(); }

/**
 * Bind this device and start the chosen route.
 * method: "link" | "card" | "contacts"; cardInput: what the person typed (card only).
 */
export async function beginJoin(method, { useDemo = false, cardInput = "" } = {}) {
  let cardSecret = null;
  if (method === "card") {
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
    both = concat(dseed, x);
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
      pending: { ...pending, devicePub: toB64(dkeys.dsaPk), startedAt: Date.now() }, device: null, pub: null, commit: null,
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
  if (st && ["approved", "released"].includes(st.status)) return finishJoin(st);
  if (st && ["expired", "cancelled", "completed"].includes(st.status)) return;
  const quick = p.method === "link" || st?.status === "collecting" || (st?.releaseAt && st.releaseAt - Date.now() < 60_000);
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
      account, via: p.method, recoveryId: p.requestId,
      device: { dsaPk: fromB64(p.devicePub), platform: PLATFORM, gateMethod: id.method, assurance: id.assurance },
      // One live check unlocks what arrived, and the secure chip attests a fresh liveness key to this session.
      sign: async (message, th) => {
        showInterrupt({ progress: 0.2, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)} to finish.` });
        await waitForHold(gate);
        released = await gate.release(id.gate.handle, { purpose: "enroll", prompt: "Open your HumID here", challenge: message, attest: th });
        secret = released.secret;
        both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
        const x = both.subarray(SEED);
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
    indexKey = Suite.indexKey(seed);
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
    if (p.method !== "link") toast("Recovered. Consider making a new recovery card in Security.", "warn");
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
    toast(`${friendly(e)} Local data was kept.`, "error");
    return;
  }
  try { await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await store.clearIdentity();
  await store.clearVault();
  wipe(indexKey); indexKey = null;
  batch(() => {
    S.identity.value = null; S.session.value = null; S.items.value = []; S.ledger.value = null; S.sheet.value = null;
    S.devices.value = null; S.recovery.value = null; S.alerts.value = []; S.view.value = "welcome";
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
  api.htp.close();
  api.htp.pinnedKid = PINNED_KID;
  api.htp.server = null;
  batch(() => { S.identity.value = null; S.lockIssue.value = null; S.view.value = "welcome"; });
  connectServer();
}
