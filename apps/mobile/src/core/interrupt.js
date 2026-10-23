// The biological interrupt: one live biometric check releases this device's keys for
// exactly one operation, then they're wiped. Every check is a LIVE face or fingerprint:
// no PIN, no password. On phones the secure chip's liveness key signs a challenge known
// BEFORE the prompt opens (the sign-in message, a step-up ticket naming the exact
// request, or a sealed file's hash), so the server can verify that a live check
// approved precisely that.
import { fromB64, toB64 } from "@humid/codec";
import { suite } from "@humid/crypto";
import { adapter as gateAdapter, CANCELLED } from "@humid/gate";
import { ml_dsa87 } from "@humid/htp";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import * as S from "./state.js";
import { R, SEED, wipe, sleep, localChallenge } from "./runtime.js";
import { toast, friendly, cancelled, haptic } from "./notify.js";

export function gateLabel(method) {
  return ({
    "ios-keychain-biometry": "Face ID or Touch ID",
    "android-keystore-biometric": "your face or fingerprint",
    "macos-keychain-biometry": "Touch ID",
    "windows-winbio-fingerprint": "your fingerprint",
    "linux-fprintd-keyring": "your fingerprint",
  })[method] || "your face or fingerprint";
}

/**
 * Checks that are part of a conversation's rhythm (sending, opening a conversation) show as a
 * compact card over the composer and get out of the way quickly. It is the same live check;
 * only less of the screen is taken while the sensor does its work.
 */
export const COMPACT = new Set(["send", "read"]);
export function showInterrupt(patch) { S.interrupt.value = { ...(S.interrupt.value || {}), ...patch }; }
export const holdMessage = "Demo mode has no sensor. Press and hold to stand in for it.";

/* the press-and-hold stand-in for a sensor (demo gate, development builds only) */
let holdWaiter = null;
export function holdComplete() { holdWaiter?.resolve(); holdWaiter = null; }
export function holdCancel() { holdWaiter?.reject(new Error(CANCELLED)); holdWaiter = null; }
export const waitForHold = (gate) => gate.needsHold ? new Promise((resolve, reject) => { holdWaiter = { resolve, reject }; }) : null;

export async function endInterrupt(ok, message, ms) {
  if (ok || message !== "The check was cancelled.") haptic(ok);
  showInterrupt({ state: ok ? "verified" : "failed", needsHold: false, progress: 1, message });
  await sleep(ms);
  S.interrupt.value = null;
}

/** The keys a session holds while unlocked, all derived from the account seed inside the check. */
export function sessionKeys(Suite, seed) {
  wipe(R.indexKey, R.offlineKey, R.settingsKey, R.msgKey);
  R.indexKey = Suite.indexKey(seed);
  R.offlineKey = Suite.offlineKey ? Suite.offlineKey(seed) : null;
  R.settingsKey = Suite.settingsKey ? Suite.settingsKey(seed) : null;
  // 4.0 messaging: seals this device's contact list and wraps each conversation's newest key.
  R.msgKey = hkdf(sha3_256, seed, undefined, new TextEncoder().encode("HUMID-MSG-v1 local store"), 32);
}
export function clearKeys() {
  wipe(R.indexKey, R.offlineKey, R.settingsKey, R.msgKey);
  R.indexKey = null; R.offlineKey = null; R.settingsKey = null; R.msgKey = null; R.duressSetting = null; R.duressUnreadable = false;
  S.liveAt.value = 0;
  R.hooks.stopMessaging?.(); // whatever messaging decrypted goes with the keys
}

/** Throws when the app is showing the offline copy: anything that needs the vault waits for a connection. */
export function needVault() {
  if (S.offline.value) throw Object.assign(new Error("offline"), { code: "offline" });
}

/**
 * Run fn with this device's keys, inside ONE live biometric check. The gate signs
 * `challenge` with the device's liveness key during that check.
 * fn gets { keys (account), dkeys (device), seed (account seed), interrupt, rec, live, Suite }.
 */
export async function withKeys(purpose, label, fn, { keepOpen = false, challenge, attest } = {}) {
  const id = S.identity.value;
  const Suite = suite(id.suite);
  let gate;
  R.busy = true;
  let secret, both, keys, dkeys;
  try {
    gate = gateAdapter(id.gate.adapter);
    showInterrupt({ purpose, label, state: "scanning", progress: 0.08, needsHold: !!gate.needsHold,
      message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
    if (!id.device) throw Object.assign(new Error("This HumID was made by an earlier test version and has to be set up again."), { code: "unknown_identity" });
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose, prompt: label, challenge: challenge ?? localChallenge(purpose), attest });
    secret = rel.secret;
    // The human-to-human rule (@humid/msg live.js): when this phone's holder was last proven live.
    S.liveAt.value = Date.now();
    showInterrupt({ needsHold: false, progress: 0.45, message: rel.live ? "Your phone's secure chip confirmed the check. Unlocking your keys…" : "Unlocking your keys on this device…" });
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    const seed = both.subarray(0, SEED);
    keys = Suite.deriveKeys(seed);
    dkeys = Suite.deriveKeys(both.subarray(SEED, 2 * SEED));
    if (toB64(keys.dsaPk) !== id.pub.dsaPk || toB64(dkeys.dsaPk) !== id.device.dsaPk) throw new Error("Unlocked keys do not match this identity.");
    const interrupt = { method: rel.interrupt.method, assurance: rel.interrupt.assurance };
    const out = await fn({ keys, dkeys, seed, interrupt, rec: rel.interrupt, live: rel.live, Suite });
    if (keepOpen) showInterrupt({ progress: 0.85, message: "Keys wiped from memory. Waiting for your vault to confirm…" });
    else await endInterrupt(true, "Verified. Keys wiped from memory.", COMPACT.has(purpose) ? 180 : 620);
    return out;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1600);
    if (e?.code === "key_invalidated") R.hooks.keyGone?.();
    throw e;
  } finally {
    wipe(secret, both);
    if (keys) Suite.wipeKeys(keys);
    if (dkeys) Suite.wipeKeys(dkeys);
    setTimeout(() => { R.busy = false; }, 600);
  }
}

/**
 * A step-up: reserve the request slot first, let the liveness key sign that slot
 * during the check, then send the request with both signatures.
 * fn gets withKeys' arguments plus `proof`, to pass as the API call's stepUp.
 */
export async function withStepUp(op, args, purpose, label, fn) {
  needVault();
  const ticket = await R.api.ticket(op, ...args);
  return withKeys(purpose, label, (k) => fn({
    ...k,
    proof: { ticket, sign: async (message) => ({ sig: ml_dsa87.sign(message, k.dkeys.dsaSk), interrupt: k.interrupt, live: k.live?.sig }) },
  }), { challenge: ticket.live });
}

/** For modules that report through toasts after a check. */
export const report = (e) => { if (!cancelled(e)) toast(friendly(e), "error"); };
