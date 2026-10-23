// Recovery modes (docs/RECOVERY.md#two-recovery-modes): the holder chooses at setup.
//   holder-only  only a live check on one of your own devices opens anything. No recovery
//                part is ever made for the server. Lose every device and the vault is gone.
//   hardened     two different proofs, a wait, and a veto from any device you still have.
// The choice is a statement signed by the account key, chained to the one before it. This
// device checks every statement the server shows it against its own account key AND against
// the newest one it has itself checked before (pinned in its sealed identity record), so a
// server can't quietly switch it, delete it, or put an older one back (V74-01/02).
import { fromB64 } from "@humid/codec";
import { ml_dsa87 } from "@humid/htp";
import { recoveryModeMessage, recoveryModeHash, followsMode, RECMODE_GENESIS, RECOVERY_MODES, routesFor } from "@humid/recovery";
import * as S from "./state.js";
import { R } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, showInterrupt } from "./interrupt.js";
import { updateIdentity } from "./identity.js";

export { RECOVERY_MODES, routesFor };
export const HOLDER_ONLY = RECOVERY_MODES.holderOnly;
export const HARDENED = RECOVERY_MODES.hardened;
/** What a new HumID starts with unless its holder picks the other: the recommended one. */
export const DEFAULT_MODE = HARDENED;

/** The account key's statement { mode, version, epoch, prev, sig } (sig as bytes). `after`: the statement it replaces. */
export function signMode(accountId, dsaSk, mode, version = 1, epoch = 1, after = null) {
  const prev = after && version > 1 ? recoveryModeHash(accountId, after) : RECMODE_GENESIS;
  return { mode, version, epoch, prev, sig: ml_dsa87.sign(recoveryModeMessage(accountId, mode, version, epoch, prev), dsaSk) };
}

const bytesOf = (s) => (typeof s === "string" ? fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)) : s);

/**
 * Check a statement against this account's own key. Returns the mode it proves, "hardened" for
 * an account from before modes (version 0, nothing signed), or null if the account key never
 * signed it. On its own this says nothing about whether it's the NEWEST one: see judgeMode.
 */
export function verifiedMode(accountId, dsaPk, st) {
  if (!st || st.broken) return null;
  if (!st.version && !st.sig) return st.mode === HARDENED ? HARDENED : null;
  try {
    return ml_dsa87.verify(bytesOf(st.sig), recoveryModeMessage(accountId, st.mode, st.version, st.epoch ?? 1, st.prev ?? RECMODE_GENESIS), dsaPk) ? st.mode : null;
  } catch { return null; }
}

/**
 * Judge what the server shows (`served`) against what this device pinned (`pin`, the newest
 * statement it has checked: { mode, version, epoch, prev }). Returns { trusted, mode, newer }:
 *   - a statement the account key didn't sign: untrusted;
 *   - nothing (version 0) once this device has pinned one: deleted, untrusted;
 *   - a lower version or epoch, or the same version with a different statement: rolled back or
 *     forked, untrusted;
 *   - a higher version (the holder's other device switched): trusted, and pinned (newer).
 * Untrusted always answers holder-only, whatever was pinned: the app then offers no recovery
 * setup and creates no escrow on the server's say-so.
 */
export function judgeMode(accountId, dsaPk, served, pin) {
  const mode = verifiedMode(accountId, dsaPk, served);
  if (!mode) return { trusted: false, mode: HOLDER_ONLY, reason: "unsigned" };
  if (!pin?.version) return { trusted: true, mode, newer: !!served.version };
  if (!served.version) return { trusted: false, mode: HOLDER_ONLY, reason: "missing" };
  const next = { mode: served.mode, version: served.version, epoch: served.epoch ?? 1, prev: served.prev ?? RECMODE_GENESIS };
  if (!followsMode(accountId, pin, next)) return { trusted: false, mode: HOLDER_ONLY, reason: next.version <= pin.version ? "rolled back" : "forked" };
  return { trusted: true, mode, newer: next.version > pin.version };
}

/** Pin a checked statement in this device's sealed identity record, if it's newer than the pin. */
export async function pinMode(st) {
  if (!st?.version) return;
  const pin = { mode: st.mode, version: st.version, epoch: st.epoch ?? 1, prev: st.prev ?? RECMODE_GENESIS };
  await updateIdentity((cur) => {
    if (cur.modePin?.version >= pin.version) return null;
    cur.modePin = pin;
    cur.recoveryMode = pin.mode;
  });
}
const pinned = () => S.identity.value?.modePin || null;

/** The newest recovery.mode_set in the ledger this device verified, as { mode, version, epoch }, or null. */
function ledgerMode() {
  const entries = S.ledger.value?.ok ? S.ledger.value.entries || [] : [];
  let best = null;
  for (const e of entries) if (e.type === "recovery.mode_set" && e.detail?.version > (best?.version || 0)) best = { mode: e.detail.mode, version: e.detail.version, epoch: e.detail.epoch ?? 1 };
  return best;
}

/** What's still stored on the server for a recovery, in words. */
const ESCROW_WORDS = { card: "recovery card", contacts: "witnesses", anchor: "ID chip link", key: "security keys" };
export const escrowWords = (list) => (list || []).map((k) => ESCROW_WORDS[k] || k);

/**
 * This account's recovery mode, as both its devices and the server see it:
 * { mode, version, epoch, prev, escrow, trusted, reason } on S.recoveryMode. Checked against the
 * account key, this device's pin, identity's copy (/identity/me), and the newest
 * recovery.mode_set in the ledger this device verified. `trusted` false is shown as a warning,
 * and the app then behaves as holder-only (it offers no recovery setup and makes no pieces).
 */
export async function loadRecoveryMode() {
  const id = S.identity.value;
  if (!id?.server?.id || !id.pub || S.offline.value) return S.recoveryMode.value;
  const acct = id.server.id, dsaPk = fromB64(id.pub.dsaPk);
  let st;
  try { st = await R.api.recoveryMode(); }
  catch (e) {
    // An older server has no modes: everything works as hardened, as before (unless this device pinned one).
    if (e?.status === 404 && !pinned()) { S.recoveryMode.value = { mode: HARDENED, version: 0, epoch: 1, escrow: null, trusted: true, legacy: true }; return S.recoveryMode.value; }
    return S.recoveryMode.value;
  }
  const me = await R.api.me().catch(() => null);
  const pin = pinned();
  let v = judgeMode(acct, dsaPk, st, pin);
  // Identity keeps the same chain: if it's further along, the recovery service's copy is stale.
  const other = me?.recoveryMode;
  if (v.trusted && other?.version && other.version !== st.version) {
    const w = judgeMode(acct, dsaPk, other, pin);
    if (w.trusted && other.version > st.version) v = { trusted: false, mode: HOLDER_ONLY, reason: "rolled back" };
    else if (!w.trusted) v = w;
  }
  // The ledger is signed, chained and in the public log: a mode_set newer than what's served means rollback.
  const led = ledgerMode();
  if (v.trusted && led && led.version > (st.version || 0)) v = { trusted: false, mode: HOLDER_ONLY, reason: "rolled back" };
  if (v.trusted && v.newer) await pinMode(st).catch(() => {});
  S.recoveryMode.value = {
    mode: v.mode, version: st.version, epoch: v.trusted ? st.epoch ?? 1 : Math.max(st.epoch ?? 1, pin?.epoch ?? 1),
    prev: st.prev ?? RECMODE_GENESIS, escrow: st.escrow || [], trusted: v.trusted, ...(v.reason ? { reason: v.reason } : {}),
    statement: v.trusted && st.version ? { mode: st.mode, version: st.version, epoch: st.epoch ?? 1, prev: st.prev ?? RECMODE_GENESIS } : pin,
  };
  return S.recoveryMode.value;
}

/** The statement a new one chains to: the newest this device trusts. */
const latest = () => S.recoveryMode.value?.statement || pinned() || null;

export const isHolderOnly = () => S.recoveryMode.value?.mode === HOLDER_ONLY;
/** May this device set up recovery pieces now? Only in a hardened mode it has checked. */
export const mayMakePieces = () => S.recoveryMode.value?.mode === HARDENED && S.recoveryMode.value?.trusted !== false;
/** Which set of recovery pieces this account is on (CRYPTO-02): new pieces are made for it. */
export const currentEpoch = () => S.recoveryMode.value?.epoch || 1;

/**
 * Make new recovery pieces (CRYPTO-02): one live check signs a new epoch. The vault server
 * then deletes every piece it held from older sets and cancels any recovery under way, and
 * every piece already out in the world (a removed witness's share, an old card, its blob in a
 * backup) no longer fits with anything new. The holder then makes the proofs again: a new
 * card, their witnesses again, a fresh chip read, their security keys again.
 */
export async function newRecoveryPieces() {
  const id = S.identity.value;
  const cur = await loadRecoveryMode();
  if (!cur || cur.mode !== HARDENED || !cur.trusted) return false;
  try {
    let sent;
    await withStepUp("setRecoveryMode", [], "mode", "Make new recovery pieces", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Retiring your old recovery pieces…" });
      sent = signMode(id.server.id, keys.dsaSk, HARDENED, (cur.version || 0) + 1, (cur.epoch || 1) + 1, latest());
      return R.api.setRecoveryMode(sent, proof);
    });
    await pinMode(sent);
    toast("Old recovery pieces retired. Set up your proofs again: they all start fresh.", "warn");
    await loadRecoveryMode();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/** Holder-only → hardened: one fresh live check signs the new statement and sends it. */
/** The next statement's version and epoch: one past the newest this device knows (served or pinned). */
const nextAfter = (cur) => {
  const base = latest() || cur;
  return { version: Math.max(cur?.version || 0, base?.version || 0) + 1, epoch: Math.max(cur?.epoch || 1, base?.epoch || 1) + 1 };
};

export async function switchToHardened() {
  const id = S.identity.value, cur = await loadRecoveryMode();
  if (!cur || (cur.mode === HARDENED && cur.trusted)) return true;
  // The server's record is broken or behind what this device knows: say so; don't build on it.
  if (!cur.trusted) { toast("Your vault server's record of how you recover doesn't check out, so HumID won't change it now. Tell whoever runs your server.", "error"); return false; }
  try {
    let sent;
    await withStepUp("setRecoveryMode", [], "mode", "Turn on recovery", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Signing your choice with your account key…" });
      // A new epoch too: any recovery piece from before holder-only can never count again.
      const n = nextAfter(cur);
      sent = signMode(id.server.id, keys.dsaSk, HARDENED, n.version, n.epoch, latest());
      return R.api.setRecoveryMode(sent, proof);
    });
    await pinMode(sent);
    toast("Recovery is on. Set up two proofs so you can get back in.");
    await loadRecoveryMode();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/**
 * Hardened → holder-only. Destructive, so it runs in order: delete every recovery piece the
 * server holds, each under its own live check, and only then sign and send the new mode. The
 * server refuses the switch while anything is left, so a half-finished switch never leaves the
 * holder believing they're holder-only while a piece still exists.
 */
const REMOVE = {
  card: ["removeCard", "Delete your recovery card", (proof) => R.api.removeCard(proof)],
  contacts: ["removeContacts", "Delete your witnesses' pieces", (proof) => R.api.removeContacts(proof)],
  anchor: ["removeAnchor", "Unlink your ID chip", (proof) => R.api.removeAnchor(proof)],
  key: ["removeAllKeys", "Delete your security keys' pieces", (proof) => R.api.removeAllKeys(proof)],
};
export async function switchToHolderOnly() {
  const id = S.identity.value;
  let cur = await loadRecoveryMode();
  if (!cur || (cur.mode === HOLDER_ONLY && cur.trusted)) return true;
  if (!cur.trusted) { toast("Your vault server's record of how you recover doesn't check out, so HumID won't change it now. Tell whoever runs your server.", "error"); return false; }
  for (const kind of ["card", "contacts", "anchor", "key"]) {
    if (!cur.escrow?.includes(kind)) continue;
    const [op, label, call] = REMOVE[kind];
    try { await withStepUp(op, [], "remove", label, async ({ proof }) => call(proof)); }
    catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); await loadRecoveryMode(); return false; } // nothing switched
  }
  cur = await loadRecoveryMode();
  if (cur.escrow?.length) { toast(`Still on your vault: your ${escrowWords(cur.escrow).join(", ")}. Remove ${cur.escrow.length > 1 ? "them" : "it"} first.`, "warn"); return false; }
  try {
    let sent;
    await withStepUp("setRecoveryMode", [], "mode", "Only my devices", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Signing your choice with your account key…" });
      const n = nextAfter(cur);
      sent = signMode(id.server.id, keys.dsaSk, HOLDER_ONLY, n.version, n.epoch, latest());
      return R.api.setRecoveryMode(sent, proof);
    });
    await pinMode(sent);
    toast("Done. Only your own devices can open your vault now.");
    await loadRecoveryMode();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/**
 * The Protection checklist (the You hub counts it too). Empty until recovery and devices are
 * known. Holder-only: devices are the whole of it (there's no recovery to set up).
 */
export function protectionItems(rec, devices, mode = S.recoveryMode.value?.mode) {
  if (!rec || !devices) return [];
  if (mode === HOLDER_ONLY) {
    return [
      { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Your only way back in if this phone is lost. Add one now", target: "devices", extra: { open: "add" } },
      { done: devices.length >= 3, icon: "key", label: "A third device, kept somewhere else", todo: "In case both go at once: at home, or with someone you trust", target: "devices", extra: { open: "add" } },
    ];
  }
  return [
    { done: !!rec.proofs?.card, icon: "idcard", label: "Recovery card", todo: "Make the card that's one of your proofs", target: "recovery", extra: { open: "card" } },
    { done: !!(rec.proofs?.witness || rec.proofs?.anchor || rec.proofs?.key), icon: "users", label: "A second proof", todo: "Witnesses who vouch for you, your ID chip, or a security key", target: "recovery" },
    { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Another phone, so a lost phone isn't an emergency", target: "devices", extra: { open: "add" } },
  ];
}

/** How many devices this account has, and whether that's a problem in this mode. */
export function deviceRisk(mode, devices) {
  if (!devices) return null;
  const n = devices.length;
  if (mode === HOLDER_ONLY && n <= 1) return "alone"; // the only safety net is gone
  return null;
}
