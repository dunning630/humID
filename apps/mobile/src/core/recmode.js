// Recovery modes (docs/RECOVERY.md#two-recovery-modes): the holder chooses at setup.
//   holder-only  only a live check on one of your own devices opens anything. No recovery
//                part is ever made for the server. Lose every device and the vault is gone.
//   hardened     two different proofs, a wait, and a veto from any device you still have.
// The choice is a statement signed by the account key, chained to the one before it. This
// device checks every statement the server shows it against its own account key AND against
// the newest one it has itself checked before (pinned in its sealed identity record), so a
// server can't quietly switch it, delete it, or put an older one back (V74-01/02).
//
// And a device makes recovery pieces only for a statement it can vouch for itself (V74B-01):
// one equal to, or after, the one it pinned (at setup, when it signed a change, or from the
// device that linked it), or, on a device that came back through a recovery and has no pin yet,
// the statement the pieces it combined were made under. What identity, the recovery service and
// the ledger show is never enough on its own: a fully colluding operator controls all three.
// docs/RECOVERY.md#when-a-phone-makes-recovery-pieces says what that does and doesn't cover.
import { fromB64 } from "@humid/codec";
import { ml_dsa87 } from "@humid/htp";
import { recoveryModeMessage, recoveryModeHash, followsMode, RECMODE_GENESIS, RECOVERY_MODES, routesFor } from "@humid/recovery";
import * as S from "./state.js";
import { R } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, showInterrupt } from "./interrupt.js";
import { updateIdentity } from "./identity.js";
import { loadLedger } from "./ledger.js";

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
 * statement it has checked: { mode, version, epoch, prev }), or, on a recovered device with no
 * pin yet, the set of pieces it was recovered from (`floor`: { epoch }).
 * Returns { trusted, vouched, mode, newer }:
 *   - a statement the account key didn't sign: untrusted;
 *   - nothing (version 0) once this device has pinned one: deleted, untrusted;
 *   - a lower version or epoch, or the same version with a different statement: rolled back or
 *     forked, untrusted;
 *   - the pinned one, or a later one that follows it (the holder's other device switched):
 *     trusted and vouched; a later one is pinned (newer);
 *   - no pin, but a floor: hardened at the floor's own epoch is the statement those pieces were
 *     made under (every change of mode starts a new epoch), so trusted, vouched and pinned. An
 *     older epoch is rolled back, holder-only at that epoch is forked (no piece is ever made in
 *     holder-only), and a newer epoch can't be vouched for;
 *   - neither: trusted (the account key signed it, so it's shown) but NOT vouched for, and never
 *     pinned. The servers could be showing an older choice than the holder's newest (V74B-01).
 * Untrusted always answers holder-only, whatever was pinned: the app then offers no recovery
 * setup and creates no escrow on the server's say-so. Unvouched makes no recovery piece either.
 */
export function judgeMode(accountId, dsaPk, served, pin, floor = null) {
  const mode = verifiedMode(accountId, dsaPk, served);
  const refuse = (reason) => ({ trusted: false, vouched: false, mode: HOLDER_ONLY, reason });
  if (!mode) return refuse("unsigned");
  if (!pin?.version) {
    if (!floor?.epoch) return { trusted: true, vouched: false, mode, newer: false };
    if (!served.version) return refuse("missing");
    const e = served.epoch ?? 1;
    if (e < floor.epoch) return refuse("rolled back");
    if (e === floor.epoch && mode !== HARDENED) return refuse("forked");
    return e === floor.epoch ? { trusted: true, vouched: true, mode, newer: true } : { trusted: true, vouched: false, mode, newer: false };
  }
  if (!served.version) return refuse("missing");
  const next = { mode: served.mode, version: served.version, epoch: served.epoch ?? 1, prev: served.prev ?? RECMODE_GENESIS };
  if (!followsMode(accountId, pin, next)) return refuse(next.version <= pin.version ? "rolled back" : "forked");
  return { trusted: true, vouched: true, mode, newer: next.version > pin.version };
}

/**
 * The epoch of the pieces a two-proof recovery combined: the first two different kinds, as
 * combineQuorum takes them. A server can't change it: each card, security-key and chip part is
 * sealed with its epoch in the authenticated data, a witness piece carries it inside the
 * envelope, and the two must rebuild this account's own key. Null when they don't agree.
 */
export function recoveredEpoch(parts) {
  const two = [...new Map(parts.map((p) => [p.x, p])).values()].slice(0, 2);
  return two.length === 2 && (two[0].epoch ?? 1) === (two[1].epoch ?? 1) ? two[0].epoch ?? 1 : null;
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
const floorOf = () => (S.identity.value?.modeFloor?.epoch ? S.identity.value.modeFloor : null);

/**
 * The newest recovery.mode_set in the ledger this device verified, as { mode, version, epoch }, or
 * null. Loaded here when this session hasn't verified a page yet, so the check doesn't depend on
 * the holder having opened Activity first.
 */
const ledgerPage = () => {
  const l = S.ledger.value;
  return l?.ok && (!l.account || l.account === S.identity.value?.server?.id) ? l : null;
};
async function verifiedLedger() {
  if (ledgerPage() || S.decoy.value || S.offline.value) return;
  try { await loadLedger(); } catch { /* checked again next time */ }
}
function ledgerMode() {
  const entries = ledgerPage()?.entries || [];
  let best = null;
  for (const e of entries) if (e.type === "recovery.mode_set" && e.detail?.version > (best?.version || 0)) best = { mode: e.detail.mode, version: e.detail.version, epoch: e.detail.epoch ?? 1, hash: e.detail.hash || null };
  return best;
}

/**
 * Every change of recovery mode in the ledger this device verified, oldest first:
 * [{ mode, version, at, from, setup }]. Shown before this phone confirms a choice it can't vouch
 * for, so the holder sees "turned off on <date>" if the servers are showing an older one.
 */
export function modeHistory() {
  const entries = ledgerPage()?.entries || [];
  return entries.filter((e) => e.type === "recovery.mode_set" && e.detail?.version)
    .map((e) => ({ mode: e.detail.mode, version: e.detail.version, at: e.at, from: e.detail.from || null, setup: e.detail.at === "setup" }));
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
    // That's the server's word, though: no recovery piece is made on it (V74B-01).
    if (e?.status === 404 && !pinned()) { S.recoveryMode.value = { mode: HARDENED, version: 0, epoch: 1, escrow: null, trusted: true, vouched: false, unvouched: "legacy", legacy: true }; return S.recoveryMode.value; }
    return S.recoveryMode.value;
  }
  const me = await R.api.me().catch(() => null);
  const pin = pinned();
  let v = judgeMode(acct, dsaPk, st, pin, floorOf());
  // Identity keeps the same chain: if it's further along, the recovery service's copy is stale.
  const other = me?.recoveryMode;
  if (v.trusted && other?.version && other.version !== st.version) {
    const w = judgeMode(acct, dsaPk, other, pin, floorOf());
    if (w.trusted && other.version > st.version) v = { trusted: false, vouched: false, mode: HOLDER_ONLY, reason: "rolled back" };
    else if (!w.trusted) v = w;
  }
  // The ledger is signed, chained and in the public log: a mode_set newer than what's served means
  // rollback, and one at the same version that says something else means the served one isn't it.
  if (v.trusted) await verifiedLedger();
  const led = ledgerMode();
  if (v.trusted && led && led.version > (st.version || 0)) v = { trusted: false, vouched: false, mode: HOLDER_ONLY, reason: "rolled back" };
  else if (v.trusted && led && led.version === st.version && (led.mode !== st.mode || led.epoch !== (st.epoch ?? 1) || (led.hash && led.hash !== recoveryModeHash(acct, { mode: st.mode, version: st.version, epoch: st.epoch ?? 1, prev: st.prev ?? RECMODE_GENESIS })))) v = { trusted: false, vouched: false, mode: HOLDER_ONLY, reason: "forked" };
  if (v.trusted && v.newer) await pinMode(st).catch(() => {});
  S.recoveryMode.value = {
    mode: v.mode, version: st.version, epoch: v.trusted ? st.epoch ?? 1 : Math.max(st.epoch ?? 1, pin?.epoch ?? 1),
    prev: st.prev ?? RECMODE_GENESIS, escrow: st.escrow || [], trusted: v.trusted, vouched: v.vouched === true,
    ...(v.trusted && !v.vouched ? { unvouched: "no pin" } : {}), ...(v.reason ? { reason: v.reason } : {}),
    statement: v.trusted && st.version ? { mode: st.mode, version: st.version, epoch: st.epoch ?? 1, prev: st.prev ?? RECMODE_GENESIS } : pin,
  };
  return S.recoveryMode.value;
}

/** The statement a new one chains to: the newest this device trusts. */
const latest = () => S.recoveryMode.value?.statement || pinned() || null;

export const isHolderOnly = () => S.recoveryMode.value?.mode === HOLDER_ONLY;
/**
 * May this device make recovery pieces now? Only in a hardened mode it has checked against its
 * account key AND can vouch for itself (V74B-01): never on what the servers show alone.
 */
export const mayMakePieces = () => {
  const m = S.recoveryMode.value;
  return m?.mode === HARDENED && m.trusted === true && m.vouched === true;
};
/** Why this device makes no recovery piece now, in words (core/recovery.js partOf). */
export function whyNoPieces() {
  const m = S.recoveryMode.value;
  if (m?.mode === HARDENED && m.trusted && !m.vouched) {
    return m.unvouched === "legacy"
      ? "Your vault server is too old to keep your signed recovery choice, so this phone can't confirm it and made no recovery piece. Ask whoever runs it to update."
      : "This phone can't confirm your recovery choice for itself, so it made no recovery piece. Under Recovery, see how to confirm it here.";
  }
  return "This HumID is set to open only on your own devices, or your vault server's record of that doesn't check out. No recovery piece was made.";
}
/** Hardened, signed by the account key, but not something this phone can vouch for itself. */
export const isUnconfirmed = () => {
  const m = S.recoveryMode.value;
  return !!(m && m.mode === HARDENED && m.trusted && m.vouched === false);
};
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
  // A choice this phone can't vouch for is confirmed first, with its history shown (confirmModeHere).
  if (!cur || cur.mode !== HARDENED || !cur.trusted || !cur.vouched) return false;
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

/**
 * The holder confirms, on this phone, a hardened choice it can't vouch for (V74B-01): after the
 * mode history this phone could verify has been shown, one live check signs a NEW statement
 * (the next version and a new epoch, chained to the one shown) with the account key. That is the
 * holder's own act, which no server can make; this phone pins it and may then make pieces.
 * If the holder had in fact turned recovery off on another device, that device sees two
 * different statements at one version and reports it.
 */
export async function confirmModeHere() {
  const id = S.identity.value;
  const cur = await loadRecoveryMode();
  if (!cur || cur.mode !== HARDENED || !cur.trusted || cur.vouched || cur.legacy) return !!cur?.vouched;
  try {
    let sent;
    await withStepUp("setRecoveryMode", [], "mode", "Confirm recovery on this phone", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Signing your choice with your account key…" });
      const n = nextAfter(cur);
      sent = signMode(id.server.id, keys.dsaSk, HARDENED, n.version, n.epoch, latest());
      return R.api.setRecoveryMode(sent, proof);
    });
    await pinMode(sent);
    toast("Confirmed on this phone. Your recovery pieces start fresh: set up your proofs again.", "warn");
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
    // Not "only your devices can open it": pieces made before still fit each other (V74-04).
    toast("Done. Your vault server keeps no recovery for you now. Destroy your old recovery card: old pieces still fit each other.", "warn");
    await loadRecoveryMode();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/**
 * The Protection checklist (the You hub counts it too). Empty until recovery and devices are
 * known. Holder-only: devices are the whole of it (there's no recovery to set up).
 */
export function protectionItems(rec, devices, mode = S.recoveryMode.value?.mode, unconfirmed = isUnconfirmed()) {
  if (!rec || !devices) return [];
  // A choice this phone can't vouch for: it asks for no recovery piece (V74B-01), only that the
  // holder look at the choice and, if they want recovery, confirm it from here.
  if (mode === HARDENED && unconfirmed) {
    return [
      { done: false, icon: "shield", label: "Confirm how you get back in", todo: "This phone can't confirm your recovery choice for itself yet", target: "recovery" },
      { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Another phone, so a lost phone isn't an emergency", target: "devices", extra: { open: "add" } },
    ];
  }
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
