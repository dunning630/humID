// Recovery modes (docs/RECOVERY.md#two-recovery-modes): the holder chooses at setup.
//   holder-only  only a live check on one of your own devices opens anything. No recovery
//                part is ever made for the server. Lose every device and the vault is gone.
//   hardened     two different proofs, a wait, and a veto from any device you still have.
// The choice is a statement signed by the account key. This device checks every statement
// the server shows it against its own account key, so a server can't quietly switch it.
import { fromB64 } from "@humid/codec";
import { ml_dsa87 } from "@humid/htp";
import { recoveryModeMessage, RECOVERY_MODES, routesFor } from "@humid/recovery";
import * as S from "./state.js";
import { R } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, showInterrupt } from "./interrupt.js";

export { RECOVERY_MODES, routesFor };
export const HOLDER_ONLY = RECOVERY_MODES.holderOnly;
export const HARDENED = RECOVERY_MODES.hardened;
/** What a new HumID starts with unless its holder picks the other: the recommended one. */
export const DEFAULT_MODE = HARDENED;

/** The account key's statement { mode, version, epoch, sig } (sig as bytes). */
export function signMode(accountId, dsaSk, mode, version = 1, epoch = 1) {
  return { mode, version, epoch, sig: ml_dsa87.sign(recoveryModeMessage(accountId, mode, version, epoch), dsaSk) };
}

/**
 * Check a statement the server returned against this account's own key. Returns the mode it
 * proves, "hardened" for an account from before modes (version 0, nothing signed), or null
 * if the server shows something the account key never signed.
 */
export function verifiedMode(accountId, dsaPk, st) {
  if (!st || st.broken) return null;
  if (!st.version && !st.sig) return st.mode === HARDENED ? HARDENED : null;
  try {
    const sig = typeof st.sig === "string" ? fromB64(st.sig.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((st.sig.length + 3) % 4)) : st.sig;
    return ml_dsa87.verify(sig, recoveryModeMessage(accountId, st.mode, st.version, st.epoch ?? 1), dsaPk) ? st.mode : null;
  } catch { return null; }
}

/** What's still stored on the server for a recovery, in words. */
const ESCROW_WORDS = { card: "recovery card", contacts: "witnesses", anchor: "ID chip link", key: "security keys" };
export const escrowWords = (list) => (list || []).map((k) => ESCROW_WORDS[k] || k);

/**
 * This account's recovery mode, as both its devices and the server see it:
 * { mode, version, epoch, escrow, trusted } on S.recoveryMode. `trusted` is false when the
 * server's statement doesn't verify against the account key: shown as a warning, and the
 * app then behaves as holder-only (it offers no recovery setup).
 */
export async function loadRecoveryMode() {
  const id = S.identity.value;
  if (!id?.server?.id || !id.pub || S.offline.value) return S.recoveryMode.value;
  let st;
  try { st = await R.api.recoveryMode(); }
  catch (e) {
    // An older server has no modes: everything works as hardened, as before.
    if (e?.status === 404) { S.recoveryMode.value = { mode: HARDENED, version: 0, epoch: 1, escrow: null, trusted: true, legacy: true }; return S.recoveryMode.value; }
    return S.recoveryMode.value;
  }
  const mode = verifiedMode(id.server.id, fromB64(id.pub.dsaPk), st);
  S.recoveryMode.value = { mode: mode || HOLDER_ONLY, version: st.version, epoch: st.epoch ?? 1, escrow: st.escrow || [], trusted: !!mode };
  return S.recoveryMode.value;
}

export const isHolderOnly = () => S.recoveryMode.value?.mode === HOLDER_ONLY;
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
    await withStepUp("setRecoveryMode", [], "mode", "Make new recovery pieces", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Retiring your old recovery pieces…" });
      return R.api.setRecoveryMode(signMode(id.server.id, keys.dsaSk, HARDENED, (cur.version || 0) + 1, (cur.epoch || 1) + 1), proof);
    });
    toast("Old recovery pieces retired. Set up your proofs again: they all start fresh.", "warn");
    await loadRecoveryMode();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/** Holder-only → hardened: one fresh live check signs the new statement and sends it. */
export async function switchToHardened() {
  const id = S.identity.value, cur = S.recoveryMode.value;
  if (!cur || cur.mode === HARDENED) return true;
  try {
    await withStepUp("setRecoveryMode", [], "mode", "Turn on recovery", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Signing your choice with your account key…" });
      // A new epoch too: any recovery piece from before holder-only can never count again.
      return R.api.setRecoveryMode(signMode(id.server.id, keys.dsaSk, HARDENED, (cur.version || 0) + 1, (cur.epoch || 1) + 1), proof);
    });
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
  if (!cur || cur.mode === HOLDER_ONLY) return true;
  for (const kind of ["card", "contacts", "anchor", "key"]) {
    if (!cur.escrow?.includes(kind)) continue;
    const [op, label, call] = REMOVE[kind];
    try { await withStepUp(op, [], "remove", label, async ({ proof }) => call(proof)); }
    catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); await loadRecoveryMode(); return false; } // nothing switched
  }
  cur = await loadRecoveryMode();
  if (cur.escrow?.length) { toast(`Still on your vault: your ${escrowWords(cur.escrow).join(", ")}. Remove ${cur.escrow.length > 1 ? "them" : "it"} first.`, "warn"); return false; }
  try {
    await withStepUp("setRecoveryMode", [], "mode", "Only my devices", async ({ keys, proof }) => {
      showInterrupt({ progress: 0.6, message: "Signing your choice with your account key…" });
      return R.api.setRecoveryMode(signMode(id.server.id, keys.dsaSk, HOLDER_ONLY, (cur.version || 0) + 1, (cur.epoch || 1) + 1), proof);
    });
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
