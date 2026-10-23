// Activity: the account's hash-chained ledger, verified on this phone, and its place
// in the public log.
import * as S from "./state.js";
import { R, epoch, stale } from "./runtime.js";
import { toast, friendly, SESSION_LOST } from "./notify.js";
import { isNetworkFailure } from "./link.js";
import { keepOffline } from "./session.js";
import { parseCosigners } from "@humid/api";
import { TLOG_COSIGNERS, LEDGER_KEY_FP } from "./config.js";

/** Cosigners of the public log this build trusts. The server's own list is never used (PC-04). */
const COSIGNERS = parseCosigners(TLOG_COSIGNERS);

/**
 * The ledger key this device trusts: built into a release build (HUMID_LEDGER_KEY_FP), so a
 * new install never has to take the server's word for it; otherwise the one it saw first.
 */
const trustedLedgerKey = () => LEDGER_KEY_FP || S.identity.value?.ledgerKeyFp || undefined;

/** The head of the page Activity shows, as this phone verified it: the public log must hold exactly this entry. */
let shownHead = null;

/**
 * The ledger's signing key, pinned on this device the first time it verifies (PC-04).
 * Without the pin a server could present a made-up history under a fresh key of its own;
 * with it, a changed key fails verification and Activity reports it.
 */
async function rememberLedgerKey(fp) {
  const id = S.identity.value;
  if (!fp || !id || id.ledgerKeyFp) return;
  const record = { ...id, ledgerKeyFp: fp };
  delete record.schema;
  await R.store.putIdentity(record);
  S.identity.value = { ...record, schema: id.schema ?? 4 };
}

/** In a decoy session, Activity shows only what a calm account with these documents would show. */
const DECOY_TYPES = new Set(["identity.created", "session.opened", "session.closed", "device.added", "device.removed", "object.sealed", "object.opened", "object.updated", "object.deleted"]);
function decoyView(l) {
  const ids = new Set(S.items.value.map((i) => i.id));
  const entries = l.entries.filter((e) => DECOY_TYPES.has(e.type) && (!e.type.startsWith("object.") || ids.has(e.detail?.id)));
  return { ...l, entries };
}

export async function loadLedger() {
  S.ledgerLoading.value = true;
  const ep = epoch();
  try {
    // previousHead: the page must still hold the head this phone verified last time (CRYPTO-01).
    const l = S.offline.value ? (R.offline?.ledger || { ok: true, reason: "Empty", entries: [] }) : await R.api.ledger({ limit: 300, trustedKeyFp: trustedLedgerKey(), previousHead: S.identity.value?.ledgerHead || undefined });
    if (stale(ep)) return;
    shownHead = !S.offline.value && l.ok && l.head ? { seq: l.head.seq, hash: l.head.hash } : null;
    if (!S.offline.value && l.ok) await rememberLedgerKey(l.keyFp);
    keepOffline({ ledger: l });
    for (const it of S.items.value) R.knownNames.set(it.id, it.name);
    S.ledger.value = { ...(S.decoy.value && l.ok ? decoyView(l) : l), names: new Map(R.knownNames), checkedAt: Date.now() };
    checkContinuity();
  } catch (e) { toast(friendly(e), "error"); }
  finally { S.ledgerLoading.value = false; }
}

/**
 * The public transparency log: prove the entry at the head of the page Activity shows is
 * in it, the same seq and the same hash (CRYPTO-01), and that the log extends the one this
 * device saw last time. A history that doesn't match the log is a loud failure: the page
 * stops counting as verified. The checkpoint and that head are remembered on success.
 */
export async function checkContinuity() {
  const id = S.identity.value;
  if (S.offline.value) { S.continuity.value = { ok: false, pending: true, reason: "Checked when you're back online" }; return; }
  const head = shownHead;
  try {
    const r = await R.api.continuity({ previous: id?.tlog || null, trustedKeyFp: trustedLedgerKey(), cosigners: COSIGNERS, head: head || undefined });
    if (r.mismatch) {
      if (S.ledger.value) S.ledger.value = { ...S.ledger.value, ok: false, reason: r.reason };
      keepOffline({ ledger: { ok: false, reason: r.reason, entries: [] } }); // never "Verified when last online"
    }
    S.continuity.value = r;
    if (r.ok && (!id.tlog || r.size >= id.tlog.size)) {
      const record = { ...id, ledgerKeyFp: id.ledgerKeyFp || r.keyFp, tlog: { size: r.size, root: r.root, at: r.at }, ...(head && r.seq === head.seq && r.hash === head.hash ? { ledgerHead: head } : {}) };
      delete record.schema;
      await R.store.putIdentity(record);
      S.identity.value = { ...record, schema: id.schema ?? 4 };
    }
  } catch (e) {
    // Not reaching the server is not evidence of tampering: check again once it's back.
    if (isNetworkFailure(e) || SESSION_LOST.has(e?.code)) { S.continuity.value = { ok: false, pending: true, reason: "Checked when your vault is reachable" }; return; }
    S.continuity.value = { ok: false, reason: e?.code === "not_in_log" ? "Not published yet" : friendly(e), pending: e?.code === "not_in_log" };
  }
}
