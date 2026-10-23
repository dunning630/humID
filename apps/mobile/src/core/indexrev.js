// Index revs (CRYPTO-05): every encrypted index entry names its item and carries a rev
// that only grows. This device remembers the highest rev it has seen for each item, so a
// vault can't serve an older entry back: a decoy flag the holder turned off, an old name
// or pin. The memory is sealed on the device under the index key (@humid/crypto
// sealIndexRevs) and opens only while the vault is unlocked.
import { suite } from "@humid/crypto";
import * as S from "./state.js";
import { R } from "./runtime.js";

let cache = null; // { epoch, account, revs: Map(id → rev) } for this unlock only
let writing = Promise.resolve();

/** This unlock's map of item id → highest rev seen. Empty if nothing was saved yet. */
export async function knownRevs() {
  const account = S.identity.value?.server?.id || null;
  if (cache && cache.epoch === R.epoch && cache.account === account) return cache.revs;
  const revs = new Map();
  try {
    const rec = await R.store?.getIndexRevs?.();
    if (rec && rec.account === account && R.indexKey) {
      const obj = await suite(S.identity.value?.suite).openIndexRevs(R.indexKey, rec.blob);
      for (const [id, rev] of Object.entries(obj?.revs || {})) if (Number.isSafeInteger(rev) && rev > 0) revs.set(id, rev);
    }
  } catch { /* unreadable: start again from what the vault shows now */ }
  cache = { epoch: R.epoch, account, revs };
  return revs;
}

/** The rev for a new version of this item's entry: later than now and than anything seen. */
export async function nextRev(item) {
  const seen = (await knownRevs()).get(item.id) || 0;
  return Math.max(Date.now(), (item.rev || 0) + 1, seen + 1);
}

/** Remember revs this device has seen or written ([id, rev] pairs); saved, sealed, on the device. */
export async function noteRevs(pairs) {
  const revs = await knownRevs();
  let changed = false;
  for (const [id, rev] of pairs) if (rev > (revs.get(id) || 0)) { revs.set(id, rev); changed = true; }
  if (!changed || !R.indexKey || !R.store?.putIndexRevs) return;
  const account = cache.account, key = R.indexKey.slice(), snapshot = Object.fromEntries(revs);
  writing = writing.then(async () => {
    try { await R.store.putIndexRevs(await suite(S.identity.value?.suite).sealIndexRevs(key, { revs: snapshot }), account); }
    catch { /* best effort: kept in memory for this unlock */ }
    finally { key.fill(0); }
  });
  await writing;
}
