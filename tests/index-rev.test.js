// CRYPTO-05: an encrypted index entry is bound to its item and to a rev that only grows,
// and the phone remembers the highest rev it has seen, so a vault can't serve an older
// entry back (a decoy flag the holder turned off, an old name) or move one entry onto
// another item.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suite, random } from "@humid/crypto";
import { openStore } from "@humid/store";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { refresh, setDecoy } from "../apps/mobile/src/core/vault.js";

const Suite = suite();
const key = Suite.indexKey(random(64));
const b64 = (b) => Buffer.from(b).toString("base64url");

test("a v2 entry opens only as its own item's, and says which rev it is", async () => {
  const blob = await Suite.sealIndex(key, { name: "passport.jpg", decoy: true }, { id: "item-a", rev: 7 });
  assert.deepEqual(await Suite.openIndex(key, blob, { id: "item-a" }), { name: "passport.jpg", decoy: true, rev: 7 });
  await assert.rejects(Suite.openIndex(key, blob, { id: "item-b" }), "moved onto another item: doesn't open");
  // entries from before 1.6.0 still open, as rev 0, whatever they say inside
  const v1 = await Suite.sealIndex(key, { name: "old.pdf", rev: 99 });
  assert.equal((await Suite.openIndex(key, v1, { id: "item-a" })).rev, 0);
  assert.equal((await Suite.openIndex(key, v1)).name, "old.pdf");
});

test("the phone refuses an entry older than one it has seen: a removed decoy flag can't come back", async () => {
  const id = "3f1c2b9a-1d2e-4f00-8a00-0123456789ab";
  let served;
  const patched = [];
  R.api = { list: async () => ({ items: [{ id, size: 100, index: served }], usage: { count: 1, bytes: 100 } }), rename: async (i, blob) => { patched.push(blob); served = b64(blob); } };
  R.store = await openStore(); // in memory here
  R.indexKey = key;
  S.identity.value = { server: { id: "hid_x" }, schema: 4 };
  S.offline.value = null; S.decoy.value = false;

  // The holder had it in the decoy view…
  const before = await Suite.sealIndex(key, { name: "passport.jpg", type: "image/jpeg", decoy: true }, { id, rev: 1000 });
  served = b64(before);
  await refresh();
  assert.equal(S.items.value[0].decoy, true);
  // …and hides it (as setDecoy does: a newer rev).
  const after = await Suite.sealIndex(key, { name: "passport.jpg", type: "image/jpeg" }, { id, rev: 2000 });
  served = b64(after);
  await refresh();
  assert.equal(S.items.value[0].decoy, undefined);

  // The vault serves the old entry again (the PoC): it opens, but it's older than this phone has seen.
  served = b64(before);
  await refresh();
  const it = S.items.value[0];
  assert.equal(it.rolledBack, true);
  assert.notEqual(it.decoy, true, "the stale decoy flag isn't believed");
  assert.equal(it.name, "Changed on the server");
  // and nothing is re-sealed from what the stale entry said
  await setDecoy(it, true);
  assert.equal(patched.length, 0);
  // The memory outlives this unlock: it's sealed on the device, and opens at the next one.
  R.epoch++;
  assert.ok(await R.store.getIndexRevs(), "saved on the device");
  await refresh();
  assert.equal(S.items.value[0].rolledBack, true);
});

test("round 2: an entry from before v2 is re-sealed as v2 on the next refresh, so it can't be rolled back after that", async () => {
  const id = "7a1c2b9a-1d2e-4f00-8a00-0123456789cd";
  let served;
  const patched = [];
  R.api = { list: async () => ({ items: [{ id, size: 100, index: served }], usage: { count: 1, bytes: 100 } }), rename: async (i, blob) => { patched.push([i, blob]); served = b64(blob); } };
  R.store = await openStore();
  R.indexKey = key;
  R.epoch++;
  S.identity.value = { server: { id: "hid_y" }, schema: 4 };
  S.offline.value = null; S.decoy.value = false;

  // A v1 entry, as every release before 4.1 sealed it, with the decoy flag on.
  const oldV1 = await Suite.sealIndex(key, { name: "deed.pdf", type: "application/pdf", decoy: true });
  served = b64(oldV1);
  await refresh();
  assert.equal(patched.length, 1, "re-sealed once");
  const [pid, blob] = patched[0];
  assert.equal(pid, id);
  const up = await Suite.openIndex(key, blob, { id });
  assert.ok(up.rev > 0, "now v2, with a rev");
  assert.equal(up.decoy, true, "otherwise unchanged");
  assert.equal(up.name, "deed.pdf");
  await assert.rejects(Suite.openIndex(key, blob, { id: "another-item" }), "and bound to its item");

  // Serving the old v1 entry back is now caught like any older entry.
  served = b64(oldV1);
  await refresh();
  assert.equal(S.items.value[0].rolledBack, true);
  assert.equal(patched.length, 1, "a stale entry is never re-sealed");

  // A decoy session writes nothing.
  const other = "8b1c2b9a-1d2e-4f00-8a00-0123456789ef";
  R.api.list = async () => ({ items: [{ id: other, size: 1, index: b64(await Suite.sealIndex(key, { name: "x", decoy: true })) }], usage: {} });
  S.decoy.value = true;
  await refresh();
  assert.equal(patched.length, 1);
  S.decoy.value = false;
});
