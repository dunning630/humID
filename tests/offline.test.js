// The offline copy (apps 1.7.0): what HumID shows when it can't reach the vault.
// It's sealed under a key only a live check can produce, holds no document or
// document key, and goes wherever this device's vault goes when it's erased.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suite, random } from "@humid/crypto";
import { openStore } from "@humid/store";

const Suite = suite();
const seed = random(64);

test("the copy has its own key, separate from the index key", () => {
  const k = Suite.offlineKey(seed);
  assert.equal(k.length, 32);
  assert.notDeepEqual(k, Suite.indexKey(seed));
  assert.deepEqual(k, Suite.offlineKey(seed.slice()), "the same seed gives the same key on every unlock");
});

test("the copy opens only with the key from the same account seed", async () => {
  const copy = { v: 1, account: "hid_x", savedAt: new Date().toISOString(), items: [{ id: "obj_1", index: "c2VhbGVk" }], devices: [{ platform: "iPhone" }] };
  const blob = await Suite.sealOffline(Suite.offlineKey(seed), copy);
  assert.deepEqual(await Suite.openOffline(Suite.offlineKey(seed), blob), copy);
  await assert.rejects(Suite.openOffline(Suite.offlineKey(random(64)), blob));
  await assert.rejects(Suite.openOffline(Suite.indexKey(seed), blob), "the index key can't open it");
  const tampered = blob.slice(); tampered[tampered.length - 1] ^= 1;
  await assert.rejects(Suite.openOffline(Suite.offlineKey(seed), tampered));
  // and nothing in it is readable as stored
  assert.ok(!Buffer.from(blob).toString("latin1").includes("iPhone"));
});

test("a sealed index entry can't be opened as an offline copy, or the reverse", async () => {
  const k = Suite.offlineKey(seed);
  const asIndex = await Suite.sealIndex(k, { name: "x" });
  await assert.rejects(Suite.openOffline(k, asIndex));
  await assert.rejects(Suite.openIndex(k, await Suite.sealOffline(k, { v: 1 })));
});

test("the store keeps one copy per device, and erasing the vault erases it", async () => {
  const store = await openStore(); // memory backend under node
  assert.equal(await store.getOffline(), null);
  await store.putOffline(new Uint8Array([1, 2, 3]), "hid_x");
  const rec = await store.getOffline();
  assert.equal(rec.account, "hid_x");
  assert.deepEqual([...rec.blob], [1, 2, 3]);
  await store.clearVault();
  assert.equal(await store.getOffline(), null);
  await store.putOffline(new Uint8Array([4]), "hid_x");
  await store.clearOffline();
  assert.equal(await store.getOffline(), null);
});
