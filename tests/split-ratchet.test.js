// VAULT-04 / PC-13: a release build pinned to its server never seals a document unsplit,
// even on its very first run, when no honest policy hint has ever been seen.
import { test } from "node:test";
import assert from "node:assert/strict";

globalThis.__HUMID_KID__ = "ab".repeat(32); // what build.mjs defines for a pinned build
const S = await import("../apps/mobile/src/core/state.js");
const { R } = await import("../apps/mobile/src/core/runtime.js");
const { splitKeysRatchet } = await import("../apps/mobile/src/core/vault.js");

const saved = [];
R.store = { getIdentity: async () => saved.at(-1) ?? S.identity.value, putIdentity: async (r) => { saved.push(r); } };
S.identity.value = { server: { id: "hid_x" } };

test("pinned build, first run, hint stripped: nothing is sealed unsplit", async () => {
  S.server.value = { policy: { splitKeys: false } };
  await assert.rejects(splitKeysRatchet({ server: { id: "hid_x" } }), (e) => e.code === "split_keys_missing");
});

test("pinned build with the signed hint: splits, and remembers it", async () => {
  S.server.value = { policy: { splitKeys: true } };
  assert.equal(await splitKeysRatchet({ server: { id: "hid_x" } }), true);
  assert.equal(saved.at(-1).splitKeysSeen, true);
});
