// The duress setting (apps/mobile/src/core/duress.js): nothing about it is on the
// device in the clear. It's sealed under a key from the account seed, reads only
// after a live check, and the decoy-or-real decision is made after that check.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suite, random } from "@humid/crypto";
import { openStore } from "@humid/store";
import { sealDuress, openDuress, isDuress, normalize, DEFAULT } from "../apps/mobile/src/core/duress.js";

const Suite = suite();
const seed = random(64);
const key = Suite.settingsKey(seed);
const record = { mode: "hardware", server: { id: "hid_x" }, wrapped: { ct: "..." }, schema: 4 };

/** Every string reachable in a record, so a test can prove a word isn't in it. */
const strings = (v, out = []) => {
  if (typeof v === "string") out.push(v);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
};

test("the settings key is its own key, derived from the seed", () => {
  assert.equal(key.length, 32);
  assert.notDeepEqual(key, Suite.indexKey(seed));
  assert.notDeepEqual(key, Suite.offlineKey(seed));
  assert.deepEqual(key, Suite.settingsKey(seed.slice()));
});

test("a saved record holds no duress field, gesture or state in the clear", async () => {
  const saved = await sealDuress(Suite, key, record, { enabled: true, gesture: "taps" });
  assert.equal(saved.duress, undefined);
  assert.equal(typeof saved.duressSealed, "string");
  const text = JSON.stringify(saved);
  for (const word of ["gesture", "taps", "hold", "enabled", "duress\""]) assert.ok(!text.includes(word), `"${word}" is in the record`);
  // and the stored form is what the store keeps
  const store = await openStore();
  await store.putIdentity(saved);
  const back = await store.getIdentity();
  assert.equal(back.duress, undefined);
  assert.ok(!strings(back).some((s) => /gesture|taps/.test(s)));
  // two saves of the same setting don't look alike on disk
  const again = await sealDuress(Suite, key, record, { enabled: true, gesture: "taps" });
  assert.notEqual(again.duressSealed, saved.duressSealed);
});

test("the setting opens with the seed's key and nothing else; unreadable counts as off", async () => {
  const saved = await sealDuress(Suite, key, record, { enabled: true, gesture: "hold" });
  assert.deepEqual((await openDuress(Suite, key, saved)).setting, { enabled: true, gesture: "hold" });
  assert.deepEqual((await openDuress(Suite, Suite.settingsKey(random(64)), saved)).setting, { ...DEFAULT });
  assert.deepEqual((await openDuress(Suite, Suite.offlineKey(seed), saved)).setting, { ...DEFAULT }, "the offline key can't open it");
  assert.deepEqual((await openDuress(Suite, null, saved)).setting, { ...DEFAULT }, "no key (locked): off");
  assert.deepEqual((await openDuress(Suite, key, record)).setting, { ...DEFAULT }, "never set: off");
  const tampered = { ...saved, duressSealed: saved.duressSealed.slice(0, -4) + "AAAA" };
  assert.deepEqual((await openDuress(Suite, key, tampered)).setting, { ...DEFAULT });
  await assert.rejects(sealDuress(Suite, null, record, { enabled: true }), "can't save while locked");
});

test("a plaintext setting from an earlier release is sealed on first open and the plaintext dropped", async () => {
  const old = { ...record, duress: { enabled: true, gesture: "taps" } };
  const { setting, record: next } = await openDuress(Suite, key, old);
  assert.deepEqual(setting, { enabled: true, gesture: "taps" });
  assert.ok(next, "the record is rewritten");
  assert.equal(next.duress, undefined);
  assert.ok(!JSON.stringify(next).includes("taps"));
  assert.deepEqual((await openDuress(Suite, key, next)).setting, { enabled: true, gesture: "taps" });
  assert.equal((await openDuress(Suite, key, next)).record, null, "a sealed record isn't rewritten again");
});

test("decoy-or-real is decided from the opened setting and the gesture that was used", () => {
  const taps = { enabled: true, gesture: "taps" }, hold = { enabled: true, gesture: "hold" };
  assert.equal(isDuress(taps, "taps"), true);
  assert.equal(isDuress(taps, "hold"), false, "the other gesture is an ordinary unlock");
  assert.equal(isDuress(hold, "hold"), true);
  assert.equal(isDuress(hold, "taps"), false);
  assert.equal(isDuress(taps, false), false);
  assert.equal(isDuress(taps, true), true, "a decoy session reconnecting stays a decoy session");
  assert.equal(isDuress({ enabled: false, gesture: "taps" }, "taps"), false, "off: no gesture means duress");
  assert.equal(isDuress(null, "hold"), false);
  assert.equal(isDuress(undefined, true), false);
  assert.deepEqual(normalize({ enabled: 1, gesture: "wink" }), { enabled: true, gesture: "hold" });
});

test("a sealed setting that won't open fails toward duress when a duress gesture was used", async () => {
  const saved = await sealDuress(Suite, key, record, { enabled: true, gesture: "taps" });
  const tampered = { ...saved, duressSealed: saved.duressSealed.slice(0, -4) + "AAAA" };
  const r = await openDuress(Suite, key, tampered);
  assert.equal(r.unreadable, true);
  assert.equal(isDuress(r.setting, "hold", r), true, "either gesture counts: which one was set can't be read");
  assert.equal(isDuress(r.setting, "taps", r), true);
  assert.equal(isDuress(r.setting, false, r), false, "a plain unlock stays a plain unlock");
  // what opens, or was never set, is not "unreadable"
  assert.equal((await openDuress(Suite, key, saved)).unreadable, undefined);
  assert.equal((await openDuress(Suite, key, record)).unreadable, undefined);
  assert.equal(isDuress({ enabled: false }, "hold", { unreadable: false }), false);
});
