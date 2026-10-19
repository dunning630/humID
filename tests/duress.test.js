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
  assert.deepEqual(normalize({ enabled: 1, gesture: "wink" }), { enabled: true, gesture: "taps" }, "3.0: the default gesture is the triple tap (a long hold triggers by accident)");
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
  assert.equal((await openDuress(Suite, key, record)).unreadable, false, "never sealed on this device: not tampering");
  assert.equal(isDuress({ enabled: false }, "hold", { unreadable: false }), false);
});

test("3.0: a record that was sealed once and lost its setting reads as tampered; sizes say nothing", async () => {
  // the first open of a record without a setting seals "off" into it, with a marker
  const first = await openDuress(Suite, key, record);
  assert.equal(first.unreadable, false);
  assert.equal(typeof first.record.duressSealed, "string");
  assert.equal(typeof first.record.duressSealedAt, "string");
  // delete the sealed setting from that record: duress can't be silently turned off that way
  const stripped = { ...first.record }; delete stripped.duressSealed;
  const r = await openDuress(Suite, key, stripped);
  assert.equal(r.unreadable, true, "a missing setting on a device that sealed one is tampering");
  assert.equal(isDuress(r.setting, "taps", r), true);
  // on and off, hold and taps: the same ciphertext length
  const sizes = new Set();
  for (const enabled of [true, false]) for (const gesture of ["hold", "taps"]) sizes.add((await sealDuress(Suite, key, record, { enabled, gesture })).duressSealed.length);
  assert.equal(sizes.size, 1, `sealed sizes differ: ${[...sizes].join(", ")}`);
});
