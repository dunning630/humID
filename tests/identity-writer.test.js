// The identity record has one writer (apps/mobile/src/core/identity.js updateIdentity), so
// writes that interleave can't undo each other (APP-11). The case that mattered: Activity's
// public-log check captured the record, waited for the network, then wrote the old record
// back with its checkpoint, after the holder had turned duress on: the next forced unlock
// was a normal one.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { suite, random } from "@humid/crypto";
import * as S from "../apps/mobile/src/core/state.js";
import { R } from "../apps/mobile/src/core/runtime.js";
import { updateIdentity } from "../apps/mobile/src/core/identity.js";
import { checkContinuity } from "../apps/mobile/src/core/ledger.js";
import { saveDuress } from "../apps/mobile/src/core/safety.js";
import { openDuress } from "../apps/mobile/src/core/duress.js";

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
/** A store like @humid/store's, with a delay on every read and write so they interleave. */
function slowStore(initial, ms = 5) {
  let rec = structuredClone(initial);
  return {
    writes: 0,
    async getIdentity() { await tick(ms); return rec ? structuredClone(rec) : null; },
    async putIdentity(r) { await tick(ms); this.writes++; rec = { ...structuredClone(r), schema: 4 }; },
    peek: () => rec,
  };
}
const Suite = suite();
const seed = random(64);
const base = { mode: "hardware", suite: Suite.id, server: { id: "hid_x" }, schema: 4 };

beforeEach(() => { S.resetSession(); S.identity.value = structuredClone(base); R.settingsKey = Suite.settingsKey(seed); });

test("writes run one at a time, each on the newest record", async () => {
  R.store = slowStore(base);
  const order = [];
  const a = updateIdentity(async (r) => { order.push("a start"); await tick(20); r.a = 1; order.push("a end"); });
  const b = updateIdentity((r) => { order.push("b"); r.b = r.a + 1; });
  const c = updateIdentity((r) => { r.c = true; });
  await Promise.all([a, b, c]);
  assert.deepEqual(order, ["a start", "a end", "b"], "b waited for a");
  const rec = R.store.peek();
  assert.equal(rec.a, 1); assert.equal(rec.b, 2); assert.equal(rec.c, true);
  assert.deepEqual({ a: S.identity.value.a, b: S.identity.value.b, c: S.identity.value.c }, { a: 1, b: 2, c: true }, "S.identity follows");
});

test("null writes nothing; a failed write doesn't block the next", async () => {
  R.store = slowStore(base);
  await updateIdentity(() => null);
  assert.equal(R.store.writes, 0);
  await assert.rejects(updateIdentity(() => { throw new Error("boom"); }), /boom/);
  await updateIdentity((r) => { r.after = true; });
  assert.equal(R.store.peek().after, true);
});

test("APP-11: duress turned on during the public-log check stays on", async () => {
  R.store = slowStore(base);
  let answer;
  R.api = { continuity: () => new Promise((r) => { answer = r; }) };
  S.offline.value = null;
  const check = checkContinuity();              // captures the record, waits for the network
  await tick(1);
  assert.ok(await saveDuress({ enabled: true, gesture: "taps" }), "duress saved");
  answer({ ok: true, size: 7, root: "r", at: "2026-10-22", keyFp: "fp" });
  await check;
  const rec = R.store.peek();
  assert.ok(rec.duressSealed, "the sealed duress setting is still in the record");
  const { setting } = await openDuress(Suite, R.settingsKey, rec);
  assert.deepEqual(setting, { enabled: true, gesture: "taps" });
  assert.deepEqual(rec.tlog, { size: 7, root: "r", at: "2026-10-22" }, "and the checkpoint was written too");
});

test("every identity write in core/ goes through identity.js", () => {
  for (const f of ["ledger.js", "safety.js", "vault.js", "join.js", "enroll.js", "account.js"]) {
    const s = readFileSync(new URL(`../apps/mobile/src/core/${f}`, import.meta.url), "utf8");
    assert.doesNotMatch(s, /R\.store\.(putIdentity|clearIdentity)\(/, `${f} writes the record itself`);
    assert.match(s, /(updateIdentity|createIdentity|clearIdentity)\(/, `${f} uses identity.js`);
  }
});

test("a write after the record was erased writes nothing, and doesn't bring it back (verify-71 #5)", async () => {
  const { clearIdentity } = await import("../apps/mobile/src/core/identity.js");
  R.store = slowStore(base);
  R.store.clearIdentity = async function () { await tick(5); this.cleared = true; };
  const realPeek = R.store.peek;
  let gone = false;
  const get = R.store.getIdentity.bind(R.store);
  R.store.getIdentity = async () => (gone ? null : get());
  // eraseEverything: the store is cleared while S.identity still holds the record
  gone = true;
  const out = await updateIdentity((cur) => { cur.tlog = { size: 9 }; });
  assert.equal(out, null);
  assert.equal(R.store.writes, 0, "no write");
  // and a clear queued after a write runs after it
  gone = false;
  const w = updateIdentity(async (cur) => { await tick(15); cur.late = true; });
  const c = clearIdentity();
  await Promise.all([w, c]);
  assert.equal(realPeek().late, true, "the write ran first");
  assert.ok(R.store.cleared, "then the clear");
});

test("createIdentity writes a new record and publishes it", async () => {
  const { createIdentity } = await import("../apps/mobile/src/core/identity.js");
  R.store = slowStore(null);
  S.identity.value = null;
  const shown = await createIdentity({ ...base, fresh: true });
  assert.equal(R.store.peek().fresh, true);
  assert.equal(S.identity.value.fresh, true);
  assert.equal(shown.schema, 4);
});
