// A relay decides how much it hands back and whether there is `more`. A hostile one must not
// be able to keep a phone fetching and storing for ever (verify-73: the MSG-04 backfill loop
// trusted `more` with no cap).
import { test } from "node:test";
import assert from "node:assert/strict";
import { BUCKETS } from "@humid/msg";
const { drainRelay } = await import("../apps/mobile/src/core/messaging.js");

const wire = () => new Uint8Array(BUCKETS[0]);

test("a relay that always says `more` is asked a bounded number of times", async () => {
  let calls = 0, kept = 0;
  const r = await drainRelay(async () => { calls++; return { got: { a: [wire(), wire()] }, more: true }; }, ["a"], async () => { kept++; });
  assert.ok(calls <= 8, `asked ${calls} times`);
  assert.equal(r.complete, false, "the backlog is left for the next poll");
  assert.equal(kept, calls * 2);
});

test("a relay that floods one page still stops the next page, and odd sizes are never stored", async () => {
  let calls = 0, kept = 0;
  const flood = Array.from({ length: 1200 }, wire);
  const r = await drainRelay(async () => { calls++; return { got: { a: [...flood, new Uint8Array(17), "x"] }, more: true }; }, ["a"], async () => { kept++; });
  assert.equal(calls, 1);
  assert.equal(kept, 1200, "a page already taken is kept whole, the junk dropped");
  assert.equal(r.complete, false);
});

test("an honest relay is drained completely", async () => {
  const pages = [{ got: { a: [wire()] }, more: true }, { got: { b: [wire()] }, more: false }];
  let kept = 0;
  const r = await drainRelay(async () => pages.shift(), ["a", "b"], async () => { kept++; });
  assert.deepEqual(r, { taken: 2, complete: true });
  assert.equal(kept, 2);
});
