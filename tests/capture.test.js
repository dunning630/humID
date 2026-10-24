// What a capture waits on, and the parts of it that can be tested without a phone:
//   - base64 ↔ bytes without the slow path (core/bytes.js)
//   - the clean scan done off the main thread (core/scanjobs.js) is the same picture as on it
//   - the timing trace exists in development builds only and records names and numbers only
//   - an early location watch (core/place.js warmPlace) hands its fix to the review's own watch
// The rest (frame grab, straightening at the capped size, the review opening before the clean
// scan, the seal) is timed in a browser: tests/bench/capture.mjs, checked by tests/browser/*.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64Bytes, bytesB64 } from "../apps/mobile/src/core/bytes.js";
import { cleanPixels, closeJobs } from "../apps/mobile/src/core/scanjobs.js";
import { cleanScan } from "../apps/mobile/src/core/scanclean.js";
import { warmPlace, stopWarmPlace, watchPlace } from "../apps/mobile/src/core/place.js";
import { confirmedByStill } from "../apps/mobile/src/core/mrzseed.js";
import { MrzConsensus } from "@humid/idscan";

test("base64 to bytes and back: every length, and the same as atob", () => {
  for (const n of [0, 1, 2, 3, 4, 5, 255, 4096, 4097, 70_001]) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + (i >> 5)) & 255);
    const text = bytesB64(bytes);
    assert.equal(text, Buffer.from(bytes).toString("base64"));
    assert.deepEqual(b64Bytes(text), bytes);
    assert.deepEqual(b64Bytes(text), Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0)));
  }
});

test("base64 decoding of a 3 MB page is fast (a plain loop, not an iterator with a callback)", () => {
  const text = Buffer.from(new Uint8Array(3_000_000).map((_, i) => i & 255)).toString("base64");
  const t0 = performance.now();
  const out = b64Bytes(text);
  const ms = performance.now() - t0;
  assert.equal(out.length, 3_000_000);
  // 10 ms here (about 400 ms the old way); generous for a busy test machine
  assert.ok(ms < 150, `decoding took ${ms.toFixed(0)} ms`);
});

/* ---------------- the clean scan, away from the main thread ---------------- */

test("the clean scan made by the jobs module is the one scanclean.js makes (no worker here: the main thread does it)", async () => {
  const W = 120, H = 160;
  const data = new Uint8ClampedArray(W * H * 4);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) { const i = (y * W + x) * 4; const v = 210 - y / 3 - ((x * 7 + y) % 5) - ((x >> 3) % 5 === 0 ? 90 : 0); data[i] = v; data[i + 1] = v; data[i + 2] = v - 6; data[i + 3] = 255; }
  const want = cleanScan({ width: W, height: H, data: new Uint8ClampedArray(data) });
  const got = await cleanPixels({ width: W, height: H, data: new Uint8ClampedArray(data) });
  assert.equal(got.width, W);
  assert.equal(got.height, H);
  assert.deepEqual([...got.data], [...want.data]);
  assert.equal(got.paper, want.paper);
  closeJobs();
});

/* ---------------- the timing trace ---------------- */

test("the trace records names and numbers in a development build and nothing in a release build", async () => {
  delete globalThis.__humidTrace;
  const off = await import("../apps/mobile/src/core/perf.js?off");
  off.mark("x"); off.span("y")(); off.timed("z", () => 1);
  assert.equal(globalThis.__humidTrace, undefined, "a release build records nothing");
  globalThis.__HUMID_ALLOW_DEMO__ = true;
  try {
    const on = await import("../apps/mobile/src/core/perf.js?on");
    on.mark("shoot");
    const end = on.span("clean"); end();
    assert.equal(await on.timed("t", async () => 7), 7);
    assert.equal(on.timed("u", () => 8), 8);
    assert.throws(() => on.timed("v", () => { throw new Error("boom"); }), /boom/);
    const names = globalThis.__humidTrace.ev.map((e) => e[0]);
    assert.deepEqual(names, ["shoot", "span:clean", "span:t", "span:u", "span:v"]);
    for (const e of globalThis.__humidTrace.ev) {
      assert.equal(typeof e[0], "string");
      assert.ok(e[2] === undefined || typeof e[2] === "number", "only a time, never a picture or text");
    }
  } finally { delete globalThis.__HUMID_ALLOW_DEMO__; delete globalThis.__humidTrace; }
});

/* ---------------- the early location watch ---------------- */

function fakeGeo() {
  let ok = null, cleared = 0;
  return {
    watchPosition(a) { ok = a; return 3; },
    clearWatch() { cleared++; },
    push: (acc, t = Date.now()) => ok({ coords: { latitude: 41.9, longitude: -88.3, accuracy: acc, altitude: null }, timestamp: t }),
    get cleared() { return cleared; },
  };
}

test("an early watch: only where location is already allowed, and the review's watch starts from its fix", async () => {
  stopWarmPlace();
  const denied = fakeGeo();
  assert.equal(await warmPlace({ geo: denied, allowed: false }), false, "never asks early");
  const geo = fakeGeo();
  assert.equal(await warmPlace({ geo, allowed: true }), true);
  assert.equal(await warmPlace({ geo, allowed: true }), true, "a second call is a no-op");
  geo.push(25);
  geo.push(60); // less accurate: the 25 m fix stays
  const w = watchPlace({ geo: fakeGeo() });
  assert.equal(geo.cleared, 1, "the review's watch takes over; the early one is let go");
  const got = await w.take(10);
  assert.equal(got.stamp.accuracy, 25, "the review starts with what the early watch heard");
  w.stop();
});

test("an early watch that heard nothing, or went stale, leaves the review to wait as before", async () => {
  stopWarmPlace();
  const geo = fakeGeo();
  await warmPlace({ geo, allowed: true });
  let now = Date.now();
  geo.push(20, now);
  now += 3 * 60 * 1000;
  const w = watchPlace({ geo: fakeGeo(), now: () => now });
  assert.deepEqual(await w.take(20), { reason: "timeout" }, "a fix from three minutes ago is no use");
  w.stop();
  stopWarmPlace();
  const w2 = watchPlace({ geo: fakeGeo() });
  assert.deepEqual(await w2.take(20), { reason: "timeout" });
  w2.stop();
});

/* ---------------- the still read after live reads ---------------- */

const NOW = new Date("2026-10-13T12:00:00Z");
const TD3 = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"];
const GOOD = `${TD3[0]}\n${TD3[1]}`;

test("a still read after a valid live reading: one agreeing pass confirms it", () => {
  const live = new MrzConsensus({ now: NOW });
  assert.equal(live.add(GOOD).stable, false, "one live reading isn't enough by itself");
  assert.ok(live.lastKey, "but it is remembered");
  const r = live.add(GOOD); // the still's own reading, same result
  assert.equal(confirmedByStill(r, true), true);
});

test("the still has to read on its own: live reads carrying the vote aren't enough", () => {
  const live = new MrzConsensus({ now: NOW });
  live.add(GOOD); live.add(GOOD); // two live readings agree (this is what would normally have fired the photo)
  const smudged = `${TD3[0]}\n${TD3[1].replace("ZE184226B", "2E1842268")}`; // the still's reading breaks a check digit
  const r = live.add(smudged);
  assert.equal(r.stable, true, "the vote still stands on the live reads");
  assert.equal(confirmedByStill(r, true), false, "…but this page didn't read as that");
  assert.equal(confirmedByStill(r, false), true, "an unseeded vote has no such check to add");
});

test("a still that reads something else is not a confirmation", () => {
  const live = new MrzConsensus({ now: NOW });
  live.add(GOOD);
  const other = `${TD3[0].replace("ERIKSSON", "ERIKSSEN")}\n${TD3[1]}`;
  const r = live.add(other);
  assert.equal(confirmedByStill(r, true), false);
});
