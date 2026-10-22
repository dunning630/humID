// "Stamp where it's sealed" (apps/mobile/src/core/place.js): the phone's location at the
// moment of sealing, kept in the document's encrypted index. A fake geolocation stands
// in for the phone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { watchPlace, stampFrom, validStamp, formatCoords, formatAccuracy } from "../apps/mobile/src/core/place.js";

/** A fake navigator.geolocation: push(fix) or fail(code) whenever the test wants. */
function fakeGeo() {
  let ok = null, bad = null, cleared = false;
  return {
    watchPosition(a, b) { ok = a; bad = b; return 7; },
    clearWatch(id) { assert.equal(id, 7); cleared = true; },
    push: (lat, lon, accuracy, t = Date.now()) => ok({ coords: { latitude: lat, longitude: lon, accuracy, altitude: null }, timestamp: t }),
    fail: (code) => bad({ code }),
    get cleared() { return cleared; },
  };
}

test("a stamp: rounded coordinates, accuracy, the fix's time", () => {
  const s = stampFrom({ coords: { latitude: 41.912345678, longitude: -88.311234567, accuracy: 12.4, altitude: 221.7 }, timestamp: Date.UTC(2026, 9, 16, 21, 30) });
  assert.deepEqual(s, { lat: 41.912346, lon: -88.311235, accuracy: 12, at: "2026-10-16T21:30:00.000Z", altitude: 222 });
  assert.ok(validStamp(s));
  assert.equal(formatCoords(s), "41.91235° N, 88.31123° W");
  // a coarse 3.0 stamp (about 110 m) shows only the digits it holds
  assert.equal(formatCoords({ lat: 41.915, lon: -88.309, accuracy: 110 }), "41.915° N, 88.309° W");
  assert.equal(formatAccuracy(12), "within 12 m");
  assert.equal(formatAccuracy(1400), "within 1.4 km");
  for (const bad of [null, {}, { ...s, lat: 91 }, { ...s, lon: "x" }, { ...s, accuracy: 0 }, { ...s, at: "not a date" }]) assert.equal(validStamp(bad), false);
});

test("seal right away: waits for the first fix, then uses the most accurate recent one", async () => {
  const geo = fakeGeo();
  const w = watchPlace({ geo });
  const taking = w.take(2000);
  setTimeout(() => geo.push(41.9, -88.3, 60), 20);
  const got = await taking;
  assert.equal(got.stamp.accuracy, 60);
  geo.push(41.91, -88.31, 9);
  geo.push(41.92, -88.32, 40); // less accurate, moments later: the 9 m fix stays
  assert.equal((await w.take()).stamp.accuracy, 9);
  w.stop();
  assert.ok(geo.cleared);
});

test("location access off: says so at once, no waiting", async () => {
  const geo = fakeGeo();
  const w = watchPlace({ geo });
  geo.fail(1);
  const t = Date.now();
  assert.deepEqual(await w.take(5000), { reason: "denied" });
  assert.ok(Date.now() - t < 100);
});

test("no fix in time, a stale fix, or no location at all: sealed without one, and why", async () => {
  const geo = fakeGeo();
  let now = Date.now();
  const w = watchPlace({ geo, now: () => now });
  assert.deepEqual(await w.take(30), { reason: "timeout" });
  geo.push(41.9, -88.3, 15, now);
  now += 3 * 60 * 1000; // three minutes later: too old to say where it was sealed
  assert.deepEqual(await w.take(30), { reason: "timeout" });
  assert.deepEqual(await watchPlace({ geo: undefined }).take(), { reason: "unsupported" });
});
