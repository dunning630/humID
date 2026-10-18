// The time a document shows as sealed (apps/mobile/src/core/sealtime.js): the vault
// server's clock, which the holder can't set, never the phone's alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sealTime, CLOCK_GAP_MS } from "../apps/mobile/src/core/sealtime.js";

test("the server's time is the seal time; the phone's agrees and isn't shown", () => {
  const t = sealTime({ uploadedAt: "2026-10-17T21:12:05.400Z", sealedAt: "2026-10-17T21:12:03.900Z" });
  assert.equal(t.at, "2026-10-17T21:12:05.400Z");
  assert.equal(t.by, "server");
  assert.equal(t.phoneAt, null);
  assert.equal(t.gapMs, -1500);
});

test("a phone clock set back (or ahead) doesn't move the seal time; it's shown beside it", () => {
  const back = sealTime({ uploadedAt: "2026-10-17T21:12:05Z", sealedAt: "2024-01-02T09:00:00Z" });
  assert.equal(back.at, "2026-10-17T21:12:05Z", "never the phone's");
  assert.equal(back.phoneAt, "2024-01-02T09:00:00Z");
  const ahead = sealTime({ uploadedAt: "2026-10-17T21:12:05Z", sealedAt: "2026-10-17T21:20:00Z" });
  assert.equal(ahead.at, "2026-10-17T21:12:05Z");
  assert.ok(ahead.phoneAt);
  // just inside the gap the server allows: not worth a note
  const near = sealTime({ uploadedAt: "2026-10-17T21:12:05Z", sealedAt: new Date(Date.parse("2026-10-17T21:12:05Z") - CLOCK_GAP_MS + 1000).toISOString() });
  assert.equal(near.phoneAt, null);
});

test("only the phone's time known: said to be the phone's; nothing known: nothing shown", () => {
  assert.deepEqual(sealTime({ sealedAt: "2026-10-17T21:12:05Z" }), { at: "2026-10-17T21:12:05Z", by: "phone", phoneAt: null, gapMs: null });
  assert.equal(sealTime({}), null);
  assert.equal(sealTime(null), null);
  assert.equal(sealTime({ uploadedAt: "not a date", sealedAt: "also not" }), null);
  // a garbage phone time beside a real server time: the server's, no note
  assert.deepEqual(sealTime({ uploadedAt: "2026-10-17T21:12:05Z", sealedAt: "garbage" }), { at: "2026-10-17T21:12:05Z", by: "server", phoneAt: null, gapMs: null });
});
