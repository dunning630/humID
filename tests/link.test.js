// The connection monitor (apps/mobile/src/core/link.js): notices a drop, retries with
// backoff forever while the app is on screen, and recovers once — with a fake clock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createLink, backoff, BACKOFF_MS, SLOW_CHECK_MS, isNetworkFailure } from "../apps/mobile/src/core/link.js";

function rig({ serverUp = true } = {}) {
  let t = 0;
  const timers = new Map();
  let id = 0;
  const r = {
    serverUp, probes: 0, ups: [], states: [],
    now: () => t,
    pending: () => [...timers.values()].sort((a, b) => a.at - b.at),
    /** Advance the clock to the next timer and run it (and any probe it starts). */
    async tick() {
      const [next] = r.pending();
      if (!next) return false;
      t = next.at; timers.delete(next.id); await next.fn(); await new Promise((res) => setImmediate(res));
      return true;
    },
  };
  r.link = createLink({
    probe: async () => { r.probes++; if (!r.serverUp) throw new TypeError("Failed to fetch"); },
    onChange: (s) => r.states.push(s), onUp: (i) => r.ups.push(i),
    now: r.now, random: () => 0.5, // no jitter
    setTimer: (fn, ms) => { const k = ++id; timers.set(k, { id: k, fn, at: t + ms }); return k; },
    clearTimer: (k) => timers.delete(k),
  });
  return r;
}

test("backoff doubles from 1 s and stays at 30 s, with ±20% jitter", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 50].map((a) => backoff(a, () => 0.5)), [1000, 2000, 4000, 8000, 15000, 30000, 30000, 30000]);
  for (let i = 0; i < 200; i++) { const d = backoff(3); assert.ok(d >= 6400 && d <= 9600); }
});

test("a failed request starts retries that never give up, and one success ends them", async () => {
  const r = rig({ serverUp: false });
  r.link.down("unreachable");
  assert.equal(r.link.state.state, "down");
  const delays = [];
  let last = 0;
  for (let i = 0; i < 9; i++) { await r.tick(); delays.push(r.now() - last); last = r.now(); }
  assert.deepEqual(delays, [...BACKOFF_MS, 30000, 30000, 30000], "1 2 4 8 15 30 30 30 s…");
  assert.equal(r.probes, 9);
  assert.equal(r.link.state.attempt, 9);
  assert.equal(r.ups.length, 0);
  r.serverUp = true;
  await r.tick();
  assert.equal(r.link.state.state, "up");
  assert.equal(r.ups.length, 1, "recovered once");
  assert.equal(r.ups[0].downFor, r.now());
  // healthy again: nothing scheduled, nothing sent
  assert.equal(r.pending().length, 0);
});

test("while the connection is fine, nothing is ever sent just to check", async () => {
  const r = rig();
  r.link.up(); r.link.up();
  r.link.visible(false); r.link.visible(true);
  r.link.online(true);
  await new Promise((res) => setImmediate(res));
  assert.equal(r.pending().length, 0, "no timers");
  // online(true) checks once in case it was down; that's the only probe, and only on that event
  assert.ok(r.probes <= 1);
  assert.equal(r.states.length, 0, "no churn while up");
});

test("a failed request is what notices a drop; the first retry follows after 1 s", () => {
  const r = rig({ serverUp: false });
  r.link.down("unreachable");
  assert.equal(r.link.state.state, "down");
  assert.equal(r.pending()[0].at - r.now(), 1000);
});

test("off the screen it pauses; back on the screen it tries at once", async () => {
  const r = rig({ serverUp: false });
  r.link.down();
  r.link.visible(false);
  assert.equal(r.pending().length, 0, "nothing scheduled while hidden");
  r.serverUp = true;
  r.link.visible(true);
  await new Promise((res) => setImmediate(res));
  assert.equal(r.link.state.state, "up");
  assert.equal(r.ups.length, 1);
});

test("no network: waits for the online event instead of hammering, then checks at once", async () => {
  const r = rig({ serverUp: false });
  r.link.online(false);
  assert.equal(r.link.state.reason, "offline");
  assert.equal(r.pending()[0].at - r.now(), SLOW_CHECK_MS, "a slow check only");
  r.serverUp = true;
  r.link.online(true);
  await new Promise((res) => setImmediate(res));
  assert.equal(r.link.state.state, "up");
});

test("Reconnect now skips the wait; repeated failures while down don't reset the count", async () => {
  const r = rig({ serverUp: false });
  r.link.down();
  await r.tick(); await r.tick();
  assert.equal(r.link.state.attempt, 2);
  r.link.down("unreachable"); // another request failed meanwhile
  assert.equal(r.link.state.attempt, 2);
  r.serverUp = true;
  r.link.retryNow();
  await new Promise((res) => setImmediate(res));
  assert.equal(r.link.state.state, "up");
});

test("what counts as the server not answering", () => {
  assert.ok(isNetworkFailure(new TypeError("Failed to fetch")));
  assert.ok(isNetworkFailure({ code: "server_unreachable" }));
  assert.ok(!isNetworkFailure({ code: "sign_in_required", status: 401 }));
  assert.ok(!isNetworkFailure(new Error("nope")));
});
