// The duress gestures (apps/mobile/src/core/gesture.js): one recognizer for the Lock screen
// and Duress Practice, so a rhythm Practice calls "the decoy view" is the one the Lock
// screen treats as duress (APP-01), and the Lock screen never acts before the window closes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createTapCounter, createHoldTimer, isDuressHold, describeTaps, TAP_WINDOW_MS, DURESS_HOLD_MS } from "../apps/mobile/src/core/gesture.js";

/** A fake clock with timers, so taps can be placed at exact times. */
function clock() {
  let t = 0;
  const timers = new Map();
  let next = 1;
  return {
    now: () => t,
    setTimer: (fn, ms) => { const id = next++; timers.set(id, { fn, at: t + ms }); return id; },
    clearTimer: (id) => { timers.delete(id); },
    advance(ms) {
      const end = t + ms;
      for (;;) {
        const due = [...timers].filter(([, x]) => x.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]); t = due[1].at; due[1].fn();
      }
      t = end;
    },
  };
}

/** Tap at these gaps (ms between taps), then let the window close. Returns what onDone heard. */
function run(gaps) {
  const c = clock();
  const done = [];
  const k = createTapCounter({ onDone: (r) => done.push(r), now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer });
  k.tap();
  for (const g of gaps) {
    c.advance(g);
    assert.equal(done.length, 0, "nothing is decided while taps are still coming");
    k.tap();
  }
  c.advance(TAP_WINDOW_MS - 1);
  assert.equal(done.length, 0, "nothing is decided before the window after the last tap closes");
  c.advance(1);
  return done;
}

test("three taps 500 ms apart are the duress gesture (the rhythm that opened the real vault before)", () => {
  const [r] = run([500, 500]);
  assert.equal(r.count, 3);
  assert.deepEqual(r.gaps, [500, 500]);
  assert.equal(r.duress, true);
});

test("every gap up to the window counts; one gap over it splits the sequence", () => {
  assert.equal(run([TAP_WINDOW_MS - 1, TAP_WINDOW_MS - 1])[0].duress, true);
  const c = clock();
  const done = [];
  const k = createTapCounter({ onDone: (r) => done.push(r), now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer });
  k.tap(); c.advance(300); k.tap(); c.advance(TAP_WINDOW_MS + 1); k.tap(); c.advance(TAP_WINDOW_MS);
  assert.deepEqual(done.map((d) => d.count), [2, 1], "two taps, then a separate single tap");
  assert.ok(done.every((d) => !d.duress));
});

test("one tap is a normal unlock, reported once, only after the window", () => {
  const done = run([]);
  assert.equal(done.length, 1);
  assert.deepEqual(done[0], { count: 1, gaps: [], duress: false });
});

test("cancel forgets a sequence in progress", () => {
  const c = clock();
  const done = [];
  const k = createTapCounter({ onDone: (r) => done.push(r), now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer });
  k.tap(); k.tap(); k.cancel(); c.advance(5000);
  assert.equal(done.length, 0);
});

test("the hold gesture: held for the full time or longer", () => {
  let t = 0;
  const h = createHoldTimer({ now: () => t });
  assert.equal(h.up(), null, "no press, no result");
  h.down(); t += DURESS_HOLD_MS - 1;
  assert.equal(isDuressHold(h.up()), false);
  h.down(); t += DURESS_HOLD_MS;
  assert.equal(isDuressHold(h.up()), true);
  h.down(); h.cancel();
  assert.equal(h.up(), null);
});

test("Practice reports the measured gaps", () => {
  assert.match(describeTaps({ count: 3, gaps: [500, 520], duress: true }), /decoy view.*0\.5 s, 0\.5 s apart/);
  assert.match(describeTaps({ count: 3, gaps: [600, 610], duress: true }), /close to the limit/);
  assert.match(describeTaps({ count: 2, gaps: [400], duress: false }), /normal unlock: 2 taps\. Your taps were 0\.4 s apart\./);
});

test("the Lock screen and Practice both use the shared recognizer, with no tap window of their own", () => {
  const src = (f) => readFileSync(new URL(`../apps/mobile/src/${f}`, import.meta.url), "utf8");
  for (const f of ["screens/lock.jsx", "screens/you/duress.jsx"]) {
    const s = src(f);
    assert.match(s, /createTapCounter\(/, `${f} uses createTapCounter`);
    assert.match(s, /isDuressHold\(/, `${f} uses isDuressHold`);
    assert.doesNotMatch(s, /setTimeout\([^)]*,\s*(?:st\.n === 1 \? )?\d{3}\b/, `${f} has no tap timer of its own`);
  }
});
