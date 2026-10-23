// The rules for leaving the screen (apps/mobile/src/core/leave.js), as a table: a sequence of
// events at given times, and whether HumID ends up locked. PC-17 / APP-04 / VAULT-07: hiding
// HumID while a check was running used to leave the vault open, the document showing, when
// it came back. Only the system's biometric prompt itself is excused now.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { leave, initialLeave, PROMPT_SETTLE_MS, PICK_HIDDEN_MS, PICK_MS } from "../apps/mobile/src/core/leave.js";

/**
 * Run events in order. Each step is [atMs, type, extra?]. `app` is true unless a step sets it.
 * Timers the reducer asks for fire at their time, in order with the steps, unless `paused`
 * (a hidden page's timers can be held back by the system). Returns the times it locked at.
 */
function run(steps, { paused = false, app: appStart = true } = {}) {
  let s = initialLeave, app = appStart;
  const timers = [];
  const locks = [];
  const apply = (at, ev) => {
    const r = leave(s, { ...ev, now: at, app });
    s = r.state;
    for (const t of r.timers) timers.push({ at: at + t.ms, ev: t.event });
    if (r.action === "lock") { locks.push(at); app = false; s = leave(s, { type: "locked", now: at }).state; }
  };
  const fireTimers = (until) => {
    if (paused) return;
    for (;;) {
      timers.sort((a, b) => a.at - b.at);
      if (!timers.length || timers[0].at > until) return;
      const t = timers.shift();
      apply(t.at, t.ev);
    }
  };
  for (const [at, type, extra = {}] of steps) {
    fireTimers(at);
    if (type === "app") { app = extra.on; if (app) apply(at, { type: "opened" }); continue; }
    apply(at, { type, ...extra });
  }
  fireTimers(Infinity);
  return locks;
}

const CASES = [
  // [name, steps, locks?, options]
  ["leaving the open vault locks at once", [[0, "hide"]], true],
  ["leaving before the vault is open does nothing", [[0, "hide"], [5000, "show"]], false, { app: false }],
  ["PC-17: hidden during a check, before its prompt (the demo hold, the server's answer): locks at once", [[0, "hide"], [1400, "show"]], true],
  ["PC-17: hidden after the prompt closed, while the document is still opening: locks at once", [[0, "promptStart"], [900, "promptEnd"], [900 + PROMPT_SETTLE_MS + 1, "hide"]], true],
  ["the prompt covering HumID (some WebViews report hidden): no lock", [[0, "promptStart"], [10, "hide"], [3000, "promptEnd"], [3200, "show"]], false],
  ["the prompt's own show arrives a little after it closes: no lock", [[0, "promptStart"], [10, "hide"], [3000, "promptEnd"], [3000 + PROMPT_SETTLE_MS - 1, "show"]], false],
  ["hidden for the prompt, and still away once it closed: locks when the settle time ends", [[0, "promptStart"], [10, "hide"], [3000, "promptEnd"], [60_000, "show"]], true],
  ["same, with the page's timers paused while hidden: locks the moment it comes back", [[0, "promptStart"], [10, "hide"], [3000, "promptEnd"], [60_000, "show"]], true, { paused: true }],
  ["hidden while the prompt is closing, and away: locks", [[0, "promptStart"], [1000, "promptEnd"], [1200, "hide"], [30_000, "show"]], true],
  ["an unlock that finishes off the screen: locks as the vault opens", [[0, "app", { on: false }], [0, "promptStart"], [500, "promptEnd"], [5000, "hide"], [6000, "app", { on: true }]], true, { app: false }],
  ["an unlock that finishes on screen: no lock", [[0, "promptStart"], [500, "promptEnd"], [2000, "app", { on: true }]], false, { app: false }],
  ["pagehide locks, even mid-check", [[0, "pagehide"]], true],
  ["pagehide while the prompt is up: the prompt", [[0, "promptStart"], [10, "pagehide"]], false],
  ["a file picker HumID opened: back within the time, no lock", [[0, "pick"], [100, "hide"], [8000, "show"]], false],
  ["a file picker, then away longer than it allows: locks", [[0, "pick"], [100, "hide"], [100 + PICK_HIDDEN_MS + 1, "show"]], true],
  ["a file picker, still hidden at its limit: locks then", [[0, "pick"], [100, "hide"]], true],
  ["a picker's own hidden limit is honoured (the document scanner asks for longer)", [[0, "pick", { hiddenMs: 45_000 }], [100, "hide"], [40_000, "show"]], false],
  ["a picker mark expires: leaving after that locks", [[0, "pick"], [PICK_MS + 1, "hide"]], true],
  ["the picker came back (focus): leaving again locks", [[0, "pick"], [100, "hide"], [2000, "show"], [3500, "stopPick"], [4000, "hide"]], true],
  ["a stale picker timer from an earlier pick doesn't lock a later one early", [[0, "pick"], [100, "hide"], [5000, "show"], [5200, "pick", { hiddenMs: 45_000 }], [6000, "hide"], [6000 + PICK_HIDDEN_MS + 1000, "show"]], false],
];

for (const [name, steps, locks, opts] of CASES) {
  test(name, () => {
    const at = run(steps, opts);
    if (locks) assert.ok(at.length >= 1, "expected a lock");
    else assert.deepEqual(at, [], "expected no lock");
  });
}

test("session.js feeds the reducer, and only the prompt (not the whole check) is excused", () => {
  const src = (f) => readFileSync(new URL(`../apps/mobile/src/core/${f}`, import.meta.url), "utf8");
  const session = src("session.js"), interrupt = src("interrupt.js");
  assert.match(session, /feed\(\{ type: document\.hidden \? "hide" : "show" \}\)/);
  assert.match(session, /addEventListener\("pagehide", \(\) => feed\(\{ type: "pagehide" \}\)\)/);
  assert.doesNotMatch(session, /R\.busy\) return|!R\.busy\) lock/, "a running check no longer keeps the vault open off the screen");
  assert.match(interrupt, /R\.hooks\.promptStart\?\.\(\);\s*\n\s*try \{ rel = await gate\.release/);
  assert.match(interrupt, /finally \{ R\.hooks\.promptEnd\?\.\(\); \}/);
});
