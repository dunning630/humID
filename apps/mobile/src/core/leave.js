// The rules for leaving the screen, as one pure reducer: (state, event) → { state, action,
// timers }. session.js feeds it the page's events and does what it says; tests/leave.test.js
// walks it through a table of cases.
//
// HumID locks the moment it leaves the screen, with two bounded exceptions:
//   - the system's own face or fingerprint prompt. On some phones it covers the app and the
//     WebView reports itself hidden. Leaving while the prompt is up is the prompt; after it
//     closes the app has PROMPT_SETTLE_MS to come back, and if it hasn't, it locks. The
//     excuse lasts PROMPT_MAX_MS at most: a prompt that never returns (hung, or abandoned
//     behind another app) while HumID is hidden still ends in a lock. (Which WebViews do
//     this, and how late their events arrive, needs a device to measure.)
//   - a system screen HumID opened itself (a file picker, the phone's document scanner),
//     marked with "pick": it may keep HumID hidden for a short time (20 s by default).
//
// PC-17 / APP-04 / VAULT-07: the old rule was "leaving the screen doesn't lock while a check
// is running", and a check runs for longer than its prompt (the hold in demo builds, the
// server's answer, opening the document). Hidden in that time, the document opened behind
// the scenes and the vault was unlocked, showing it, when HumID came back. Now only the
// prompt itself is excused, and coming back after the prompt closed while still hidden locks
// even if the settle timer never ran (a hidden page's timers can be paused).
//
// Events (each carries `now`, and `app`: whether the vault is open):
//   hide · show · pagehide · opened (the vault just opened) · promptStart · promptEnd · settle ·
//   promptTimeout { at }
//   pick { forMs, hiddenMs } · pickEnd { gen } · pickTimeout { gen } · stopPick · locked

export const PROMPT_SETTLE_MS = 1500; // the prompt has closed: this long for the app to be shown again
export const PROMPT_MAX_MS = 60_000;  // no system prompt excuses leaving the screen for longer than this
export const PICK_MS = 60_000;        // a picker that hasn't come back by then no longer excuses leaving
export const PICK_HIDDEN_MS = 20_000; // behind the picker longer than this (another app, home) locks anyway
export const PICK_MAX_MS = 90_000;
export const PICK_HIDDEN_MAX_MS = 60_000;

export const initialLeave = Object.freeze({
  hidden: false,
  hiddenAt: 0,       // when HumID last left the screen
  prompt: false,     // the system's biometric prompt is up
  promptAt: 0,       // since when
  settleUntil: 0,    // the prompt closed while HumID was hidden: it must be back by then
  picking: false,
  pickGen: 0,        // which "pick" a picker timer belongs to
  pickHiddenMs: 0,
});

const stopPicking = (s) => ({ ...s, picking: false, pickHiddenMs: 0, pickGen: s.pickGen + 1 });
const none = (state) => ({ state, action: null, timers: [] });
const lock = (state) => ({ state: { ...stopPicking(state), settleUntil: 0 }, action: "lock", timers: [] });

/** The prompt is up and still within its time. */
const promptUp = (s, now) => s.prompt && now - s.promptAt <= PROMPT_MAX_MS;

export function leave(s, ev) {
  const { now = 0, app = false } = ev;
  switch (ev.type) {
    case "hide": {
      const st = { ...s, hidden: true, hiddenAt: now };
      if (!app) return none(st);
      if (promptUp(s, now)) {                                           // the prompt covering HumID, for a bounded time
        return { state: st, action: null, timers: [{ ms: PROMPT_MAX_MS - (now - s.promptAt) + 1, event: { type: "promptTimeout", at: s.promptAt } }] };
      }
      if (s.settleUntil && now <= s.settleUntil) return none(st);       // the prompt still closing
      if (s.picking) return { state: st, action: null, timers: [{ ms: s.pickHiddenMs || PICK_HIDDEN_MS, event: { type: "pickTimeout", gen: s.pickGen } }] };
      return lock(st);
    }
    case "show": {
      const st = { ...s, hidden: false, hiddenAt: 0, settleUntil: 0 };
      if (!app || !s.hidden) return none(st);
      // hidden behind a prompt that outlasted its limit (the page's timers may not have run)
      if (s.prompt && !promptUp(s, now)) return lock(st);
      // the prompt closed while HumID was hidden, and it stayed away past the settle time
      if (s.settleUntil && now > s.settleUntil) return lock(st);
      if (s.picking && s.hiddenAt && now - s.hiddenAt > (s.pickHiddenMs || PICK_HIDDEN_MS)) return lock(st);
      return none(st);
    }
    case "pagehide": {
      // leaving the page entirely (closed, navigated, suspended) is never a file picker
      const st = { ...stopPicking(s), hidden: true, hiddenAt: s.hiddenAt || now };
      if (app && promptUp(s, now)) return { state: st, action: null, timers: [{ ms: PROMPT_MAX_MS - (now - s.promptAt) + 1, event: { type: "promptTimeout", at: s.promptAt } }] };
      return app ? lock(st) : none(st);
    }
    case "opened":
      // the vault opened from the Lock screen (an unlock finished) while HumID was off the screen
      if (s.hidden && !promptUp(s, now) && !(s.settleUntil && now <= s.settleUntil) && !s.picking) return lock(s);
      return none(s);
    case "promptStart": return none({ ...s, prompt: true, promptAt: now, settleUntil: 0 });
    case "promptTimeout":
      // the same prompt is still up, past its limit, and HumID is still off the screen
      if (app && s.hidden && s.prompt && ev.at === s.promptAt && !promptUp(s, now)) return lock(s);
      return none(s);
    case "promptEnd":
      // A short window either way: the page's own hide/show for the prompt can arrive late.
      return { state: { ...s, prompt: false, promptAt: 0, settleUntil: now + PROMPT_SETTLE_MS }, action: null, timers: [{ ms: PROMPT_SETTLE_MS, event: { type: "settle" } }] };
    case "settle":
      if (app && s.hidden && s.settleUntil && now >= s.settleUntil && !promptUp(s, now)) return lock(s);
      return none(s);
    case "pick": {
      const gen = s.pickGen + 1;
      const st = { ...s, picking: true, pickGen: gen, pickHiddenMs: Math.min(ev.hiddenMs ?? PICK_HIDDEN_MS, PICK_HIDDEN_MAX_MS) };
      return { state: st, action: null, timers: [{ ms: Math.min(ev.forMs ?? PICK_MS, PICK_MAX_MS), event: { type: "pickEnd", gen } }] };
    }
    case "pickEnd": return ev.gen === s.pickGen ? none(stopPicking(s)) : none(s);
    case "pickTimeout":
      if (ev.gen === s.pickGen && app && s.hidden && s.picking && s.hiddenAt) return lock(s);
      return none(s);
    case "stopPick": return none(stopPicking(s));
    case "locked": return none({ ...stopPicking(s), settleUntil: 0, prompt: false, promptAt: 0 });
    default: return none(s);
  }
}
