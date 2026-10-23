// The rules for leaving the screen, as one pure reducer: (state, event) → { state, action,
// timers }. session.js feeds it the page's events and does what it says; tests/leave.test.js
// walks it through a table of cases.
//
// HumID locks the moment it leaves the screen, with two bounded exceptions:
//   - the system's own face or fingerprint prompt. On some phones it covers the app and the
//     WebView reports itself hidden. Leaving while the prompt is up is the prompt; after it
//     closes the app has PROMPT_SETTLE_MS to come back, and if it hasn't, it locks. (Which
//     WebViews do this, and how late their events arrive, needs a device to measure.)
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
//   hide · show · pagehide · opened (the vault just opened) · promptStart · promptEnd · settle
//   pick { forMs, hiddenMs } · pickEnd { gen } · pickTimeout { gen } · stopPick · locked

export const PROMPT_SETTLE_MS = 1500; // the prompt has closed: this long for the app to be shown again
export const PICK_MS = 60_000;        // a picker that hasn't come back by then no longer excuses leaving
export const PICK_HIDDEN_MS = 20_000; // behind the picker longer than this (another app, home) locks anyway
export const PICK_MAX_MS = 90_000;
export const PICK_HIDDEN_MAX_MS = 60_000;

export const initialLeave = Object.freeze({
  hidden: false,
  hiddenAt: 0,       // when HumID last left the screen
  prompt: false,     // the system's biometric prompt is up
  settleUntil: 0,    // the prompt closed while HumID was hidden: it must be back by then
  picking: false,
  pickGen: 0,        // which "pick" a picker timer belongs to
  pickHiddenMs: 0,
});

const stopPicking = (s) => ({ ...s, picking: false, pickHiddenMs: 0, pickGen: s.pickGen + 1 });
const none = (state) => ({ state, action: null, timers: [] });
const lock = (state) => ({ state: { ...stopPicking(state), settleUntil: 0 }, action: "lock", timers: [] });

export function leave(s, ev) {
  const { now = 0, app = false } = ev;
  switch (ev.type) {
    case "hide": {
      const st = { ...s, hidden: true, hiddenAt: now };
      if (!app) return none(st);
      if (s.prompt) return none(st);                                    // the prompt covering HumID
      if (s.settleUntil && now <= s.settleUntil) return none(st);       // the prompt still closing
      if (s.picking) return { state: st, action: null, timers: [{ ms: s.pickHiddenMs || PICK_HIDDEN_MS, event: { type: "pickTimeout", gen: s.pickGen } }] };
      return lock(st);
    }
    case "show": {
      const st = { ...s, hidden: false, hiddenAt: 0, settleUntil: 0 };
      if (!app || !s.hidden) return none(st);
      // the prompt closed while HumID was hidden, and it stayed away past the settle time
      if (s.settleUntil && now > s.settleUntil) return lock(st);
      if (s.picking && s.hiddenAt && now - s.hiddenAt > (s.pickHiddenMs || PICK_HIDDEN_MS)) return lock(st);
      return none(st);
    }
    case "pagehide": {
      // leaving the page entirely (closed, navigated, suspended) is never a file picker
      const st = { ...stopPicking(s), hidden: true, hiddenAt: s.hiddenAt || now };
      return app && !s.prompt ? lock(st) : none(st);
    }
    case "opened":
      // the vault opened from the Lock screen (an unlock finished) while HumID was off the screen
      if (s.hidden && !s.prompt && !(s.settleUntil && now <= s.settleUntil) && !s.picking) return lock(s);
      return none(s);
    case "promptStart": return none({ ...s, prompt: true, settleUntil: 0 });
    case "promptEnd":
      // A short window either way: the page's own hide/show for the prompt can arrive late.
      return { state: { ...s, prompt: false, settleUntil: now + PROMPT_SETTLE_MS }, action: null, timers: [{ ms: PROMPT_SETTLE_MS, event: { type: "settle" } }] };
    case "settle":
      if (app && s.hidden && s.settleUntil && now >= s.settleUntil && !s.prompt) return lock(s);
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
    case "locked": return none({ ...stopPicking(s), settleUntil: 0 });
    default: return none(s);
  }
}
