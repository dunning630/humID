// The unlock gestures, recognised in one place. The Lock screen and Duress Practice both
// use these, so what Practice says would open the decoy view is exactly what the Lock
// screen does (APP-01: Practice once allowed 650 ms between taps while the Lock screen
// gave the second tap only 420 ms, so a practised rhythm opened the real vault).
//
// Taps: each tap restarts one window; when TAP_WINDOW_MS passes with no new tap, the
// sequence is over and onDone hears how many taps it had and how far apart they were.
// Three or more is the taps gesture. Nothing acts before the window closes, so a first
// tap never starts an unlock that swallows the next two.
//
// Hold: Unlock held for DURESS_HOLD_MS or longer is the hold gesture.
//
// Pure, with the clock and timers injectable (tests/gesture.test.js).

export const TAP_WINDOW_MS = 650;  // the most time between one tap and the next
export const DURESS_TAPS = 3;
export const DURESS_HOLD_MS = 3000; // 3.0: a long hold, not a long-ish press (UX-13)

/**
 * A tap counter. tap() on every tap; onDone({ count, gaps, duress }) once the window
 * after the last tap closes, where gaps are the milliseconds between taps.
 */
export function createTapCounter({ onDone, windowMs = TAP_WINDOW_MS, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let times = [];
  let timer = null;
  const finish = () => {
    timer = null;
    const t = times;
    times = [];
    const gaps = t.slice(1).map((x, i) => x - t[i]);
    onDone?.({ count: t.length, gaps, duress: t.length >= DURESS_TAPS });
  };
  return {
    tap() {
      times.push(now());
      if (timer) clearTimer(timer);
      timer = setTimer(finish, windowMs);
      return times.length;
    },
    /** Forget a sequence in progress without reporting it (the screen went away). */
    cancel() { if (timer) clearTimer(timer); timer = null; times = []; },
    get count() { return times.length; },
  };
}

/** A press timer: down() when the press starts, up() → how long it was held (null if no press). */
export function createHoldTimer({ now = Date.now } = {}) {
  let at = 0;
  return {
    down() { at = now(); },
    up() { if (!at) return null; const held = now() - at; at = 0; return held; },
    cancel() { at = 0; },
    get pressing() { return at > 0; },
  };
}

/**
 * Seconds, as Practice says them: as many decimals as the number needs (0.65 s, 0.5 s, 3 s),
 * so the limit shown is the limit used (0.65 s was once shown as "0.7 s").
 */
export const seconds = (ms) => `${+(ms / 1000).toFixed(2)} s`;

/** Is a press this long the hold gesture? */
export const isDuressHold = (ms) => ms != null && ms >= DURESS_HOLD_MS;

/** What Practice tells the person about a tap sequence, in words, from the measured gaps. */
export function describeTaps({ count, gaps, duress }, windowMs = TAP_WINDOW_MS) {
  // gaps and the limit in the same exact form: a gap of 0.65 s must never read as "0.7 s"
  const s = seconds;
  const apart = gaps.length ? ` Your taps were ${gaps.map(s).join(", ")} apart.` : "";
  if (duress) {
    const slowest = Math.max(...gaps);
    const close = slowest > windowMs * 0.8 ? ` That's close to the limit of ${s(windowMs)}: tap a little faster to be sure.` : "";
    return `That would have opened the decoy view.${apart}${close}`;
  }
  const what = count === 1 ? "one tap" : `${count} taps`;
  return `That would have been a normal unlock: ${what}.${apart} Tap three times, each within ${s(windowMs)} of the last.`;
}
