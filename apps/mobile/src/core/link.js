// The connection to the vault server: noticed when it drops, and re-established
// for as long as it takes.
//
//   Listening    every request the app makes reports whether the server answered
//                (any HTTP status but 502-504 counts as an answer); the browser's
//                online/offline events and the app coming back to the screen
//                count too. Nothing is sent just to check: while the connection is
//                fine and nothing is happening, HumID uses no network at all.
//   Re-trying    only after a drop: it probes (the server's public key bundle, no
//                session involved) with exponential backoff and jitter (1 s, 2 s,
//                4 s … at most 30 s) until the server answers, pausing while HumID
//                is off the screen; "online" and coming back to the screen try at
//                once, and so does "Reconnect now".
//   Recovering   onUp runs once per recovery: the controller refreshes what is
//                on screen. A session the server has forgotten (it restarted)
//                still ends the way it always has: a live check signs back in.
//
// Pure logic with its clock, timers and probe injected, so it can be tested
// without a network (tests/link.test.js).

export const BACKOFF_MS = [1000, 2000, 4000, 8000, 15000, 30000];
/** With no network at all, check this rarely: the "online" event is what wakes it. */
export const SLOW_CHECK_MS = 30_000;

/** Delay before retry number `attempt` (0-based), with ±20% jitter so many phones don't retry in step. */
export function backoff(attempt, random = Math.random) {
  const base = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)];
  return Math.round(base * (0.8 + 0.4 * random()));
}

/** Network failure (the server didn't answer), as opposed to the server answering "no". */
export const isNetworkFailure = (e) => e instanceof TypeError || e?.name === "AbortError" || e?.name === "TimeoutError" || e?.code === "server_unreachable";

/**
 * createLink({ probe, onChange, onUp, … }) → { up, down, check, retryNow, visible, online, stop, state }
 *   probe()      resolves if the server answered, rejects if not
 *   onChange(s)  every state change: { state: "up" | "down", attempt, nextAt, since, reason }
 *   onUp(info)   once each time it comes back: { downFor }
 */
export function createLink({
  probe, onChange = () => {}, onUp = () => {},
  now = () => Date.now(), setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (t) => clearTimeout(t),
  random = Math.random,
} = {}) {
  let s = { state: "up", attempt: 0, nextAt: 0, since: now(), reason: null };
  let timer = null, probing = false, shown = true, net = true, stopped = false;

  const emit = () => onChange({ ...s });
  const clear = () => { if (timer) clearTimer(timer); timer = null; };
  const plan = () => {
    clear();
    if (stopped || !shown) return; // off the screen: wait for it to come back
    if (s.state !== "down") return; // healthy: nothing scheduled, nothing sent
    const ms = net ? backoff(s.attempt, random) : SLOW_CHECK_MS;
    s.nextAt = now() + ms; emit();
    timer = setTimer(check, ms);
  };

  function up() {
    if (stopped) return;
    if (s.state === "down") {
      const downFor = now() - s.since;
      s = { state: "up", attempt: 0, nextAt: 0, since: now(), reason: null };
      emit();
      plan();
      onUp({ downFor });
    }
  }

  function down(reason = "unreachable") {
    if (stopped) return;
    if (s.state === "up") {
      s = { state: "down", attempt: 0, nextAt: 0, since: now(), reason };
      plan();
    } else if (!probing) { s.reason = reason; plan(); }
  }

  async function check() {
    if (stopped || probing) return;
    clear();
    probing = true;
    let ok = false;
    try { await probe(); ok = true; } catch { ok = false; }
    probing = false;
    if (ok) return up();
    if (s.state === "up") return down("unreachable");
    s.attempt++;
    plan();
  }

  return {
    up, down, check,
    /** "Reconnect now": skip the wait. */
    retryNow: () => { if (s.state === "down") check(); },
    /** The app went off or came back to the screen: pause, or (if it was down) try at once. */
    visible(v) { shown = !!v; if (!shown) clear(); else if (s.state === "down") check(); },
    /** The browser's online / offline events. */
    online(v) { net = !!v; if (net) check(); else down("offline"); },
    stop() { stopped = true; clear(); },
    get state() { return { ...s }; },
  };
}
