// Timings for finding what a capture waits on. Development builds only: the flag is tested
// inline, so a release build folds every call here to nothing (tests/bundle.test.js checks
// the trace isn't in a release bundle). It records WHEN something happened and how long it
// took, in milliseconds, by name: never a picture, never text read from one, never a size
// that could say what a document was.
//
// The same list the camera screen writes to (screens/add/camera.jsx trace()): globalThis.__humidTrace.ev,
// entries [name, performance.now() rounded, extra]. A span is recorded when it ends, as
// ["span:<name>", end time, duration ms], so the list reads in order.
//
// To read it on a phone: see docs/ID-SCANNING.md ("Measuring a capture").

/* global __HUMID_ALLOW_DEMO__ */
const ON = typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true;
const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());

/** Note that something happened. */
export function mark(name, extra) {
  if (!ON) return;
  const t = (globalThis.__humidTrace ||= { ev: [] });
  t.ev.push([name, Math.round(now()), extra]);
}

/** Start timing; call the returned function when the work ends. Free in release builds. */
export function span(name) {
  if (!ON) return noop;
  const t0 = now();
  return () => mark(`span:${name}`, Math.round(now() - t0));
}
const noop = () => {};

/** Time a promise or a plain call. */
export function timed(name, fn) {
  if (!ON) return fn();
  const end = span(name);
  let r;
  try { r = fn(); } catch (e) { end(); throw e; }
  if (r && typeof r.then === "function") return r.then((v) => { end(); return v; }, (e) => { end(); throw e; });
  end();
  return r;
}
