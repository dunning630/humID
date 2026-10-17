// Where a document was sealed: the phone's location at the moment of sealing, kept
// with the document's name and category in its encrypted details (the index), which
// only the holder's keys open. The vault server never sees it, and it isn't written
// into the file itself, so a copy saved or sent elsewhere carries no location.
//
// It is what the phone reported (satellites, Wi-Fi, cell towers), with the accuracy the
// phone gave: evidence of where the phone said it was, not a proof. Nothing is looked up
// online: no address, no map tiles, unless the person taps "Show on a map".
//
// Asked for when the seal screen opens, so a fix is usually ready by the time Seal is
// pressed; the freshest one is used, and sealing waits a few seconds at most for one.

/** How old a fix may be at the moment of sealing. */
const FRESH_MS = 2 * 60 * 1000;

/** Coordinates kept to 6 decimals (about 11 cm): more would only pretend to be precise. */
const round = (v, d = 6) => Math.round(v * 10 ** d) / 10 ** d;

/** A Geolocation position → the stamp kept with the document. */
export function stampFrom(pos) {
  const c = pos.coords;
  const out = { lat: round(c.latitude), lon: round(c.longitude), accuracy: Math.max(1, Math.round(c.accuracy || 0)), at: new Date(pos.timestamp || Date.now()).toISOString() };
  if (Number.isFinite(c.altitude)) out.altitude = Math.round(c.altitude);
  return out;
}

/** Is this a stamp HumID wrote (lat/lon in range, accuracy, time)? Anything else is ignored. */
export function validStamp(p) {
  return !!p && Number.isFinite(p.lat) && Number.isFinite(p.lon) && Math.abs(p.lat) <= 90 && Math.abs(p.lon) <= 180
    && Number.isFinite(p.accuracy) && p.accuracy > 0 && typeof p.at === "string" && !Number.isNaN(Date.parse(p.at));
}

const why = (e) => (e?.code === 1 ? "denied" : e?.code === 3 ? "timeout" : "unavailable");

/**
 * Start watching the location while a seal screen is open. Returns
 *   { take(waitMs) → Promise<{ stamp } | { reason }>, stop() , status }
 * take() resolves with the freshest fix (waiting up to waitMs for a first one) or the reason
 * there is none: "denied" (location access off for HumID), "unavailable", "timeout",
 * "unsupported" (no location on this device).
 */
export function watchPlace({ geo = globalThis.navigator?.geolocation, now = () => Date.now(), onChange } = {}) {
  let best = null, reason = null, id = null;
  const waiters = new Set();
  const settle = () => { for (const w of waiters) w(); };
  if (!geo?.watchPosition) reason = "unsupported";
  else {
    try {
      id = geo.watchPosition(
        (pos) => {
          const s = stampFrom(pos);
          // keep the more accurate of two recent fixes
          if (!best || Date.parse(best.at) < now() - 15_000 || s.accuracy <= best.accuracy) best = s;
          reason = null;
          onChange?.({ stamp: best });
          settle();
        },
        (e) => { reason = why(e); onChange?.({ reason }); settle(); },
        { enableHighAccuracy: true, maximumAge: 30_000, timeout: 20_000 },
      );
    } catch { reason = "unavailable"; }
  }
  const fresh = () => best && now() - Date.parse(best.at) <= FRESH_MS ? best : null;
  return {
    get status() { return fresh() ? { stamp: fresh() } : { reason: reason || "waiting" }; },
    async take(waitMs = 6000) {
      if (fresh()) return { stamp: fresh() };
      if (reason === "denied" || reason === "unsupported") return { reason };
      await new Promise((res) => {
        const check = () => { if (fresh() || reason === "denied") finish(); };
        const finish = () => { clearTimeout(t); waiters.delete(check); res(); };
        const t = setTimeout(finish, waitMs);
        waiters.add(check);
      });
      return fresh() ? { stamp: fresh() } : { reason: reason || "timeout" };
    },
    stop() { if (id != null) try { geo.clearWatch(id); } catch {} id = null; waiters.clear(); },
  };
}

/** "41.91234° N, 88.31120° W" */
export function formatCoords(p) {
  const f = (v, pos, neg) => `${Math.abs(v).toFixed(5)}° ${v >= 0 ? pos : neg}`;
  return `${f(p.lat, "N", "S")}, ${f(p.lon, "E", "W")}`;
}

/** "within 12 m" / "within 1.4 km" */
export const formatAccuracy = (m) => (m >= 1000 ? `within ${(m / 1000).toFixed(1)} km` : `within ${Math.round(m)} m`);

/** A link the phone opens in its maps app (only when the person taps it). */
export const mapLink = (p) => `https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=17/${p.lat}/${p.lon}`;

/** What to say when there's no stamp. */
export const REASONS = {
  denied: "Location access is off for HumID. Turn it on in your phone's settings to stamp where documents are sealed.",
  unavailable: "This phone can't tell where it is right now.",
  timeout: "No location fix yet. It's sealed without one.",
  unsupported: "This device doesn't report a location.",
  waiting: "Finding your location…",
};
