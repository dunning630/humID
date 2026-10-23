// The human-to-human rule: nobody interacts on HumID without a live check.
//
// Every interaction between two holders carries proof that a live human approved it:
//
//   | Step                     | Proof required                                                        |
//   |--------------------------|-----------------------------------------------------------------------|
//   | make an invite           | the inviter's live check (it releases the account seed the persona comes from) |
//   | ask to connect (request) | a live stamp over this handshake (readRequest refuses one without)    |
//   | approve (accept)         | the approver's live check; the "accept" message carries a live stamp  |
//   | every message            | a live stamp over its exact bytes; anything unstamped is discarded    |
//   | reading                  | the reader's own live check within the freshness window               |
//
// On top of those per-step proofs, a conversation is VALIDATED HUMAN-TO-HUMAN only while,
// within one freshness window (LIVE_WINDOW_MS):
//
//   1. this device has verified a live stamp from the contact (their most recent message
//      or acceptance), and
//   2. this device's own holder has passed a live check.
//
// When either lapses, so does the validated state. The app shows it lapsing, hides message
// content until its holder checks again, and needs a new live check (and so a new stamp)
// for anything it sends. Nothing here trusts a clock it can't check: the contact's time is
// the moment their message says it was sent, never later than when this phone received it.
//
// A stamp proves A live human approved those bytes on a proven phone, not WHICH human; the
// ratchet proves only the contact's persona could have sent them. Together: a live human
// on the contact's side. See docs/MESSAGING.md, "The human-to-human rule".
//
// "Live" means a match made at that moment: HumID requires a Class-3 biometric match on
// attested hardware and relies on the device's own anti-spoofing; it performs no
// additional liveness detection.

export const LIVE_WINDOW_MS = 5 * 60_000;
export const MIN_LIVE_WINDOW_MS = 30_000;
export const MAX_LIVE_WINDOW_MS = 30 * 60_000;
/** How far ahead of this phone a contact's clock may run before their time is capped at receipt. */
export const LIVE_SKEW_MS = 2 * 60_000;

const num = (x) => (Number.isFinite(x) ? x : null);

/**
 * When the contact was last proven live, from one stamped message:
 * the time it says it was sent, but never later than when it arrived here (a contact
 * whose clock runs fast can't stretch their own freshness), and null if it was not live.
 */
export function peerLiveAt({ live, sentAt, receivedAt }) {
  if (live !== true) return null;
  const s = num(sentAt), r = num(receivedAt);
  if (r === null) return null;
  if (s === null) return r;
  return Math.min(s, r);
}

/**
 * The validated human-to-human state of one conversation.
 * @param ownAt   when this device's holder last passed a live check (ms), or null
 * @param peerAt  when the contact was last proven live (peerLiveAt), or null
 * @returns {{ live, own, peer, until, needs }}
 *   live   true only while BOTH are fresh
 *   own / peer  { fresh, at, until }
 *   until  when the validated state lapses (null if it isn't live)
 *   needs  null when live; "own" (check yourself), "peer" (waiting for them), or "both"
 */
export function liveState({ ownAt = null, peerAt = null, now = Date.now(), windowMs = LIVE_WINDOW_MS } = {}) {
  if (!(windowMs >= MIN_LIVE_WINDOW_MS && windowMs <= MAX_LIVE_WINDOW_MS)) throw new RangeError("windowMs out of range");
  const side = (at) => {
    const t = num(at);
    // a time in the future (beyond skew) is not trusted as fresh
    const fresh = t !== null && t <= now + LIVE_SKEW_MS && now - t < windowMs;
    return { fresh, at: t, until: t !== null ? t + windowMs : null };
  };
  const own = side(ownAt), peer = side(peerAt);
  const live = own.fresh && peer.fresh;
  const needs = live ? null : !own.fresh && !peer.fresh ? "both" : !own.fresh ? "own" : "peer";
  return { live, own, peer, until: live ? Math.min(own.until, peer.until) : null, needs };
}

/** May this device show message content now? Only while its own holder's check is fresh. */
export function canRead({ ownAt = null, now = Date.now(), windowMs = LIVE_WINDOW_MS } = {}) {
  return liveState({ ownAt, peerAt: null, now, windowMs }).own.fresh;
}
