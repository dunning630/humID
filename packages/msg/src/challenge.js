// "Is this really you?": proving it's you when someone could be faking your
// voice or face.
//
// A cloned voice or a deepfake video is built to match what you look and sound
// like, so comparing it with a stored sample proves nothing. What a faker can't
// do is pass a live check on YOUR phone. So the person who got the suspicious
// call doesn't judge the call; they ask your phone, over the conversation they
// already pinned when you connected:
//
//   verifier                                   claimant (the real person, wherever they are)
//   ────────                                   ────────
//   sendChallenge ── "challenge" ────────────► readChallenge
//     "are you on a call with me right now?"     shows the question and who asks
//                                                live check → replyToChallenge(yes | no)
//   checkReply ◄──── "challenge-reply" + stamp ─  shows the spoken code (if yes)
//     confirmed + spoken code  /  denied  /  unverified
//
// On the call, the claimant reads the spoken code from their phone; the
// verifier checks it against theirs. Three things must line up:
//
//   1. The reply came over the ratchet from the persona pinned at the handshake,
//      so it came from the claimant's device and nobody else's.
//   2. It carries a live stamp over exactly these reply bytes (which include the
//      challenge id), so a live human approved this answer to this question.
//   3. The voice on the call knows the spoken code, which appears only on the
//      claimant's phone after that live check. Even if the real person said
//      "yes" by mistake, a faker on the line can't read the code.
//
// A "yes" without a valid stamp is never shown as confirmed. A "no" is shown as
// denied whether or not it is stamped: the safe action is the same either way.
// A reply sent from a duress unlock is never shown as confirmed; it comes back
// as unverified, with `duress: true` for an app whose user opted in to alerts.
//
// Nothing here looks at, records or compares a voice or a face.

import { base32 } from "@humid/recovery";
import { MsgError, H, label, lp, random, utf8, b64u, unb64u, encodeJSON, decodeJSON, toHex, fromHex, guard } from "./util.js";

export const CHALLENGE_TTL = 5 * 60_000;           // default: answer within 5 minutes
export const MAX_CHALLENGE_TTL = 30 * 60_000;
export const CLOCK_SKEW = 2 * 60_000;              // phones' clocks may differ this much
export const PURPOSES = Object.freeze(["call", "video", "voice-note", "message", "other"]);
export const ANSWERS = Object.freeze(["yes", "no"]);
export const SPOKEN_CODE_CHARS = 8;                // 40 bits: only needs to survive one live call
const NOTE_MAX = 140;
const ID = 16;

const group = (s) => s.match(/.{1,4}/g).join("-");

/** The words the claimant's app shows for each purpose. */
export const QUESTIONS = Object.freeze({
  call: "Are you on a voice call with me right now?",
  video: "Are you on a video call with me right now?",
  "voice-note": "Did you just send me a voice note?",
  message: "Did you just send me that message?",
  other: "Is this really you?",
});

function cleanNote(note) {
  if (note === undefined || note === null) return "";
  if (typeof note !== "string") throw new MsgError("bad_challenge", "Note must be text");
  // One line, printable, short: it's shown on the claimant's phone next to the question.
  const n = note.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, " ").trim();
  if (n.length > NOTE_MAX) throw new MsgError("bad_challenge", `Note is longer than ${NOTE_MAX} characters`);
  return n;
}

/**
 * Verifier: build a challenge. Send `body` as kind "challenge"; keep `pending`
 * (plain JSON) with the conversation until the reply arrives or it expires.
 */
export function makeChallenge({ purpose = "call", note, now = Date.now(), ttl = CHALLENGE_TTL } = {}) {
  if (!PURPOSES.includes(purpose)) throw new MsgError("bad_challenge", `Unknown purpose "${purpose}"`);
  if (!Number.isInteger(ttl) || ttl < 30_000 || ttl > MAX_CHALLENGE_TTL) throw new MsgError("bad_challenge", "Challenge lifetime must be 30 s to 30 min");
  const id = random(ID);
  const exp = now + ttl;
  const n = cleanNote(note);
  const body = encodeJSON({ v: 1, id: b64u(id), p: purpose, n, exp });
  return { body, pending: { v: 1, id: toHex(id), purpose, note: n, created: now, expires: exp, outcome: null } };
}

/** Verifier: make a challenge and send it on `session`. Returns { box, wire, pending }. */
export async function sendChallenge(session, opts = {}) {
  const { body, pending } = makeChallenge(opts);
  const sent = await session.encrypt("challenge", body, { now: opts.now ?? Date.now(), duress: !!opts.duress });
  return { ...sent, pending };
}

/**
 * Claimant: read a decrypted "challenge" message. Returns what the app shows:
 * { id, purpose, question, note, expires, expired }.
 */
export function readChallenge(msg, { now = Date.now() } = {}) {
  return guard(() => {
    if (msg?.kind !== "challenge") throw new MsgError("bad_challenge", "Not a challenge");
    const c = decodeJSON(msg.body);
    if (c?.v !== 1 || !PURPOSES.includes(c.p) || typeof c.exp !== "number" || typeof c.n !== "string") throw new MsgError("bad_challenge", "Malformed challenge");
    const id = unb64u(c.id, ID);
    const note = cleanNote(c.n);
    // A challenge that claims to live longer than the maximum was not made by HumID.
    if (c.exp - msg.at > MAX_CHALLENGE_TTL + CLOCK_SKEW) throw new MsgError("bad_challenge", "Challenge lifetime out of range");
    return { id: toHex(id), purpose: c.p, question: QUESTIONS[c.p], note, expires: c.exp, expired: now > c.exp + CLOCK_SKEW };
  });
}

/** The code both phones show after a "yes". Bound to this conversation, this challenge and this reply. */
export function spokenCode(convId, challengeIdHex, replyNonce) {
  return group(base32(H(label("spoken code"), lp(convId, fromHex(challengeIdHex), replyNonce))).slice(0, SPOKEN_CODE_CHARS));
}

/**
 * Claimant: answer a challenge. A reply must be stamped (one live check), so
 * `stamper` is required. Returns { box, wire, code } where `code` is the spoken
 * code to read aloud on the call (null for "no").
 */
export async function replyToChallenge(session, challenge, { answer, stamper, now = Date.now(), duress = false } = {}) {
  if (!ANSWERS.includes(answer)) throw new MsgError("bad_answer", 'Answer must be "yes" or "no"');
  if (typeof stamper !== "function") throw new MsgError("stamp_required", "Answering a challenge takes a live check");
  if (!challenge || typeof challenge.id !== "string" || !/^[0-9a-f]{32}$/.test(challenge.id)) throw new MsgError("bad_challenge", "Read the challenge first (readChallenge)");
  if (now > challenge.expires + CLOCK_SKEW) throw new MsgError("challenge_expired", "This question has expired. Ask them to send a new one.");
  const nonce = random(ID);
  const body = encodeJSON({ v: 1, re: b64u(fromHex(challenge.id)), a: answer, r: b64u(nonce) });
  const sent = await session.encrypt("challenge-reply", body, { now, stamper, duress });
  return { ...sent, code: answer === "yes" ? spokenCode(session.convId, challenge.id, nonce) : null };
}

/** Anyone: the challenge id a decrypted "challenge-reply" answers, to find its pending record. */
export function replyId(msg) {
  return guard(() => {
    if (msg?.kind !== "challenge-reply") throw new MsgError("bad_reply", "Not a challenge reply");
    const r = decodeJSON(msg.body);
    return toHex(unb64u(r?.re, ID));
  });
}

/**
 * Verifier: judge a decrypted "challenge-reply" (session.decrypt with stampKeys).
 * Returns { verdict, code, live, duress, pending } where `pending` is the
 * updated record to store (a challenge takes one answer).
 *
 *   confirmed        "yes", valid live stamp, in time, not under duress. Show `code`;
 *                    the person on the call must read the same code.
 *   denied           "no": they say it is NOT them. Treat the call as an impersonation.
 *   unverified       "yes" without a valid stamp, or from a duress unlock.
 *   expired          the answer came after the challenge expired.
 *   already_answered this challenge was answered before; a second answer is suspect.
 *   not_this_challenge the reply answers a different challenge.
 */
export function checkReply(session, pending, msg, { now = Date.now() } = {}) {
  return guard(() => {
    if (msg?.kind !== "challenge-reply") throw new MsgError("bad_reply", "Not a challenge reply");
    if (!pending || pending.v !== 1 || !/^[0-9a-f]{32}$/.test(pending.id)) throw new MsgError("bad_challenge", "Unknown pending challenge");
    const r = decodeJSON(msg.body);
    if (r?.v !== 1 || !ANSWERS.includes(r.a)) throw new MsgError("bad_reply", "Malformed challenge reply");
    const id = toHex(unb64u(r.re, ID));
    const nonce = unb64u(r.r, ID);
    const live = msg.live === true;
    const duress = msg.duress === true;
    const out = (verdict, code = null) => ({ verdict, code, live, duress, answer: r.a, pending: { ...pending, outcome: pending.outcome ?? verdict } });
    if (id !== pending.id) return { ...out("not_this_challenge"), pending };
    if (pending.outcome) return { ...out("already_answered"), pending };
    if (now > pending.expires) return out("expired");
    if (r.a === "no") return out("denied");
    if (!live || duress) return out("unverified");
    return out("confirmed", spokenCode(session.convId, pending.id, nonce));
  });
}
