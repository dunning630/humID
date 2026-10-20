// Meeting someone: invite → request (with a live stamp) → approve (with a live
// check) → connected. Neither person learns anything but the other's persona ID.
//
//   A  createInvite        new persona, one-time ML-KEM + X25519 keys, dual-signed,
//                          sealed under a key from the invite secret, posted to
//                          box = SHA3(secret). A shows the invite code / QR.
//   B  openInvite          fetches box, decrypts and checks it with the secret.
//                          The relay never had the secret, so it can neither read
//                          the bundle nor swap its keys.
//   B  requestContact      new persona for A; hybrid handshake against A's keys:
//                            ML-KEM-1024 to the one-time key and to A's persona key,
//                            X25519 ephemeral × (one-time, persona), B persona × one-time,
//                            plus a binding key from the invite secret;
//                          dual-signs the transcript (ML-DSA-87 + SLH-DSA), attaches
//                          a live stamp, posts to A's reply box.
//   A  readRequest         decrypts, checks both signatures and the stamp, shows
//                          "HC-…  wants to connect · live human ✓ · safety code".
//   A  acceptRequest       (after a live check) starts the conversation; the first
//                          message is an "accept".
//   B  — the accept arrives in the conversation's inbox; B's session opens it.
//
// Root key: HKDF-SHA3-256(ss_otk || ss_persona || dh1 || dh2 || dh3 || bind, salt = transcript)
// Breaking it needs ML-KEM-1024 AND X25519 broken, AND the invite secret.

import { base32, unbase32, normalize } from "@humid/recovery";
import { backend, SIZES, checkKemPk } from "./backend.js";
import { newPersona, encodePub, decodePub, dualSign, dualVerify, personaFingerprint, personaId, safetyCode } from "./persona.js";
import { requestCommitment, verifyStamp } from "./stamp.js";
import { Session } from "./session.js";
import {
  MsgError, kdf, H, label, lp, unlp, concat, random, wipe, toHex, b64u, unb64u, equal,
  encodeJSON, decodeJSON, aeadSeal, aeadOpen, guard,
} from "./util.js";
import { pad, unpad, checkWire, WIRE_VERSION, isBox, newRetract } from "./wire.js";

export const INVITE_SECRET_BYTES = 16;      // 128 bits: what opens the bundle
export const INVITE_PIN_BYTES = 10;         // 80 bits: which persona the bundle must carry
export const DEFAULT_INVITE_TTL = 24 * 3600_000;   // a day: an invite read over a cloned voice call stops working soon
export const MAX_INVITE_TTL = 7 * 24 * 3600_000;
const SIG_MAX = SIZES.slhSig;

/* ---------- invite codes: HI-XXXX-…  (42 data + 2 check characters) ----------
 * The code carries the secret AND a pin: 80 bits of the inviter's persona
 * fingerprint. Whoever opens the invite checks the bundle's persona against the
 * pin, so someone else who learns the code (another invitee, someone who saw
 * it) can't post their own bundle under it and pose as the inviter.
 */

const CODE_BYTES = INVITE_SECRET_BYTES + INVITE_PIN_BYTES;
const DATA_CHARS = Math.ceil((CODE_BYTES * 8) / 5); // 42
const check2 = (data) => base32(H(label("invite check"), new TextEncoder().encode(data))).slice(0, 2);
const pinOf = (personaPub) => personaFingerprint(personaPub).subarray(0, INVITE_PIN_BYTES);

export function formatInviteCode(secret, pin) {
  if (secret.length !== INVITE_SECRET_BYTES || pin.length !== INVITE_PIN_BYTES) throw new MsgError("bad_invite_code");
  const data = base32(concat(secret, pin));
  return `HI-${(data + check2(data)).match(/.{1,4}/g).join("-")}`;
}

/** { secret, pin } behind a typed or scanned code. Throws bad_invite_code (typos are caught here, on the phone). */
export function parseInviteCode(input) {
  let s = normalize(input);
  if (s.startsWith("H1") && s.length === DATA_CHARS + 4) s = s.slice(2); // "HI" normalises to "H1"
  if (s.length !== DATA_CHARS + 2) throw new MsgError("bad_invite_code", "That isn't a HumID invite code");
  const data = s.slice(0, DATA_CHARS);
  if (check2(data) !== s.slice(DATA_CHARS)) throw new MsgError("bad_invite_code", "That invite code has a typo");
  let raw;
  try { raw = unbase32(data, CODE_BYTES); }
  catch { throw new MsgError("bad_invite_code", "That isn't a HumID invite code"); }
  return { secret: raw.slice(0, INVITE_SECRET_BYTES), pin: raw.slice(INVITE_SECRET_BYTES) };
}

export const inviteBoxOf = (secret) => toHex(H(label("invite box"), secret)).slice(0, 32);
const inviteKey = (secret) => kdf(secret, undefined, "invite key");
const bindKey = (secret) => kdf(secret, undefined, "invite bind");

/* ---------- A: create ---------- */

/**
 * @returns {{ code, box, wire, state }}
 *   code   show it (text or QR) to the one person you mean to meet
 *   box, wire  post the bundle to the relay
 *   state  keep it, sealed, until the invite is used or expires (it holds the one-time secret keys)
 */
export async function createInvite(accountSeed, { now = Date.now(), ttlMs = DEFAULT_INVITE_TTL, uses = 1 } = {}) {
  if (!(ttlMs > 0 && ttlMs <= MAX_INVITE_TTL)) throw new MsgError("bad_ttl", "An invite lasts at most 7 days");
  if (!(Number.isInteger(uses) && uses >= 1 && uses <= 20)) throw new MsgError("bad_uses", "An invite admits 1 to 20 people");
  const b = backend();
  const persona = newPersona(accountSeed);
  const secret = random(INVITE_SECRET_BYTES);
  const otk = b.kem.keygen(random(SIZES.kemSeed));
  const otxSk = random(32);
  const replyBox = toHex(random(16));
  const expires = now + ttlMs;
  const body = encodeJSON({
    v: 1, persona: encodePub(persona.pub),
    otk: { kem: b64u(otk.publicKey), x: b64u(b.x25519.publicKey(otxSk)) },
    reply: replyBox, exp: expires,
  });
  const sigs = dualSign("bundle", body, persona.keys);
  const plain = lp(body, sigs.dsa, sigs.slh);
  const box = inviteBoxOf(secret);
  const nonce = random(12);
  const ct = await aeadSeal(inviteKey(secret), nonce, pad(plain, 29), concat(label("bundle"), new TextEncoder().encode(box)));
  const { retract, retractTag } = newRetract();
  return {
    code: formatInviteCode(secret, pinOf(persona.pub)),
    box,
    wire: concat(Uint8Array.of(WIRE_VERSION), nonce, ct),
    retractTag, // post with the bundle; state.retract takes it down again (cancelInvite)
    state: {
      v: 1, secret, personaSalt: persona.salt, personaId: persona.id, box, retract,
      otkSk: otk.secretKey, otkPk: otk.publicKey, otxSk, replyBox, expires, uses, used: 0, seen: [],
      bundleHash: H(label("bundle hash"), plain),
    },
    persona,
  };
}

/* ---------- B: open ---------- */

export async function openInvite(code, wire, { now = Date.now() } = {}) {
  return guard(async () => {
    const { secret, pin } = typeof code === "string" ? parseInviteCode(code) : code;
    checkWire(wire);
    const box = inviteBoxOf(secret);
    const plain = unpad(await aeadOpen(inviteKey(secret), wire.subarray(1, 13), wire.subarray(13),
      concat(label("bundle"), new TextEncoder().encode(box)), "invite_mismatch"));
    const [bodyBytes, dsa, slh] = unlp(plain, 3);
    const body = decodeJSON(bodyBytes);
    if (body.v !== 1 || !isBox(body.reply) || typeof body.exp !== "number") throw new MsgError("malformed", "Bad invite");
    if (now > body.exp) throw new MsgError("invite_expired", "This invite has expired. Ask for a new one.");
    const persona = decodePub(body.persona);
    if (!equal(pinOf(persona), pin)) throw new MsgError("invite_mismatch", "This invite wasn't made by the person whose code you have");
    if (!dualVerify("bundle", bodyBytes, { dsa, slh }, persona)) throw new MsgError("bad_signature", "Invite signature is invalid");
    return {
      secret, persona, id: personaId(persona), replyBox: body.reply, expires: body.exp,
      otk: { kemPk: checkKemPk(unb64u(body.otk.kem, SIZES.kemPk)), xPk: unb64u(body.otk.x, SIZES.x) },
      bundleHash: H(label("bundle hash"), plain),
    };
  });
}

/* ---------- B: request ---------- */

const REQ_PREFIX = 1 + 32 + SIZES.kemCt + SIZES.kemCt + 12;
const REQ_OVERHEAD = REQ_PREFIX + 16;

/**
 * @param invite   result of openInvite
 * @param opts.stamper  (commitment) → stamp: one live check proves a live human made this request
 * @param opts.intro    optional short note shown with the request ("Parker, from the workshop")
 * @returns {{ box, wire, session, persona }}  post wire to box; keep the session (status "requested") and persona salt
 */
export function requestContact(accountSeed, invite, opts = {}) {
  return guard(() => makeRequest(accountSeed, invite, opts));
}

async function makeRequest(accountSeed, invite, { intro = "", stamper = null, now = Date.now() } = {}) {
  if (typeof intro !== "string" || intro.length > 280) throw new MsgError("bad_intro", "Keep the note to 280 characters");
  if (now > invite.expires) throw new MsgError("invite_expired", "This invite has expired. Ask for a new one.");
  const b = backend();
  const me = newPersona(accountSeed);
  const A = invite;
  const xe = random(32), xePk = b.x25519.publicKey(xe);
  const k1 = b.kem.encapsulate(A.otk.kemPk);
  const k2 = b.kem.encapsulate(A.persona.kemPk);
  const dh1 = b.x25519.shared(xe, A.otk.xPk);
  const dh2 = b.x25519.shared(xe, A.persona.xPk);
  const dh3 = b.x25519.shared(me.keys.xSk, A.otk.xPk);
  const bind = bindKey(invite.secret);
  const th0 = H(label("hello"), lp(invite.bundleHash, xePk, k1.cipherText, k2.cipherText));
  const wrapKey = kdf(concat(k1.sharedSecret, k2.sharedSecret, dh1, dh2, bind), th0, "request wrap");

  const rxSk = random(32), rxPk = b.x25519.publicKey(rxSk);
  const rek = b.kem.keygen(random(SIZES.kemSeed));
  const stamp = stamper ? await stamper(requestCommitment({ th0, senderFp: personaFingerprint(me.pub) })) : null;
  const innerJSON = encodeJSON({ v: 1, persona: encodePub(me.pub), rx: b64u(rxPk), rek: b64u(rek.publicKey), intro, st: stamp, at: now });
  const th = H(label("hello transcript"), lp(th0, H(innerJSON)));
  const sigs = dualSign("request", th, me.keys);
  const nonce = random(12);
  const ct = await aeadSeal(wrapKey, nonce, pad(lp(innerJSON, sigs.dsa, sigs.slh), REQ_OVERHEAD), concat(label("request"), th0));
  const rk0 = kdf(concat(k1.sharedSecret, k2.sharedSecret, dh1, dh2, dh3, bind), th, "root");
  wipe(xe, k1.sharedSecret, k2.sharedSecret, dh1, dh2, dh3, bind, wrapKey);

  const session = Session.create({
    role: "b", rk0, th, me, peer: A.persona, now,
    ratchet: { rxSk, rxPk, rekSk: rek.secretKey, rekPk: rek.publicKey },
  });
  wipe(rk0);
  return {
    box: A.replyBox,
    wire: concat(Uint8Array.of(WIRE_VERSION), xePk, k1.cipherText, k2.cipherText, nonce, ct),
    session, persona: me,
    ...newRetract(), // retractTag: post with the request; retract: withdraw it before it's read
  };
}

/* ---------- A: read and accept ---------- */

/**
 * Open a request that arrived in the invite's reply box.
 * @param persona  A's persona for this invite (personaFromSalt(accountSeed, state.personaSalt))
 * @returns what to show before approving: { from, intro, live, safetyCode, … }
 */
export async function readRequest(state, persona, wire, { now = Date.now(), stampKeys = null } = {}) {
  return guard(async () => {
    if (state.used >= state.uses) throw new MsgError("invite_used", "This invite has already been used");
    if (now > state.expires) throw new MsgError("invite_expired", "This invite has expired");
    checkWire(wire);
    let o = 1;
    const take = (n) => { const x = wire.subarray(o, o + n); o += n; return x; };
    const xePk = take(32), ct1 = take(SIZES.kemCt), ct2 = take(SIZES.kemCt), nonce = take(12), ct = wire.subarray(o);
    const b = backend();
    const ss1 = b.kem.decapsulate(ct1, state.otkSk);
    const ss2 = b.kem.decapsulate(ct2, persona.keys.kemSk);
    const dh1 = b.x25519.shared(state.otxSk, xePk);
    const dh2 = b.x25519.shared(persona.keys.xSk, xePk);
    const bind = bindKey(state.secret);
    const th0 = H(label("hello"), lp(state.bundleHash, xePk, ct1, ct2));
    const wrapKey = kdf(concat(ss1, ss2, dh1, dh2, bind), th0, "request wrap");
    let inner;
    try { inner = unpad(await aeadOpen(wrapKey, nonce, ct, concat(label("request"), th0), "not_for_us")); }
    finally { wipe(wrapKey); }
    const [innerJSON, dsa, slh] = unlp(inner, 3, SIG_MAX + 1);
    const r = decodeJSON(innerJSON);
    if (r.v !== 1 || typeof r.intro !== "string" || r.intro.length > 280) throw new MsgError("malformed", "Bad request");
    const peer = decodePub(r.persona);
    const peerRx = unb64u(r.rx, SIZES.x), peerRek = checkKemPk(unb64u(r.rek, SIZES.kemPk));
    const th = H(label("hello transcript"), lp(th0, H(innerJSON)));
    if (!dualVerify("request", th, { dsa, slh }, peer)) throw new MsgError("bad_signature", "Request signature is invalid");
    if (state.seen.includes(toHex(th))) throw new MsgError("replay_or_old", "This request was already handled");
    const dh3 = b.x25519.shared(state.otxSk, peer.xPk);
    const rk0 = kdf(concat(ss1, ss2, dh1, dh2, dh3, bind), th, "root");
    wipe(ss1, ss2, dh1, dh2, dh3, bind);
    const senderFp = personaFingerprint(peer);
    let live = null;
    if (r.st && stampKeys) live = verifyStamp(stampKeys, r.st, requestCommitment({ th0, senderFp }), { now });
    return {
      from: personaId(peer), intro: r.intro, at: r.at, live, stamped: !!r.st,
      safetyCode: safetyCode(persona.pub, peer),
      _accept: { rk0, th, peer, peerRx, peerRek },
    };
  });
}

/**
 * Approve (the app runs a live check first). Marks the invite used; once all
 * its uses are spent, its one-time secret keys are erased.
 * @returns the Session (role "a"). Send its first message: session.encrypt("accept", "").
 */
export function acceptRequest(state, persona, request, { now = Date.now() } = {}) {
  const a = request._accept;
  if (!a) throw new MsgError("malformed", "Not a request read by readRequest");
  if (state.used >= state.uses) throw new MsgError("invite_used", "This invite has already been used");
  const thHex = toHex(a.th);
  if (state.seen.includes(thHex)) throw new MsgError("replay_or_old", "This request was already handled");
  const session = Session.create({
    role: "a", rk0: a.rk0, th: a.th, me: persona, peer: a.peer, now,
    ratchet: { peerRx: a.peerRx, peerRek: a.peerRek },
  });
  wipe(a.rk0);
  state.seen.push(thHex);
  state.used += 1;
  if (state.used >= state.uses) closeInvite(state);
  return session;
}

/** Decline: remembered so the same request can't be shown again. Nothing is sent. */
export function declineRequest(state, request) {
  if (request._accept) { state.seen.push(toHex(request._accept.th)); wipe(request._accept.rk0); }
}

/**
 * Cancel an invite: erase its one-time secrets (requests made to it can no
 * longer be read) and return what the app shows the relay to take the bundle
 * down, so no one else can fetch it with the code: { box, retract }.
 */
export function cancelInvite(state) {
  const takeDown = { box: state.box, retract: state.retract?.slice?.() ?? null };
  closeInvite(state);
  return takeDown;
}

/** Erase the invite's one-time secrets. Requests made to it can no longer be read. */
export function closeInvite(state) {
  wipe(state.otkSk, state.otxSk, state.secret);
  state.used = state.uses;
  state.closed = true;
}
