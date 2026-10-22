// A conversation between two personas: a hybrid post-quantum double ratchet.
//
// Every time the conversation changes direction, the sender mixes BOTH a new
// X25519 exchange AND a new ML-KEM-1024 encapsulation into the root key:
//
//   RK', CKs = HKDF-SHA3-256(ikm = X25519(newDH, peerDH) || ML-KEM-1024 shared secret,
//                            salt = RK, "HUMID-MSG-v1 ratchet step", 64)
//
// and each message key comes from a one-way chain (HMAC-SHA3-256). So:
//
// | Property | How |
// |---|---|
// | Confidentiality now and after quantum computers | each step needs both ML-KEM-1024 and X25519 broken |
// | Forward secrecy | message and chain keys are deleted once used; a phone seized tomorrow cannot read today's traffic |
// | Healing after a compromise | the next direction change brings fresh DH and KEM secrets the thief never saw |
// | Deniability | messages are authenticated by shared keys, not signatures: the contact knows you sent it, but cannot prove that to anyone else |
// | Drops, reorders, replays | out-of-order messages open (up to 1,000 skipped); a replay or an old message is refused; a gap that stays open is reported |
//
// The ratchet runs inside a second layer (the wire key) so the relay never sees
// ratchet keys, counters or which messages belong to one chain.

import { backend, SIZES, checkKemPk } from "./backend.js";
import { personaFingerprint, personaId, safetyCode, encodePub, decodePub } from "./persona.js";
import { messageCommitment, verifyStamp } from "./stamp.js";
import {
  MsgError, kdf, mac, label, concat, u32, readU32, random, wipe, equal, toHex, b64u, unb64u,
  encodeJSON, decodeJSON, aeadSeal, aeadOpen, dayOf, utf8, fromUtf8, guard, toPlain, fromPlain,
} from "./util.js";
import { pad, unpad, checkWire, WIRE_VERSION, boxFor, pollDays, newRetract } from "./wire.js";

export const MAX_SKIP = 1000;        // per chain step
export const MAX_SKIPPED_TOTAL = 2000;
const SALT = 16;
export const HEADER_BYTES = SIZES.x + SIZES.kemCt + SIZES.kemPk + SALT + 8; // dh | kem ct | next kem ek | salt | pn | n
export const SKIPPED_TTL_MS = 14 * 24 * 3600_000; // a withheld message's key is kept no longer than the relay keeps the message
const WIRE_OVERHEAD = 1 + 12 + 16;
const NONCE = 16;
const STAMP_ROOM = 1200; // characters reserved for a stamp in every payload
// challenge / challenge-reply: "Is this really you?" (challenge.js). media: a
// voice note, photo or clip with its capture details (media.js). All kinds pad
// to the same size classes, so the relay can't tell a challenge from a text.
export const KINDS = Object.freeze(["text", "accept", "file-key", "receipt", "close", "delete", "timer", "challenge", "challenge-reply", "media"]);

/* ---------- delete and disappearing messages ---------- */

const DAY_MS = 86_400_000;
export const MIN_TTL_MS = 30_000;            // disappearing messages: shortest timer
export const MAX_TTL_MS = 365 * DAY_MS;      // longest timer
export const MAX_DELETE = 500;               // message ids in one delete message
export const isTtl = (x) => x === 0 || (Number.isInteger(x) && x >= MIN_TTL_MS && x <= MAX_TTL_MS);
const ID_RE = /^[A-Za-z0-9_-]{22}$/;         // 16 random bytes, base64url
const DH_RE = /^[0-9a-f]{64}$/;

/**
 * The body of a "delete" message: which of MY messages the contact's app must
 * erase. Each entry names the message id and its place in the ratchet
 * ({ dh, n }, as encrypt returned it), so if the message hasn't arrived yet the
 * contact's phone destroys the key it would have opened with. Saved with
 * Conversation.seal (a new key every save), no stored copy of the conversation
 * holds that key afterwards, so a kept copy of the ciphertext can't be opened.
 */
export function deleteBody(entries) {
  if (!Array.isArray(entries)) throw new MsgError("bad_delete", "Nothing to delete");
  const d = entries.map((e) => {
    if (!e || typeof e.id !== "string" || !e.pos || typeof e.pos.dh !== "string") throw new MsgError("bad_delete", "This message can't be deleted for both of you");
    return { id: e.id, dh: e.pos.dh, n: e.pos.n };
  });
  const body = encodeJSON({ d });
  parseDelete(body);
  return body;
}

export function parseDelete(bytes) {
  const o = decodeJSON(bytes);
  const d = o?.d;
  if (!Array.isArray(d) || d.length < 1 || d.length > MAX_DELETE) throw new MsgError("bad_delete", "A delete names 1 to 500 messages");
  for (const e of d) {
    if (!e || !ID_RE.test(e.id) || !DH_RE.test(e.dh) || !Number.isInteger(e.n) || e.n < 0 || e.n > 0xffffffff) {
      throw new MsgError("bad_delete", "Malformed delete");
    }
  }
  return d;
}

function parseTimer(bytes) {
  const t = fromUtf8(bytes);
  const ms = /^\d{1,12}$/.test(t) ? Number(t) : NaN;
  if (!isTtl(ms)) throw new MsgError("bad_timer", "Timer must be off, or between 30 seconds and a year");
  return ms;
}

/**
 * Both phones apply the same rule to every timer change, so they always agree:
 * the later change wins; on a tie, the shorter timer (0 = off counts as longest).
 */
function newerTimer(cur, curAt, ms, at) {
  if (at !== curAt) return at > curAt;
  const len = (x) => (x === 0 ? Infinity : x);
  return len(ms) < len(cur);
}
const MAX_BODY = 1_900_000;

const kdfRk = (rk, ikm) => { const o = kdf(ikm, rk, "ratchet step", 64); return [o.slice(0, 32), o.slice(32)]; };
const kdfCk = (ck) => [mac(ck, Uint8Array.of(1)), mac(ck, Uint8Array.of(2))]; // [message key, next chain key]
// The per-message salt (random, carried in the header) means that even if a
// device were rolled back to an older state and reused a chain key, the AES
// key and nonce would still never repeat.
const msgKeys = (mk, salt) => { const o = kdf(mk, salt, "message key", 44); return [o.slice(0, 32), o.slice(32)]; };

/** Keys both sides derive from the handshake. */
export function conversationKeys(rk0, th, role) {
  const k = (info, n = 32) => kdf(rk0, th, info, n);
  const a2b = { box: k("box a2b"), wire: k("wire a2b") };
  const b2a = { box: k("box b2a"), wire: k("wire b2a") };
  const [send, recv] = role === "a" ? [a2b, b2a] : [b2a, a2b];
  return {
    convId: k("conversation id", 16),
    root: k("ratchet root"),
    sendBox: send.box, recvBox: recv.box, sendWire: send.wire, recvWire: recv.wire,
  };
}

function encodeHeader(h) {
  return concat(h.dh, h.ct, h.ek, h.salt, u32(h.pn), u32(h.n));
}
function decodeHeader(b) {
  let o = 0;
  const take = (n) => { const x = b.subarray(o, o + n); o += n; return x; };
  const dh = take(SIZES.x), ct = take(SIZES.kemCt), ek = take(SIZES.kemPk), salt = take(SALT);
  return { dh, ct, ek, salt, pn: readU32(b, o), n: readU32(b, o + 4) };
}

const cloneState = (s) => structuredClone(s);

/** Overwrite every secret in a state object. Each step works on a copy, so the copy it replaces is wiped. */
function wipeState(st) {
  if (!st) return;
  wipe(st.RK, st.CKs, st.CKr, st.sendBox, st.recvBox, st.sendWire, st.recvWire, st.DHs?.sk, st.KEMs?.sk);
  for (const e of st.skipped || []) wipe(e[1]);
}
const MAX_OLD_CHAINS = 64; // remembered so a late message from an old chain is refused as old, without any work

export class Session {
  /**
   * @param {object} p
   *   role "a" (accepted the request; sends first) or "b" (made the request)
   *   rk0, th          handshake output
   *   me               { pub, id } of my persona for this contact (the salt lives in the contact list)
   *   peer             peer persona public keys
   *   ratchet          a: { peerRx, peerRek }   b: { rxSk, rxPk, rekSk, rekPk }
   */
  static create({ role, rk0, th, me, peer, ratchet, now = Date.now() }) {
    const ck = conversationKeys(rk0, th, role);
    const s = {
      v: 1, role, version: 0, created: now, status: role === "a" ? "connected" : "requested",
      convId: ck.convId, sendBox: ck.sendBox, recvBox: ck.recvBox, sendWire: ck.sendWire, recvWire: ck.recvWire,
      me: { id: me.id, fp: personaFingerprint(me.pub) },
      peer: { id: personaId(peer), fp: personaFingerprint(peer), pub: encodePub(peer) },
      safety: safetyCode(me.pub, peer),
      RK: ck.root, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0,
      DHs: null, DHr: null, KEMs: null, KEMr: null, needSend: false, head: null,
      skipped: [], // [ "dhhex:n", messageKey, firstSeenMs ]
      lastRecv: null, lastSend: null,
      timer: 0, timerAt: 0, // disappearing messages, ms (0 = off), and when it was last set; either side sets it
    };
    if (role === "a") {
      s.DHr = ratchet.peerRx; s.KEMr = checkKemPk(ratchet.peerRek); s.needSend = true;
    } else {
      s.DHs = { sk: ratchet.rxSk, pk: ratchet.rxPk };
      s.KEMs = { sk: ratchet.rekSk, pk: ratchet.rekPk };
    }
    return new Session(s);
  }

  /**
   * @param state   from create() or fromJSON()
   * @param opts.persist  async (session) => void. Called with the new state
   *   before encrypt/decrypt return; if it throws, the step is undone and
   *   nothing is handed back. The app seals and stores the conversation here,
   *   so a message can never go out from a state that wasn't saved first.
   */
  constructor(state, { persist = null } = {}) {
    this.s = state;
    this.persist = persist;
    this.queue = Promise.resolve();
  }

  async #commit(prev, next) {
    // persist sees the new state through its own Session view; everyone else keeps
    // seeing the saved state until the save has succeeded.
    if (this.persist) {
      try { await this.persist(new Session(next)); }
      catch (e) { throw new MsgError("persist_failed", `Could not save the conversation: ${e?.message || e}`); }
    }
    this.s = next;
    wipeState(prev); // the replaced copy's keys are overwritten, not left for the garbage collector
  }

  /** Run one step on a copy of the state; a step that fails wipes its copy. */
  async #step(fn) {
    let work = null;
    try { return await fn((st) => (work = st)); }
    catch (e) { if (work && work !== this.s) wipeState(work); throw e; }
  }

  get peerId() { return this.s.peer?.id ?? null; }
  get myId() { return this.s.me?.id ?? null; }
  get safetyCode() { return this.s.safety ?? null; }
  get status() { return this.s.status; }
  get version() { return this.s.version; }
  get timer() { return this.s.timer ?? 0; }
  get peerPub() { return decodePub(this.s.peer.pub); }

  /** Mailboxes to poll for this conversation. */
  inboxes(now = Date.now()) {
    if (this.s.status === "erased") return [];
    return pollDays(now).map((d) => boxFor(this.s.recvBox, d));
  }

  /** Serialise every encrypt/decrypt: the ratchet must never run two steps at once. */
  #serial(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  /**
   * Encrypt one message. `body` is a string or bytes.
   * opts.stamper(commitment) → stamp: asks for a live stamp (one live check).
   * opts.duress: true when the app was unlocked with the duress gesture. Carried
   *   encrypted; only the contact's app sees it, and only if they opted in to alerts.
   * opts.ttlMs: disappearing time for this message (default: the conversation's timer).
   * Returns { box, wire, retractTag } to post to the relay, and for the sender's
   * own records { id, pos, ttlMs, retract } (retract: the unsend token; keep it, never send it
   * except to unsend).
   */
  encrypt(kind, body, { now = Date.now(), stamper = null, duress = false, ttlMs, requireLive = false, nonce: given = null } = {}) {
    return this.#serial(() => guard(() => this.#step(async (track) => {
      if (!KINDS.includes(kind)) throw new MsgError("bad_kind", `Unknown message kind "${kind}"`);
      const s0 = this.s;
      if (s0.status === "erased") throw new MsgError("erased", "This conversation was deleted");
      if (s0.status === "closed") throw new MsgError("closed", "This conversation was closed");
      if (s0.status === "requested") throw new MsgError("not_accepted", "Your contact hasn't accepted yet");
      // The human-to-human rule (live.js): nothing goes out without a live stamp.
      if (requireLive && typeof stamper !== "function") throw new MsgError("stamp_required", "Sending needs a live check");
      const bodyBytes = typeof body === "string" ? utf8(body) : body;
      if (!(bodyBytes instanceof Uint8Array) || bodyBytes.length > MAX_BODY) throw new MsgError("too_large", "Message too large");
      const ttl = ttlMs ?? (kind === "text" || kind === "file-key" ? s0.timer ?? 0 : 0);
      if (!isTtl(ttl)) throw new MsgError("bad_timer", "Timer must be off, or between 30 seconds and a year");
      const newTimer = kind === "timer" ? parseTimer(bodyBytes) : null;
      if (kind === "delete") parseDelete(bodyBytes);
      // A caller may pick the nonce (the message id) so it can stamp several messages in one
      // live check (Conversation stamps a whole "delete for both" that way). It must be fresh.
      if (given !== null && (!(given instanceof Uint8Array) || given.length !== NONCE)) throw new MsgError("bad_nonce", "A message id is 16 random bytes");
      const nonce = given ? given.slice() : random(NONCE);
      const stamp = stamper
        ? await stamper(messageCommitment({ convId: s0.convId, senderFp: s0.me.fp, nonce, kind, body: bodyBytes }))
        : null;
      if (requireLive && !stamp) throw new MsgError("stamp_required", "The live check didn't complete, so nothing was sent");

      const s = track(cloneState(this.s));
      const b = backend();
      if (s.needSend) {
        const dh = random(32);
        const prevDh = s.DHs;
        s.DHs = { sk: dh, pk: b.x25519.publicKey(dh) };
        const kem = b.kem.keygen(random(SIZES.kemSeed));
        const prevKem = s.KEMs;
        s.KEMs = { sk: kem.secretKey, pk: kem.publicKey };
        const { cipherText, sharedSecret } = b.kem.encapsulate(s.KEMr);
        const dhOut = b.x25519.shared(s.DHs.sk, s.DHr);
        const ikm = concat(dhOut, sharedSecret);
        [s.RK, s.CKs] = kdfRk(s.RK, ikm);
        wipe(dhOut, sharedSecret, ikm);
        if (prevKem) wipe(prevKem.sk);
        if (prevDh) wipe(prevDh.sk);
        s.PN = s.Ns; s.Ns = 0; s.needSend = false;
        s.head = { dh: s.DHs.pk, ct: cipherText, ek: s.KEMs.pk };
      }
      const [mk, next] = kdfCk(s.CKs);
      s.CKs = next;
      const salt = random(SALT);
      const pos = { dh: toHex(s.head.dh), n: s.Ns };
      const header = encodeHeader({ ...s.head, salt, pn: s.PN, n: s.Ns });
      s.Ns += 1;

      const payload = { k: kind, b: b64u(bodyBytes), at: now, nonce: b64u(nonce), x: ttl };
      // A change you make is always newer than the one you last saw, even if the clocks disagree.
      const timerAt = Math.max(now, (s0.timerAt ?? 0) + 1);
      if (newTimer !== null) payload.ta = timerAt;
      if (stamp) payload.st = stamp;
      payload.d = duress ? 1 : 0; // always present, same width: a duress message is the same size
      // Stamped or not, the payload is the same length (for stamp keys up to 4096 bits), so
      // the wire size never shows whether a live check was made.
      payload.f = "0".repeat(Math.max(0, STAMP_ROOM - (stamp ? JSON.stringify(stamp).length + 6 : 0)));
      const [key, iv] = msgKeys(mk, salt);
      const ct = await aeadSeal(key, iv, encodeJSON(payload), concat(label("message"), s.convId, header));
      wipe(mk, key, iv);

      const inner = pad(concat(header, ct), WIRE_OVERHEAD);
      const wn = random(12);
      const outer = await aeadSeal(s.sendWire, wn, inner, concat(label("wire"), s.convId));
      const wire = concat(Uint8Array.of(WIRE_VERSION), wn, outer);
      if (kind === "close") s.status = "closed";
      if (newTimer !== null) { s.timer = newTimer; s.timerAt = timerAt; }
      s.lastSend = now;
      s.version += 1;
      await this.#commit(s0, s);
      return { box: boxFor(s.sendBox, dayOf(now)), wire, id: b64u(nonce), pos, ttlMs: ttl, ...newRetract() };
    })));
  }

  /**
   * Decrypt one wire object from this conversation's inbox.
   * opts.stampKeys: the server's published stamp keys (importStampKeys).
   * Returns { kind, id, body (bytes), text (if kind is text), at, n, ttlMs, live, duress }, plus
   *   for "timer": timer (ms); for "delete": ids (the contact's messages to erase) and destroyed
   *   (how many not-yet-arrived messages can now never be opened).
   *   live: true (valid stamp), false (stamp present but invalid), null (no stamp, or no keys to check).
   * opts.requireLive: the human-to-human rule (live.js). A message without a valid live stamp is
 *   discarded: { kind, id, at, n, refused: "not_live" } and nothing it says is applied.
 * Throws MsgError: not_for_us, replay_or_old, decrypt_failed, malformed, too_many_skipped, closed, erased, no_stamp_keys.
   */
  decrypt(wire, { now = Date.now(), stampKeys = null, requireLive = false } = {}) {
    return this.#serial(() => guard(() => this.#step(async (track) => {
      checkWire(wire);
      // The human-to-human rule needs the issuer's keys to check a stamp; without them nothing moves.
      if (requireLive && !stampKeys) throw new MsgError("no_stamp_keys", "Can't check live stamps yet");
      const s0 = this.s;
      if (s0.status === "erased") throw new MsgError("erased", "This conversation was deleted");
      const s = track(cloneState(s0));
      expireSkipped(s, now);
      const inner = unpad(await aeadOpen(s.recvWire, wire.subarray(1, 13), wire.subarray(13), concat(label("wire"), s.convId), "not_for_us"));
      if (inner.length < HEADER_BYTES + 16) throw new MsgError("malformed", "Message too short");
      const headerBytes = inner.subarray(0, HEADER_BYTES);
      const h = decodeHeader(headerBytes);
      const ct = inner.subarray(HEADER_BYTES);

      const id = `${toHex(h.dh)}:${h.n}`;
      let mk;
      const hit = s.skipped.findIndex((e) => e[0] === id);
      if (hit >= 0) {
        mk = s.skipped[hit][1];
        s.skipped.splice(hit, 1);
      } else {
        const b = backend();
        if (!s.DHr || !equal(h.dh, s.DHr)) {
          if (!s.KEMs || !s.DHs) throw new MsgError("replay_or_old", "Not expecting a new chain");
          if ((s.oldChains || []).includes(toHex(h.dh))) throw new MsgError("replay_or_old", "This message is from an earlier part of the conversation and can no longer be opened");
          if (s.CKr) skip(s, h.pn, now);
          checkKemPk(h.ek);
          const ss = b.kem.decapsulate(h.ct, s.KEMs.sk);
          const dhOut = b.x25519.shared(s.DHs.sk, h.dh);
          const ikm = concat(dhOut, ss);
          [s.RK, s.CKr] = kdfRk(s.RK, ikm);
          wipe(dhOut, ss, ikm);
          if (s.DHr) s.oldChains = [...(s.oldChains || []), toHex(s.DHr)].slice(-MAX_OLD_CHAINS);
          s.DHr = h.dh.slice(); s.KEMr = h.ek.slice(); s.Nr = 0; s.needSend = true;
        }
        if (h.n < s.Nr) throw new MsgError("replay_or_old", "This message was already received");
        skip(s, h.n, now);
        [mk, s.CKr] = kdfCk(s.CKr);
        s.Nr += 1;
      }
      const [key, iv] = msgKeys(mk, h.salt);
      const pt = await aeadOpen(key, iv, ct, concat(label("message"), s.convId, headerBytes));
      wipe(mk, key, iv);
      const p = decodeJSON(pt);
      if (!KINDS.includes(p.k) || typeof p.at !== "number") throw new MsgError("malformed", "Bad message payload");
      // After the conversation ends, only deletes still count: "delete for both" then
      // "end" may arrive in either order, and the deletes must not be lost.
      if (s.status === "closed" && p.k !== "delete") throw new MsgError("closed", "This conversation was closed");
      const body = unb64u(p.b);
      const nonce = unb64u(p.nonce, NONCE);
      let live = null;
      if (p.st && stampKeys) {
        live = verifyStamp(stampKeys, p.st, messageCommitment({ convId: s.convId, senderFp: s.peer.fp, nonce, kind: p.k, body }), { now });
      }
      if (requireLive && live !== true) {
        // Not approved live: discarded. The key is still used up (the ratchet moves on, so
        // forward secrecy holds and the message can't be opened again), but nothing it says
        // is applied: no text, no accept, no timer, no delete, no end.
        wipe(body);
        s.version += 1;
        await this.#commit(s0, s);
        return { kind: p.k, id: p.nonce, at: p.at, n: h.n, refused: "not_live", stamped: !!p.st, live, duress: false };
      }
      const text = p.k === "text" ? fromUtf8(body) : undefined; // decode before committing: bad text moves nothing
      const sent = p.x ?? 0;
      if (!isTtl(sent)) throw new MsgError("malformed", "Bad disappearing time");
      // Your own timer applies to what you receive too: the shorter of the sender's and yours.
      const ttl = !(p.k === "text" || p.k === "file-key") ? 0
        : sent === 0 ? s.timer : s.timer === 0 ? sent : Math.min(sent, s.timer);
      const extra = {};
      if (p.k === "timer") {
        const ms = parseTimer(body);
        const at = Number.isSafeInteger(p.ta) ? p.ta : p.at;
        if (newerTimer(s.timer, s.timerAt ?? 0, ms, at)) { s.timer = ms; s.timerAt = at; }
        extra.timer = s.timer;
      }
      if (p.k === "delete") {
        const d = parseDelete(body);
        let destroyed = 0;
        for (const e of d) {
          // Only keys of the CONTACT's own sending chain are ever in `skipped`, so a
          // delete can't touch anything but the contact's own messages.
          const i = s.skipped.findIndex((k) => k[0] === `${e.dh}:${e.n}`);
          if (i >= 0) { wipe(s.skipped[i][1]); s.skipped.splice(i, 1); destroyed++; }
        }
        extra.ids = d.map((e) => e.id);
        extra.destroyed = destroyed;
      }

      if (s.status === "requested") s.status = "connected";
      if (p.k === "close") s.status = "closed";
      s.lastRecv = now;
      s.version += 1;
      // Commit only after everything checked: a tampered message never moves the ratchet.
      await this.#commit(s0, s);
      const out = { kind: p.k, id: p.nonce, body, at: p.at, n: h.n, ttlMs: ttl, live, duress: p.d === 1, stamped: !!p.st, ...extra };
      if (text !== undefined) out.text = text;
      return out;
    })));
  }

  /**
   * Messages known to be missing: a later one arrived, these didn't, for longer
   * than `olderThanMs`. A relay that drops messages is caught this way.
   */
  gaps({ now = Date.now(), olderThanMs = 10 * 60_000 } = {}) {
    const late = this.s.skipped.filter((e) => now - e[2] >= olderThanMs);
    return { missing: late.length, oldestSince: late.length ? Math.min(...late.map((e) => e[2])) : null };
  }

  /**
   * Delete the conversation's keys from this device. Every secret in the state
   * (root and chain keys, ratchet private keys, mailbox and wire keys, keys kept
   * for late messages) is overwritten with zeros, and the session refuses all
   * further use. The app then deletes its stored copy and the key that sealed it.
   */
  erase() {
    return this.#serial(() => {
      const s = this.s;
      if (s.status === "erased") return;
      wipeState(s);
      this.s = { v: 1, status: "erased", convId: s.convId, version: s.version + 1 };
    });
  }

  /* ---------- at rest ---------- */

  toJSON() { return toPlain(this.s); }
  static fromJSON(o, opts) { return new Session(fromPlain(o), opts); }
  get convId() { return this.s.convId; }

  /**
   * Seal the conversation for storage, under a key the app derives during a
   * live check (e.g. from the account seed). The version is bound in, so a
   * stored copy can't be swapped for another conversation's, and an older copy
   * is refused by openSession({ minVersion }) — rolling back the ratchet would
   * re-open message keys already used (audit SEC-A-04, applied to messaging).
   */
  async seal(stateKey) {
    if (this.s.status === "erased") throw new MsgError("erased", "This conversation was deleted");
    const head = concat(this.s.convId, u32(Math.floor(this.s.version / 2 ** 32)), u32(this.s.version >>> 0));
    const nonce = random(12);
    const ct = await aeadSeal(stateKey, nonce, encodeJSON(this.toJSON()), concat(label("state"), head));
    return concat(head, nonce, ct);
  }
}

/** Open a sealed conversation. minVersion: the highest version this device has seen for it. */
export async function openSession(stateKey, blob, { convId, minVersion = 0, persist = null } = {}) {
  return guard(async () => {
    if (!(convId instanceof Uint8Array) || convId.length !== 16) throw new MsgError("bad_request", "Say which conversation this copy should be (convId)");
    if (!(blob instanceof Uint8Array) || blob.length < 24 + 12 + 16) throw new MsgError("malformed", "Not a sealed conversation");
    const head = blob.subarray(0, 24);
    const version = readU32(head, 16) * 2 ** 32 + readU32(head, 20);
    if (!equal(head.subarray(0, 16), convId)) throw new MsgError("wrong_conversation", "Stored copy belongs to another conversation");
    if (version < minVersion) throw new MsgError("rolled_back", "This is an older copy of the conversation. Refusing it.");
    const pt = await aeadOpen(stateKey, blob.subarray(24, 36), blob.subarray(36), concat(label("state"), head), "decrypt_failed");
    const session = Session.fromJSON(decodeJSON(pt), { persist });
    if (session.version !== version || !equal(session.s.convId, head.subarray(0, 16))) throw new MsgError("malformed", "Stored copy is inconsistent");
    return session;
  });
}

/** Forget skipped message keys older than SKIPPED_TTL_MS: the relay has dropped those messages by then anyway. */
function expireSkipped(s, now) {
  const keep = [];
  for (const e of s.skipped) { if (now - e[2] < SKIPPED_TTL_MS) keep.push(e); else wipe(e[1]); }
  if (keep.length !== s.skipped.length) s.skipped = keep;
}

function skip(s, until, now = Date.now()) {
  if (!s.CKr) return;
  if (until - s.Nr > MAX_SKIP) throw new MsgError("too_many_skipped", "Too many messages missing");
  while (s.Nr < until) {
    const [mk, next] = kdfCk(s.CKr);
    s.skipped.push([`${toHex(s.DHr)}:${s.Nr}`, mk, now]);
    s.CKr = next; s.Nr += 1;
  }
  while (s.skipped.length > MAX_SKIPPED_TOTAL) { const [, old] = s.skipped.shift(); wipe(old); }
}
