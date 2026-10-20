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
  encodeJSON, decodeJSON, aeadSeal, aeadOpen, dayOf, utf8, fromUtf8, guard,
} from "./util.js";
import { pad, unpad, checkWire, WIRE_VERSION, boxFor, pollDays } from "./wire.js";

export const MAX_SKIP = 1000;        // per chain step
export const MAX_SKIPPED_TOTAL = 2000;
const SALT = 16;
export const HEADER_BYTES = SIZES.x + SIZES.kemCt + SIZES.kemPk + SALT + 8; // dh | kem ct | next kem ek | salt | pn | n
export const SKIPPED_TTL_MS = 14 * 24 * 3600_000; // a withheld message's key is kept no longer than the relay keeps the message
const WIRE_OVERHEAD = 1 + 12 + 16;
const NONCE = 16;
const STAMP_ROOM = 1200; // characters reserved for a stamp in every payload
export const KINDS = Object.freeze(["text", "accept", "file-key", "receipt", "close"]);
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
    this.s = next;
    if (!this.persist) return;
    try { await this.persist(this); }
    catch (e) { this.s = prev; throw new MsgError("persist_failed", `Could not save the conversation: ${e?.message || e}`); }
  }

  get peerId() { return this.s.peer.id; }
  get myId() { return this.s.me.id; }
  get safetyCode() { return this.s.safety; }
  get status() { return this.s.status; }
  get version() { return this.s.version; }
  get peerPub() { return decodePub(this.s.peer.pub); }

  /** Mailboxes to poll for this conversation. */
  inboxes(now = Date.now()) { return pollDays(now).map((d) => boxFor(this.s.recvBox, d)); }

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
   * Returns { box, wire } to post to the relay.
   */
  encrypt(kind, body, { now = Date.now(), stamper = null, duress = false } = {}) {
    return this.#serial(() => guard(async () => {
      if (!KINDS.includes(kind)) throw new MsgError("bad_kind", `Unknown message kind "${kind}"`);
      const s0 = this.s;
      if (s0.status === "closed") throw new MsgError("closed", "This conversation was closed");
      if (s0.status === "requested") throw new MsgError("not_accepted", "Your contact hasn't accepted yet");
      const bodyBytes = typeof body === "string" ? utf8(body) : body;
      if (!(bodyBytes instanceof Uint8Array) || bodyBytes.length > MAX_BODY) throw new MsgError("too_large", "Message too large");
      const nonce = random(NONCE);
      const stamp = stamper
        ? await stamper(messageCommitment({ convId: s0.convId, senderFp: s0.me.fp, nonce, kind, body: bodyBytes }))
        : null;

      const s = cloneState(this.s);
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
      const header = encodeHeader({ ...s.head, salt, pn: s.PN, n: s.Ns });
      s.Ns += 1;

      const payload = { k: kind, b: b64u(bodyBytes), at: now, nonce: b64u(nonce) };
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
      s.lastSend = now;
      s.version += 1;
      await this.#commit(s0, s);
      return { box: boxFor(s.sendBox, dayOf(now)), wire };
    }));
  }

  /**
   * Decrypt one wire object from this conversation's inbox.
   * opts.stampKeys: the server's published stamp keys (importStampKeys).
   * Returns { kind, body (bytes), text (if kind is text), at, n, live, duress }.
   *   live: true (valid stamp), false (stamp present but invalid), null (no stamp, or no keys to check).
   * Throws MsgError: not_for_us, replay_or_old, decrypt_failed, malformed, too_many_skipped, closed.
   */
  decrypt(wire, { now = Date.now(), stampKeys = null } = {}) {
    return this.#serial(() => guard(async () => {
      checkWire(wire);
      const s0 = this.s;
      const s = cloneState(s0);
      if (s.status === "closed") throw new MsgError("closed", "This conversation was closed");
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
          if (s.CKr) skip(s, h.pn, now);
          checkKemPk(h.ek);
          const ss = b.kem.decapsulate(h.ct, s.KEMs.sk);
          const dhOut = b.x25519.shared(s.DHs.sk, h.dh);
          const ikm = concat(dhOut, ss);
          [s.RK, s.CKr] = kdfRk(s.RK, ikm);
          wipe(dhOut, ss, ikm);
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
      const body = unb64u(p.b);
      const nonce = unb64u(p.nonce, NONCE);
      let live = null;
      if (p.st && stampKeys) {
        live = verifyStamp(stampKeys, p.st, messageCommitment({ convId: s.convId, senderFp: s.peer.fp, nonce, kind: p.k, body }), { now });
      }
      const text = p.k === "text" ? fromUtf8(body) : undefined; // decode before committing: bad text moves nothing

      if (s.status === "requested") s.status = "connected";
      if (p.k === "close") s.status = "closed";
      s.lastRecv = now;
      s.version += 1;
      // Commit only after everything checked: a tampered message never moves the ratchet.
      await this.#commit(s0, s);
      const out = { kind: p.k, body, at: p.at, n: h.n, live, duress: p.d === 1, stamped: !!p.st };
      if (text !== undefined) out.text = text;
      return out;
    }));
  }

  /**
   * Messages known to be missing: a later one arrived, these didn't, for longer
   * than `olderThanMs`. A relay that drops messages is caught this way.
   */
  gaps({ now = Date.now(), olderThanMs = 10 * 60_000 } = {}) {
    const late = this.s.skipped.filter((e) => now - e[2] >= olderThanMs);
    return { missing: late.length, oldestSince: late.length ? Math.min(...late.map((e) => e[2])) : null };
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

/* Uint8Array-safe JSON for the state. */
function toPlain(v) {
  if (v instanceof Uint8Array) return { $b: b64u(v) };
  if (Array.isArray(v)) return v.map(toPlain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toPlain(x)]));
  return v;
}
function fromPlain(v) {
  if (v && typeof v === "object" && !Array.isArray(v) && typeof v.$b === "string" && Object.keys(v).length === 1) return unb64u(v.$b);
  if (Array.isArray(v)) return v.map(fromPlain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fromPlain(x)]));
  return v;
}
