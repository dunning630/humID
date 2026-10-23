// HTP/1 server core: static keys, session table, frame open/seal. Transport
// agnostic; the gateway service wires it to HTTP.

import { serverRespond, keyId, fingerprint, generateServerKeys, HELLO_SKEW_MS } from "./handshake.js";
import { sealFrame, openFrame, parseHeader, DIR, FRAME_SKEW_MS } from "./frame.js";
import { ReplayWindow } from "./replay.js";
import { ml_dsa87, b64u, unb64u, toHex, wipe } from "./primitives.js";
import { policyMessage, canonicalJson } from "./proofs.js";

export class HtpServerError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

export const SESSION_IDLE_MS = 15 * 60 * 1000;
export const SESSION_MAX_MS = 8 * 60 * 60 * 1000;
/** A signed policy hint is re-signed this often (one ML-DSA-87 signature, not one per request). */
export const POLICY_RESIGN_MS = 60 * 60 * 1000;

/** Create a full static key set (KEM + X25519 for the handshake, ML-DSA-87 for signed statements). */
export function createStatics() {
  const k = generateServerKeys();
  const dsa = ml_dsa87.keygen();
  return withKid({ ...k, dsaPk: dsa.publicKey, dsaSk: dsa.secretKey });
}

const withKid = (s) => ({ ...s, kid: keyId(s.kemPk, s.xPk, s.dsaPk) });

export const exportStatics = (s) =>
  Object.fromEntries(["kemPk", "kemSk", "xPk", "xSk", "dsaPk", "dsaSk"].map((k) => [k, b64u(s[k])]));
export const importStatics = (j) =>
  withKid(Object.fromEntries(["kemPk", "kemSk", "xPk", "xSk", "dsaPk", "dsaSk"].map((k) => [k, unb64u(j[k])])));

/** A session that hasn't signed in (no `subject`) is dropped after this long without a call. */
export const PENDING_IDLE_MS = 2 * 60 * 1000;
/** Sessions that haven't signed in, per client group (an IPv4 address or an IPv6 /64). */
export const PENDING_PER_GROUP = 20;

export class HtpServer {
  /**
   * maxSessions: the whole table. When it's full, the session that hasn't signed in and was
   * used least recently makes room; only a table full of signed-in sessions answers `busy`.
   * pendingPerGroup / pendingIdleMs: how many sessions one client group may hold before
   * signing in, and how long one may sit unused (CRYPTO-04).
   */
  constructor(statics, { maxSessions = 50_000, idleMs = SESSION_IDLE_MS, maxMs = SESSION_MAX_MS, pendingIdleMs = PENDING_IDLE_MS, pendingPerGroup = PENDING_PER_GROUP } = {}) {
    this.statics = statics;
    this.sessions = new Map();
    this.maxSessions = maxSessions;
    this.idleMs = idleMs;
    this.maxMs = maxMs;
    this.pendingIdleMs = pendingIdleMs;
    this.pendingPerGroup = pendingPerGroup;
    // Client nonces of accepted hellos, until the hello's time window closes: a captured hello
    // can't be replayed to make the server do the handshake work and hold a slot again.
    this.helloNonces = new Map(); // nC -> expires
    this.maxHelloNonces = maxSessions * 4;
  }

  get kid() { return toHex(this.statics.kid); }
  get fingerprint() { return fingerprint(this.statics.kid); }

  publicKeys() {
    const s = this.statics;
    return { v: 1, kid: this.kid, fingerprint: this.fingerprint, kem: b64u(s.kemPk), x25519: b64u(s.xPk), dsa: b64u(s.dsaPk) };
  }

  /**
   * The policy hint with the server's ML-DSA-87 signature, for GET /htp/v1/keys:
   * { policy, policySig: { at, sig } }. Signed once and re-used until the policy
   * changes or the signature is an hour old, so a public route costs no signing.
   */
  signedPolicy(policy, now = Date.now()) {
    const text = canonicalJson(policy);
    const c = this.policyCache;
    if (!c || c.text !== text || now - c.at > POLICY_RESIGN_MS || now < c.at) {
      const sig = ml_dsa87.sign(policyMessage(this.statics.kid, policy, now), this.statics.dsaSk);
      this.policyCache = { text, at: now, sig: b64u(sig) };
    }
    return { policy, policySig: { at: this.policyCache.at, sig: this.policyCache.sig } };
  }

  /**
   * Answer a ClientHello. `group`: who it comes from for fairness (the gateway passes the
   * client's IPv4 address or IPv6 /64), so one network can't take every slot.
   */
  hello(wire, now = Date.now(), { group = "" } = {}) {
    this.sweep(now);
    const nC = typeof wire?.nC === "string" ? wire.nC : "";
    if (nC && this.helloNonces.has(nC)) throw new HtpServerError(409, "replay", "This handshake was already used.");
    this.makeRoom(group);
    let out;
    try { out = serverRespond(this.statics, wire, { ttlMs: this.maxMs, now }); }
    catch (e) { throw new HtpServerError(400, "handshake_rejected", e.message); }
    this.rememberHello(nC, Number(wire.ts) + HELLO_SKEW_MS, now);
    const s = out.session;
    this.sessions.set(s.sidText, {
      ...s, createdAt: now, touchedAt: now, replay: new ReplayWindow(), group: String(group),
      subject: null, dsaPk: null, assurance: null, challenge: null, authAt: null,
    });
    return out.wire;
  }

  /** Free a slot for a new session from `group`, or refuse when only signed-in sessions are left. */
  makeRoom(group) {
    let mine = 0, oldestMine = null, oldest = null;
    for (const x of this.sessions.values()) {
      if (x.subject) continue;
      if (!oldest || x.touchedAt < oldest.touchedAt) oldest = x;
      if (x.group === String(group)) { mine++; if (!oldestMine || x.touchedAt < oldestMine.touchedAt) oldestMine = x; }
    }
    // A group at its limit makes room from its own sessions, never anyone else's.
    if (mine >= this.pendingPerGroup && oldestMine) { this.drop(oldestMine); return; }
    if (this.sessions.size < this.maxSessions) return;
    if (!oldest) throw new HtpServerError(503, "busy", "Too many sessions");
    this.drop(oldest);
  }

  rememberHello(nC, expires, now) {
    if (!nC) return;
    this.helloNonces.set(nC, expires);
    if (this.helloNonces.size <= this.maxHelloNonces) return;
    for (const [k, exp] of this.helloNonces) { if (exp < now || this.helloNonces.size > this.maxHelloNonces) this.helloNonces.delete(k); else break; }
  }

  /** Authenticate and decrypt a request frame. */
  async open(frameBytes, now = Date.now()) {
    let parsed;
    try { parsed = parseHeader(frameBytes); } catch (e) { throw new HtpServerError(400, "bad_frame", e.message); }
    if (parsed.dir !== DIR.request) throw new HtpServerError(400, "bad_frame", "Not a request frame");
    const session = this.sessions.get(b64u(parsed.sid));
    if (!session) throw new HtpServerError(401, "session_unknown", "Unknown session; handshake again.");
    if (now > session.expiresAt || now - session.touchedAt > (session.subject ? this.idleMs : Math.min(this.idleMs, this.pendingIdleMs))) {
      this.drop(session);
      throw new HtpServerError(401, "session_expired", "Session expired; handshake again.");
    }
    if (Math.abs(now - parsed.ts) > FRAME_SKEW_MS) throw new HtpServerError(400, "stale_frame", "Frame timestamp outside window.");
    let opened;
    try { opened = await openFrame(session.c2s, parsed); }
    catch (e) {
      if (e?.code === "meta_too_large") throw new HtpServerError(413, "too_large", "Request headers are too large.");
      throw new HtpServerError(400, "bad_frame", "Frame failed authentication.");
    }
    // Replay check only after the frame proves it came from the session holder.
    if (!session.replay.accept(parsed.seq)) throw new HtpServerError(409, "replay", "Sequence number already used.");
    session.touchedAt = now;
    return { session, seq: parsed.seq, meta: opened.meta, body: opened.body };
  }

  seal(session, seq, status, headers, body) {
    return sealFrame(session.s2c, DIR.response, session.sid, seq, { s: status, h: headers || {} }, body);
  }

  drop(session) {
    wipe(session.c2s, session.s2c);
    this.sessions.delete(session.sidText);
  }

  sweep(now = Date.now()) {
    for (const s of this.sessions.values()) {
      if (now > s.expiresAt || now - s.touchedAt > (s.subject ? this.idleMs : Math.min(this.idleMs, this.pendingIdleMs))) this.drop(s);
    }
    for (const [k, exp] of this.helloNonces) if (exp < now) this.helloNonces.delete(k);
  }
}

export { generateServerKeys };
