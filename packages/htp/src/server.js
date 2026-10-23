// HTP/1 server core: static keys, session table, frame open/seal. Transport
// agnostic; the gateway service wires it to HTTP.

import { serverRespond, keyId, fingerprint, generateServerKeys } from "./handshake.js";
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

export class HtpServer {
  constructor(statics, { maxSessions = 50_000, idleMs = SESSION_IDLE_MS, maxMs = SESSION_MAX_MS } = {}) {
    this.statics = statics;
    this.sessions = new Map();
    this.maxSessions = maxSessions;
    this.idleMs = idleMs;
    this.maxMs = maxMs;
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

  hello(wire, now = Date.now()) {
    this.sweep(now);
    if (this.sessions.size >= this.maxSessions) throw new HtpServerError(503, "busy", "Too many sessions");
    let out;
    try { out = serverRespond(this.statics, wire, { ttlMs: this.maxMs, now }); }
    catch (e) { throw new HtpServerError(400, "handshake_rejected", e.message); }
    const s = out.session;
    this.sessions.set(s.sidText, {
      ...s, createdAt: now, touchedAt: now, replay: new ReplayWindow(),
      subject: null, dsaPk: null, assurance: null, challenge: null, authAt: null,
    });
    return out.wire;
  }

  /** Authenticate and decrypt a request frame. */
  async open(frameBytes, now = Date.now()) {
    let parsed;
    try { parsed = parseHeader(frameBytes); } catch (e) { throw new HtpServerError(400, "bad_frame", e.message); }
    if (parsed.dir !== DIR.request) throw new HtpServerError(400, "bad_frame", "Not a request frame");
    const session = this.sessions.get(b64u(parsed.sid));
    if (!session) throw new HtpServerError(401, "session_unknown", "Unknown session; handshake again.");
    if (now > session.expiresAt || now - session.touchedAt > this.idleMs) {
      this.drop(session);
      throw new HtpServerError(401, "session_expired", "Session expired; handshake again.");
    }
    if (Math.abs(now - parsed.ts) > FRAME_SKEW_MS) throw new HtpServerError(400, "stale_frame", "Frame timestamp outside window.");
    let opened;
    try { opened = await openFrame(session.c2s, parsed); }
    catch { throw new HtpServerError(400, "bad_frame", "Frame failed authentication."); }
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
      if (now > s.expiresAt || now - s.touchedAt > this.idleMs) this.drop(s);
    }
  }
}

export { generateServerKeys };
