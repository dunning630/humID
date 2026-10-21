// CTAP 2.1 client: the authenticator commands HumID needs, the PIN/UV auth protocols,
// and the hmac-secret extension. Everything here is checked against what the spec says
// the key must send back; anything else is refused before it's used.
import { p256 } from "@noble/curves/nist.js";
import { cbc } from "@noble/ciphers/aes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { encode, decode, decodeFirst } from "./cbor.js";
import { selectFido, ctapMessage } from "./nfc.js";
import { FidoError, statusError } from "./errors.js";

export const CMD = Object.freeze({ makeCredential: 0x01, getAssertion: 0x02, getInfo: 0x04, clientPin: 0x06, getNextAssertion: 0x08 });
const PIN_SUB = Object.freeze({ getRetries: 0x01, getKeyAgreement: 0x02, setPin: 0x03, getPinToken: 0x05, getTokenWithPermissions: 0x09 });
export const PERMISSION = Object.freeze({ makeCredential: 0x01, getAssertion: 0x02 });
export const FLAG = Object.freeze({ UP: 0x01, UV: 0x04, AT: 0x40, ED: 0x80 });
const ES256 = -7;

const te = new TextEncoder();
export const wipe = (...bs) => { for (const b of bs) if (b && b.fill) b.fill(0); };
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const equal = (a, b) => {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};
const bad = (what) => new FidoError("bad_response", `The key's answer was malformed (${what}).`);
const bytesOf = (v, what, len) => {
  if (!(v instanceof Uint8Array) || (len !== undefined && v.length !== len)) throw bad(what);
  return v;
};

/* ---------------- PIN/UV auth protocols (CTAP 2.1 §6.5.6, §6.5.7) ---------------- */

/** A shared secret with the key, from ECDH, for one protocol. */
class Shared {
  constructor(protocol, z) {
    this.protocol = protocol;
    if (protocol === 1) {
      this.key = sha256(z);
    } else if (protocol === 2) {
      const salt = new Uint8Array(32);
      this.key = concat(hkdf(sha256, z, salt, te.encode("CTAP2 HMAC key"), 32), hkdf(sha256, z, salt, te.encode("CTAP2 AES key"), 32));
    } else throw new FidoError("unsupported_protocol", "This key uses a PIN protocol HumID doesn't know.");
  }
  get aesKey() { return this.protocol === 1 ? this.key : this.key.subarray(32, 64); }
  get hmacKey() { return this.protocol === 1 ? this.key : this.key.subarray(0, 32); }
  encrypt(plain) {
    if (this.protocol === 1) return cbc(this.aesKey, new Uint8Array(16), { disablePadding: true }).encrypt(plain);
    const iv = random(16);
    return concat(iv, cbc(this.aesKey, iv, { disablePadding: true }).encrypt(plain));
  }
  decrypt(ct) {
    if (this.protocol === 1) {
      if (ct.length % 16) throw bad("ciphertext length");
      return cbc(this.aesKey, new Uint8Array(16), { disablePadding: true }).decrypt(ct);
    }
    if (ct.length < 32 || ct.length % 16) throw bad("ciphertext length");
    return cbc(this.aesKey, ct.subarray(0, 16), { disablePadding: true }).decrypt(ct.subarray(16));
  }
  /** authenticate(key, message): with the shared secret's HMAC key. */
  authenticate(message) { return authenticate(this.protocol, this.hmacKey, message); }
  wipe() { wipe(this.key); }
}

/** pinUvAuthParam: HMAC-SHA-256, truncated to 16 bytes in protocol 1. */
export function authenticate(protocol, key, message) {
  const mac = hmac(sha256, key, message);
  return protocol === 1 ? mac.slice(0, 16) : mac;
}

/** The authenticator's COSE key-agreement key (ECDH-ES+HKDF-256, P-256), checked on the curve. */
function coseToPoint(cose) {
  if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(-1) !== 1) throw bad("key agreement key");
  const x = bytesOf(cose.get(-2), "key agreement x", 32), y = bytesOf(cose.get(-3), "key agreement y", 32);
  const point = concat(Uint8Array.of(4), x, y);
  try { p256.Point.fromBytes(point).assertValidity(); } catch { throw bad("key agreement key is not on the curve"); }
  return point;
}
const pointToCose = (pt) => new Map([[1, 2], [3, -25], [-1, 1], [-2, pt.slice(1, 33)], [-3, pt.slice(33, 65)]]);

/* ---------------- authenticator data (WebAuthn §6.1) ---------------- */

/** { rpIdHash, flags, signCount, aaguid?, credentialId?, publicKey? (65-byte P-256 point), extensions? (Map) } */
export function parseAuthData(ad) {
  bytesOf(ad, "authenticator data");
  if (ad.length < 37) throw bad("authenticator data too short");
  const out = { rpIdHash: ad.slice(0, 32), flags: ad[32], signCount: ((ad[33] << 24) >>> 0) + (ad[34] << 16) + (ad[35] << 8) + ad[36] };
  let o = 37;
  if (out.flags & FLAG.AT) {
    if (ad.length < o + 18) throw bad("credential data too short");
    out.aaguid = ad.slice(o, o + 16); o += 16;
    const n = (ad[o] << 8) | ad[o + 1]; o += 2;
    if (n < 16 || n > 1023 || ad.length < o + n) throw bad("credential id");
    out.credentialId = ad.slice(o, o + n); o += n;
    const { value: cose, length } = decodeFirst(ad.subarray(o));
    o += length;
    if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== ES256 || cose.get(-1) !== 1) throw bad("credential public key is not ES256");
    const pt = concat(Uint8Array.of(4), bytesOf(cose.get(-2), "public key x", 32), bytesOf(cose.get(-3), "public key y", 32));
    try { p256.Point.fromBytes(pt).assertValidity(); } catch { throw bad("credential public key is not on the curve"); }
    out.publicKey = pt;
  }
  if (out.flags & FLAG.ED) {
    const { value, length } = decodeFirst(ad.subarray(o));
    if (!(value instanceof Map)) throw bad("extensions");
    out.extensions = value; o += length;
  }
  if (o !== ad.length) throw bad("trailing bytes in authenticator data");
  return out;
}

/* ---------------- the authenticator ---------------- */

export class Authenticator {
  /** Select the FIDO applet on `transport` and read the key's info. */
  static async open(transport) {
    const ctap1Only = () => new FidoError("ctap1_only", "This is an older U2F-only key. HumID needs a FIDO2 key (most keys made since 2019 are).");
    // A key that also speaks CTAP1 answers "U2F_V2" here (CTAP 2.1 §11.3.1), as YubiKey 5 NFC
    // keys do; whether it speaks CTAP2 is what getInfo says.
    const version = await selectFido(transport);
    if (version !== "FIDO_2_0" && version !== "U2F_V2") throw new FidoError("not_fido", "That isn't a FIDO2 security key.");
    const a = new Authenticator(transport);
    try { a.info = await a.getInfo(); }
    catch (e) { if (version === "U2F_V2" && ["not_fido2", "invalid_command", "sw"].includes(e.code)) throw ctap1Only(); throw e; }
    if (!a.info.versions.some((v) => v === "FIDO_2_0" || v === "FIDO_2_1")) throw ctap1Only();
    return a;
  }

  constructor(transport) { this.t = transport; this.info = null; }

  /** Send one CTAP2 command; returns the decoded CBOR map (or null for an empty success). */
  async call(cmd, params) {
    const body = params === undefined ? new Uint8Array(0) : encode(params);
    const r = await ctapMessage(this.t, cmd, body);
    if (r[0] !== 0x00) throw statusError(r[0]);
    if (r.length === 1) return null;
    let m;
    try { m = decode(r.subarray(1)); } catch (e) { throw new FidoError("bad_response", "The key's answer was malformed.", { cause: e }); }
    if (!(m instanceof Map)) throw bad("response is not a map");
    return m;
  }

  async getInfo() {
    const m = await this.call(CMD.getInfo);
    if (!m) throw bad("empty info");
    const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" || typeof x === "number") : []);
    const options = m.get(4) instanceof Map ? Object.fromEntries([...m.get(4)].filter(([k, v]) => typeof k === "string" && typeof v === "boolean")) : {};
    return {
      versions: list(m.get(1)), extensions: list(m.get(2)), aaguid: m.get(3) instanceof Uint8Array ? m.get(3) : null, options,
      maxMsgSize: typeof m.get(5) === "number" ? m.get(5) : 1024,
      pinUvAuthProtocols: list(m.get(6)).filter((p) => p === 1 || p === 2),
      minPinLength: typeof m.get(0x0d) === "number" ? m.get(0x0d) : 4,
    };
  }

  /** The PIN protocol to use: 2 if the key offers it, else 1 (CTAP 2.0 keys list none: 1). */
  get protocol() {
    const ps = this.info?.pinUvAuthProtocols || [];
    if (ps.includes(2)) return 2;
    if (ps.includes(1) || !ps.length) return 1;
    throw new FidoError("unsupported_protocol", "This key uses a PIN protocol HumID doesn't know.");
  }
  get is21() { return !!this.info?.versions.includes("FIDO_2_1"); }
  get pinSet() { return this.info?.options.clientPin === true; }
  get hasHmacSecret() { return !!this.info?.extensions.includes("hmac-secret"); }
  get hasCredProtect() { return !!this.info?.extensions.includes("credProtect"); }

  async pinRetries() {
    const m = await this.call(CMD.clientPin, new Map([[1, this.protocol], [2, PIN_SUB.getRetries]]));
    const n = m?.get(3);
    return typeof n === "number" ? n : null;
  }

  /** ECDH with the key's current key-agreement key → { shared, platformCose }. */
  async agree(protocol = this.protocol) {
    const m = await this.call(CMD.clientPin, new Map([[1, protocol], [2, PIN_SUB.getKeyAgreement]]));
    const peer = coseToPoint(m?.get(1));
    const sk = p256.utils.randomSecretKey();
    const pub = p256.getPublicKey(sk, false);
    let z;
    try { z = p256.getSharedSecret(sk, peer).slice(1, 33); }
    finally { wipe(sk); }
    const shared = new Shared(protocol, z);
    wipe(z);
    return { shared, platformCose: pointToCose(pub) };
  }

  /** Give a key without a PIN its first PIN. */
  async setPin(pin) {
    const padded = padPin(pin, this.info?.minPinLength);
    const { shared, platformCose } = await this.agree();
    try {
      const newPinEnc = shared.encrypt(padded);
      await this.call(CMD.clientPin, new Map([[1, shared.protocol], [2, PIN_SUB.setPin], [3, platformCose], [4, shared.authenticate(newPinEnc)], [5, newPinEnc]]));
      this.info = await this.getInfo();
    } finally { shared.wipe(); wipe(padded); }
  }

  /**
   * A pinUvAuthToken for `permissions` on `rpId` (CTAP 2.1: getPinUvAuthTokenUsingPinWithPermissions;
   * CTAP 2.0: getPinToken). Wrong PIN: FidoError "pin_invalid" with `retries` left.
   */
  async pinToken(pin, { permissions, rpId } = {}) {
    const p = pinBytes(pin);
    const pinHash = sha256(p).slice(0, 16);
    wipe(p);
    const { shared, platformCose } = await this.agree();
    try {
      const pinHashEnc = shared.encrypt(pinHash);
      const useP = this.is21 && this.info.options.pinUvAuthToken === true;
      const req = new Map([[1, shared.protocol], [2, useP ? PIN_SUB.getTokenWithPermissions : PIN_SUB.getPinToken], [3, platformCose], [6, pinHashEnc]]);
      if (useP) { req.set(9, permissions); if (rpId) req.set(0x0a, rpId); }
      let m;
      try { m = await this.call(CMD.clientPin, req); }
      catch (e) {
        if (e.code === "pin_invalid") {
          const left = await this.pinRetries().catch(() => null);
          if (left != null) { e.retries = left; e.message = left === 1 ? "Wrong PIN. One try left before the key locks itself for good." : `Wrong PIN. ${left} tries left before the key locks itself.`; }
        }
        throw e;
      }
      const enc = bytesOf(m?.get(2), "token");
      const token = shared.decrypt(enc);
      if (!(token.length === 32 || (shared.protocol === 1 && token.length === 16))) throw bad("token length");
      return { token, protocol: shared.protocol };
    } finally { shared.wipe(); wipe(pinHash); }
  }

  async makeCredential({ clientDataHash, rp, user, exclude, extensions, rk = true, token }) {
    const req = new Map([
      [1, clientDataHash], [2, rp], [3, user], [4, [{ alg: ES256, type: "public-key" }]],
      ...(exclude?.length ? [[5, exclude.map((id) => ({ id, type: "public-key" }))]] : []),
      ...(extensions ? [[6, extensions]] : []),
      [7, { rk }],
      ...(token ? [[8, authenticate(token.protocol, token.token, clientDataHash)], [9, token.protocol]] : []),
    ]);
    const m = await this.call(CMD.makeCredential, req);
    const authData = bytesOf(m?.get(2), "authenticator data");
    return { fmt: m.get(1), authData, parsed: parseAuthData(authData) };
  }

  /**
   * getAssertion with hmac-secret. Returns the first assertion and how many matched
   * ({ credentialId, authData, parsed, signature, userHandle, secret, count }); call
   * nextAssertion() for the rest. `secret` is the decrypted hmac-secret output.
   */
  async getAssertion({ rpId, clientDataHash, allowList, salt, token }) {
    const { shared, platformCose } = await this.agree(token?.protocol);
    this.lastShared?.wipe();
    this.lastShared = shared;
    const saltEnc = shared.encrypt(salt);
    const hs = new Map([[1, platformCose], [2, saltEnc], [3, shared.authenticate(saltEnc)], ...(shared.protocol === 2 ? [[4, 2]] : [])]);
    const req = new Map([
      [1, rpId], [2, clientDataHash],
      ...(allowList ? [[3, allowList.map((id) => ({ id, type: "public-key" }))]] : []),
      [4, { "hmac-secret": hs }],
      ...(token ? [[6, authenticate(token.protocol, token.token, clientDataHash)], [7, token.protocol]] : []),
    ]);
    const first = this.#assertion(await this.call(CMD.getAssertion, req), allowList);
    return { ...first, count: first.count ?? 1 };
  }

  async nextAssertion() {
    if (!this.lastShared) throw new FidoError("not_allowed", "No assertion to continue.");
    return this.#assertion(await this.call(CMD.getNextAssertion));
  }

  #assertion(m, allowList) {
    if (!m) throw bad("empty assertion");
    const cred = m.get(1);
    let credentialId = cred instanceof Map ? cred.get("id") : undefined;
    if (!credentialId && allowList?.length === 1) credentialId = allowList[0]; // the spec lets a key omit it then
    bytesOf(credentialId, "credential id");
    const authData = bytesOf(m.get(2), "authenticator data");
    const parsed = parseAuthData(authData);
    const signature = bytesOf(m.get(3), "signature");
    const user = m.get(4);
    const userHandle = user instanceof Map && user.get("id") instanceof Uint8Array ? user.get("id") : null;
    const count = m.get(5);
    const out = parsed.extensions?.get("hmac-secret");
    if (!(out instanceof Uint8Array)) throw new FidoError("no_hmac_secret", "This key didn't return its secret. It may not support hmac-secret.");
    const secret = this.lastShared.decrypt(out);
    if (secret.length !== 32) throw bad("hmac-secret length");
    return { credentialId, authData, parsed, signature, userHandle, secret, count: Number.isInteger(count) && count >= 1 ? count : undefined };
  }

  end() { this.lastShared?.wipe(); this.lastShared = null; }
}

/* ---------------- PINs ---------------- */

/** A PIN as CTAP wants it: NFC-normalised UTF-8, at most 63 bytes. */
export function pinBytes(pin) {
  const s = String(pin ?? "").normalize("NFC");
  const b = te.encode(s);
  if (!s.length) throw new FidoError("pin_empty", "Type the key's PIN.");
  if (b.length > 63) { wipe(b); throw new FidoError("pin_policy", "That PIN is too long for a security key (63 bytes at most)."); }
  return b;
}

/** A new PIN, checked against the key's minimum, padded to 64 bytes. */
export function padPin(pin, minLength = 4) {
  const s = String(pin ?? "").normalize("NFC");
  const points = [...s].length;
  const min = Math.max(4, minLength || 4);
  if (points < min) throw new FidoError("pin_policy", `This key needs a PIN of at least ${min} characters.`);
  const b = pinBytes(s);
  const out = new Uint8Array(64);
  out.set(b);
  wipe(b);
  return out;
}

export { equal as constantTimeEqual };
