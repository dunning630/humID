// COSE (RFC 9052) as ISO/IEC 18013-5 uses it: COSE_Sign1 for the issuer's
// signature over the Mobile Security Object and the device's signature over
// DeviceAuthentication, COSE_Mac0 for device MACs, and EC2 / OKP COSE_Key.

import { p256, p384, p521 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from "@noble/curves/misc.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { encode, decode, get, Encoded } from "./cbor.js";

export class CoseError extends Error {}
const fail = (m) => { throw new CoseError(m); };

export const ALG = { ES256: -7, ES384: -35, ES512: -36, EdDSA: -8, HMAC256: 5 };
const HASH_OF = { [-7]: sha256, [-35]: sha384, [-36]: sha512 };
const CRV = { 1: p256, 2: p384, 3: p521, 8: brainpoolP256r1, 10: brainpoolP384r1, 11: brainpoolP512r1 };
const CRV_NAME = { 1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519", 8: "brainpoolP256r1", 10: "brainpoolP384r1", 11: "brainpoolP512r1" };
const H = { alg: 1, x5chain: 33 };
const EMPTY = new Uint8Array(0);

/** COSE_Key (EC2 kty 2, OKP kty 1) → { crv, curve, publicKey (SEC1 uncompressed, or 32-byte Ed25519) }. */
export function coseKey(key) {
  const k = key instanceof Encoded ? key.value : key;
  const kty = get(k, 1), crv = get(k, -1);
  if (kty === 2) {
    const curve = CRV[crv];
    if (!curve) fail("unsupported key curve");
    const x = get(k, -2), y = get(k, -3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) fail("compressed or malformed EC key");
    const pub = new Uint8Array(1 + x.length + y.length);
    pub[0] = 4; pub.set(x, 1); pub.set(y, 1 + x.length);
    try { curve.Point.fromBytes(pub); } catch { fail("the key isn't a point on its curve"); }
    return { kty, crv, crvName: CRV_NAME[crv], curve, publicKey: pub };
  }
  if (kty === 1 && crv === 6) {
    const x = get(k, -2);
    if (!(x instanceof Uint8Array) || x.length !== 32) fail("malformed Ed25519 key");
    return { kty, crv, crvName: "Ed25519", curve: ed25519, publicKey: x };
  }
  fail("unsupported key type");
}

/** An EC2 COSE_Key map for a SEC1 uncompressed public key. */
export function ecCoseKey(pub, crv = 1) {
  const n = (pub.length - 1) / 2;
  return new Map([[1, 2], [-1, crv], [-2, pub.slice(1, 1 + n)], [-3, pub.slice(1 + n)]]);
}

/** Split a COSE_Sign1 / COSE_Mac0 array, decoding its protected header. */
export function parse1(msg) {
  const m = msg instanceof Uint8Array ? decode(msg) : msg;
  if (!Array.isArray(m) || m.length !== 4) fail("not a COSE_Sign1 / COSE_Mac0 structure");
  const [prot, unprot, payload, tag] = m;
  if (!(prot instanceof Uint8Array) || !(tag instanceof Uint8Array)) fail("malformed COSE structure");
  const protectedMap = prot.length ? decode(prot) : new Map();
  const alg = get(protectedMap, H.alg) ?? get(unprot, H.alg);
  return { protectedBytes: prot, protectedMap, unprotected: unprot instanceof Map ? unprot : new Map(), payload, tag, alg };
}

/** The x5chain header (label 33): one certificate or several, leaf first. */
export function x5chain(parsed) {
  const v = get(parsed.protectedMap, H.x5chain) ?? get(parsed.unprotected, H.x5chain);
  if (v instanceof Uint8Array) return [v];
  if (Array.isArray(v) && v.every((c) => c instanceof Uint8Array)) return v;
  return [];
}

const toBeSigned = (p, payload, aad) => encode(["Signature1", p.protectedBytes, aad || EMPTY, payload]);
const toBeMaced = (p, payload, aad) => encode(["MAC0", p.protectedBytes, aad || EMPTY, payload]);

/** The algorithm must be in the PROTECTED header (ISO 18013-5 9.1.3.6 / 9.1.2.4). */
function protectedAlg(p) {
  const a = get(p.protectedMap, H.alg);
  if (a == null) fail("the signature algorithm isn't protected");
  return a;
}

/**
 * The bytes a signature or MAC must cover. When the caller supplies `detached` (the session's own
 * DeviceAuthentication), that is what is checked, and a structure that carries a payload of its
 * own is refused: otherwise a holder proof captured from another session verified against the
 * payload the attacker attached (review 2026-10-23, CRED-01).
 */
function payloadOf(p, detached) {
  if (detached !== undefined) {
    if (p.payload != null) fail("the payload must be detached here");
    if (!(detached instanceof Uint8Array)) fail("no payload to verify");
    return detached;
  }
  if (!(p.payload instanceof Uint8Array)) fail("no payload to verify");
  return p.payload;
}

/**
 * Verify a COSE_Sign1. key: { curve, publicKey, crv? }. detached: the payload
 * when the structure carries nil (DeviceSignature).
 */
export function verifySign1(msg, key, { detached, aad } = {}) {
  const p = msg.protectedBytes ? msg : parse1(msg);
  const alg = protectedAlg(p);
  const payload = payloadOf(p, detached);
  const data = toBeSigned(p, payload, aad);
  try {
    if (alg === ALG.EdDSA) return key.curve === ed25519 && ed25519.verify(p.tag, data, key.publicKey);
    const hash = HASH_OF[alg];
    if (!hash || key.curve === ed25519) return false;
    return key.curve.verify(p.tag, hash(data), key.publicKey, { prehash: false, lowS: false, format: "compact" });
  } catch { return false; }
}

/** Verify a COSE_Mac0 with HMAC-SHA-256 (alg 5) under `macKey`. */
export function verifyMac0(msg, macKey, { detached, aad } = {}) {
  const p = msg.protectedBytes ? msg : parse1(msg);
  if (protectedAlg(p) !== ALG.HMAC256) return false;
  const payload = payloadOf(p, detached);
  const want = hmac(sha256, macKey, toBeMaced(p, payload, aad));
  return want.length === p.tag.length && want.every((x, i) => x === p.tag[i]);
}

/** Make a COSE_Sign1 (tests, simulated wallets and issuers). key: { curve, secretKey }. */
export function signSign1(payload, key, { alg = ALG.ES256, unprotected = new Map(), detached = false, aad } = {}) {
  const prot = encode(new Map([[H.alg, alg]]));
  const p = { protectedBytes: prot };
  const data = toBeSigned(p, payload, aad);
  const sig = alg === ALG.EdDSA ? ed25519.sign(data, key.secretKey)
    : key.curve.sign(HASH_OF[alg](data), key.secretKey, { prehash: false, format: "compact" });
  return [prot, unprotected, detached ? null : payload, sig];
}

/** Make a COSE_Mac0 with HMAC-SHA-256. */
export function macMac0(payload, macKey, { detached = true, aad } = {}) {
  const prot = encode(new Map([[H.alg, ALG.HMAC256]]));
  const tag = hmac(sha256, macKey, toBeMaced({ protectedBytes: prot }, payload, aad));
  return [prot, new Map(), detached ? null : payload, tag];
}
