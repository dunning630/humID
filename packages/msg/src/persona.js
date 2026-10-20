// Personas: the only identity a contact ever sees.
//
// Each contact relationship gets its own key set, derived from the account
// seed and a random 32-byte salt kept in the holder's sealed contact list:
//
//   personaSeed = HKDF-SHA3-256(accountSeed, salt, "HUMID-MSG-v1 persona", 64)
//   ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256f and X25519 keys from personaSeed
//   persona id  = "HC-" + Crockford-base32(SHA3-256(label || lp(public keys)))[0:20]   (100 bits)
//
// A persona's public keys are independent of the account's keys and of every
// other persona, so a contact learns one ID that means nothing anywhere else,
// and two contacts comparing notes cannot tell they are talking to the same
// person. Any of the holder's devices can re-derive a persona from the seed
// and the salt; forgetting the salt forgets the persona for good.

import { base32 } from "@humid/recovery";
import { backend, SIZES } from "./backend.js";
import { MsgError, kdf, H, label, lp, b64u, unb64u, wipe, random, toHex } from "./util.js";

export const PERSONA_ID_CHARS = 20;
export const SAFETY_CHARS = 20; // 100 bits. The audit flagged the 40-bit device match code (A-10); this is 2^60 times stronger.

const group = (s) => s.match(/.{1,4}/g).join("-");

export function personaFromSalt(accountSeed, salt) {
  if (!(accountSeed instanceof Uint8Array) || accountSeed.length !== 64) throw new MsgError("bad_seed", "Account seed must be 64 bytes");
  if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new MsgError("bad_seed", "Persona salt must be 32 bytes");
  const b = backend();
  const seed = kdf(accountSeed, salt, "persona", 64);
  const kemSeed = kdf(seed, undefined, "persona ml-kem-1024", SIZES.kemSeed);
  const dsaSeed = kdf(seed, undefined, "persona ml-dsa-87", SIZES.dsaSeed);
  const slhSeed = kdf(seed, undefined, "persona slh-dsa", SIZES.slhSeed);
  const xSk = kdf(seed, undefined, "persona x25519", 32);
  const kem = b.kem.keygen(kemSeed), dsa = b.dsa.keygen(dsaSeed), slh = b.slh.keygen(slhSeed);
  wipe(seed, kemSeed, dsaSeed, slhSeed);
  const keys = {
    kemPk: kem.publicKey, kemSk: kem.secretKey,
    dsaPk: dsa.publicKey, dsaSk: dsa.secretKey,
    slhPk: slh.publicKey, slhSk: slh.secretKey,
    xPk: b.x25519.publicKey(xSk), xSk,
  };
  const pub = publicOf(keys);
  return { salt, keys, pub, id: personaId(pub) };
}

/** A new persona for a new contact. Keep `salt` in the sealed contact list. */
export const newPersona = (accountSeed) => personaFromSalt(accountSeed, random(32));

export const publicOf = (k) => ({ kemPk: k.kemPk, dsaPk: k.dsaPk, slhPk: k.slhPk, xPk: k.xPk });
export const wipePersona = (p) => p?.keys && wipe(p.keys.kemSk, p.keys.dsaSk, p.keys.slhSk, p.keys.xSk);

const pubBytes = (p) => lp(p.kemPk, p.dsaPk, p.slhPk, p.xPk);
export const personaFingerprint = (p) => H(label("persona-id"), pubBytes(p));

export function personaId(pub) {
  return `HC-${group(base32(personaFingerprint(pub)).slice(0, PERSONA_ID_CHARS))}`;
}

/**
 * The code both people compare (read aloud, or one scans the other's screen).
 * It commits to both personas' full key sets. Matching codes prove no one
 * swapped keys between them, whatever channel carried the invite.
 */
export function safetyCode(a, b) {
  const [x, y] = [personaFingerprint(a), personaFingerprint(b)].sort((p, q) => (toHex(p) < toHex(q) ? -1 : 1));
  return group(base32(H(label("safety"), lp(x, y))).slice(0, SAFETY_CHARS));
}

export function encodePub(p) {
  return { kem: b64u(p.kemPk), dsa: b64u(p.dsaPk), slh: b64u(p.slhPk), x: b64u(p.xPk) };
}

export function decodePub(o) {
  if (!o || typeof o !== "object") throw new MsgError("malformed", "Missing persona");
  return {
    kemPk: unb64u(o.kem, SIZES.kemPk),
    dsaPk: unb64u(o.dsa, SIZES.dsaPk),
    slhPk: unb64u(o.slh, SIZES.slhPk),
    xPk: unb64u(o.x, SIZES.x),
  };
}

/**
 * Dual signature: ML-DSA-87 (lattice) AND SLH-DSA-SHA2-256f (hash-based).
 * Security audit, "signatures that must outlive their algorithm" and "a
 * lattice break" (T5): if lattice maths falls, a handshake still cannot be
 * forged unless SHA-2 falls too. Both must verify.
 */
export function dualSign(msgLabel, bytes, keys) {
  const b = backend();
  const m = concat2(label(msgLabel), bytes);
  return { dsa: b.dsa.sign(m, keys.dsaSk), slh: b.slh.sign(m, keys.slhSk) };
}

export function dualVerify(msgLabel, bytes, sigs, pub) {
  const b = backend();
  const m = concat2(label(msgLabel), bytes);
  if (sigs.dsa.length !== SIZES.dsaSig || sigs.slh.length !== SIZES.slhSig) return false;
  let ok = false;
  try { ok = b.dsa.verify(sigs.dsa, m, pub.dsaPk); } catch { ok = false; }
  let ok2 = false;
  try { ok2 = b.slh.verify(sigs.slh, m, pub.slhPk); } catch { ok2 = false; }
  return ok && ok2;
}

const concat2 = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
