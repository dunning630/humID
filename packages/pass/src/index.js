// @humid/pass — anonymous access passes. Paying for HumID must not tell HumID
// who paid. The person buys an access code (cash at a counter, or any online
// store), and the app swaps it for a PASS: a value the server signs without
// seeing it (a blind signature). At registration the app spends the pass. The
// server can check its own signature, but it never saw the pass before, so it
// cannot tell which code, purchase or person it came from.
//
// Blind signatures: RFC 9474, RSABSSA-SHA384-PSS-Randomized.
//   Blind     (app)     encode the pass, multiply by r^e        → blinded
//   BlindSign (server)  blinded^d                               → blind signature
//   Finalize  (app)     multiply by r^-1, verify RSASSA-PSS     → signature
// Blindness is unconditional: every pass is equally likely to have come from
// every blinded request, whatever the signer computes, now or later, quantum or
// not. Forging a pass is what RSA protects; keys rotate yearly.
//
// This module holds no private key. The signer is @humid/pass/issuer (Node,
// OpenSSL) and @humid/pass/jwk (the in-app simulation only).

import { sha384, sha256 } from "@noble/hashes/sha2.js";

export const SUITE = "RSABSSA-SHA384-PSS-Randomized";
export const PASS_VERSION = 1;
export const MIN_BITS = 2048;
/** Never trust more issuer keys than this at once: a server handing each person their own key could tag them. */
export const MAX_KEYS = 2;
const H_LEN = 48;   // SHA-384
const S_LEN = 48;   // salt = hash length (RFC 9474 §5)
const PREFIX = 32;  // the "Randomized" variant's message prefix
const NONCE = 32;
const LABEL = new TextEncoder().encode("HUMID-PASS-v1\0");

/* ---------------- bytes and integers ---------------- */

export const b64u = (b) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const unb64u = (s) => {
  const t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  const o = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i);
  return o;
};
export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const concat = (...xs) => {
  const o = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of xs) { o.set(x, i); i += x.length; }
  return o;
};
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
export const os2ip = (b) => (b.length ? BigInt(`0x${toHex(b)}`) : 0n);
export function i2osp(x, len) {
  if (x < 0n || x >= 1n << BigInt(8 * len)) throw new PassError("integer_too_large", "Integer too large for its encoding");
  const o = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; }
  return o;
}
export function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function modInv(a, m) {
  let [r0, r1, t0, t1] = [m, a % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
  if (r0 !== 1n) throw new PassError("not_invertible", "Value is not invertible modulo n");
  return t0 < 0n ? t0 + m : t0;
}
const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
const bitLen = (x) => x.toString(2).length;

export class PassError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

/* ---------------- EMSA-PSS (RFC 8017 §9.1) with SHA-384 / MGF1-SHA-384 ---------------- */

function mgf1(seed, len) {
  const out = new Uint8Array(len);
  for (let c = 0, off = 0; off < len; c++) {
    const block = sha384(concat(seed, i2osp(BigInt(c), 4)));
    out.set(block.subarray(0, Math.min(H_LEN, len - off)), off);
    off += H_LEN;
  }
  return out;
}

export function pssEncode(msg, emBits, salt = randomBytes(S_LEN)) {
  const emLen = Math.ceil(emBits / 8);
  if (emLen < H_LEN + S_LEN + 2) throw new PassError("key_too_small", "Key too small for PSS");
  const h = sha384(concat(new Uint8Array(8), sha384(msg), salt));
  const db = new Uint8Array(emLen - H_LEN - 1);
  db[emLen - S_LEN - H_LEN - 2] = 0x01;
  db.set(salt, emLen - S_LEN - H_LEN - 1);
  const mask = mgf1(h, db.length);
  for (let i = 0; i < db.length; i++) db[i] ^= mask[i];
  db[0] &= 0xff >> (8 * emLen - emBits);
  return concat(db, h, Uint8Array.of(0xbc));
}

export function pssVerify(msg, em, emBits) {
  const emLen = Math.ceil(emBits / 8);
  if (em.length !== emLen || emLen < H_LEN + S_LEN + 2 || em[emLen - 1] !== 0xbc) return false;
  const top = 0xff >> (8 * emLen - emBits);
  const masked = em.subarray(0, emLen - H_LEN - 1);
  const h = em.subarray(emLen - H_LEN - 1, emLen - 1);
  if (masked[0] & ~top & 0xff) return false;
  const mask = mgf1(h, masked.length);
  const db = masked.map((x, i) => x ^ mask[i]);
  db[0] &= top;
  const ps = emLen - H_LEN - S_LEN - 2;
  for (let i = 0; i < ps; i++) if (db[i] !== 0) return false;
  if (db[ps] !== 0x01) return false;
  const h2 = sha384(concat(new Uint8Array(8), sha384(msg), db.subarray(db.length - S_LEN)));
  let d = 0;
  for (let i = 0; i < H_LEN; i++) d |= h[i] ^ h2[i];
  return d === 0;
}

/* ---------------- issuer public keys ---------------- */

/** An issuer key id commits to n and e, so the app computes it itself: a server can't relabel keys. */
export function keyIdOf(nBytes, eBytes) {
  return toHex(sha256(concat(new TextEncoder().encode("HUMID-PASS-KEY-v1\0"), i2osp(BigInt(nBytes.length), 4), nBytes, eBytes)));
}

/**
 * Import a published key { id, n, e, issuing?, acceptUntil? } (n, e base64url, big-endian).
 * Throws if the id doesn't match, the key is too small, or e is not 65537.
 */
export function importKey(pub) {
  const nB = unb64u(pub.n), eB = unb64u(pub.e);
  const n = os2ip(nB), e = os2ip(eB);
  const bits = bitLen(n);
  if (bits < MIN_BITS || nB[0] === 0) throw new PassError("bad_key", "Issuer key is too small or malformed");
  if (e !== 65537n) throw new PassError("bad_key", "Issuer key must use e = 65537");
  const id = keyIdOf(nB, eB);
  if (pub.id !== undefined && String(pub.id).toLowerCase() !== id) throw new PassError("bad_key", "Issuer key id does not match the key");
  return { id, n, e, bits, k: nB.length, issuing: !!pub.issuing, acceptUntil: pub.acceptUntil ?? null, n64: b64u(nB), e64: b64u(eB) };
}

/**
 * The server's published key set, as the app accepts it. More than MAX_KEYS keys,
 * or more than one issuing key, means the server could be sorting people into
 * groups by key, so the app refuses to use it.
 */
export function importKeySet(list) {
  if (!Array.isArray(list) || list.length === 0) throw new PassError("no_keys", "This server publishes no access-pass keys");
  if (list.length > MAX_KEYS) throw new PassError("too_many_keys", "This server publishes more pass keys than HumID allows. Refusing, to protect your anonymity.");
  const keys = list.map(importKey);
  if (new Set(keys.map((k) => k.id)).size !== keys.length) throw new PassError("bad_key", "Duplicate pass keys");
  const issuing = keys.filter((k) => k.issuing);
  if (issuing.length !== 1) throw new PassError("bad_key", "The server must name exactly one issuing key");
  return { keys, issuing: issuing[0] };
}

/* ---------------- the pass ---------------- */

/** The message a pass signs: label ‖ key id ‖ nonce. Binding the key id stops a pass moving between keys. */
const passMessage = (kidHex, nonce) => {
  const kid = new Uint8Array(kidHex.match(/../g).map((h) => parseInt(h, 16)));
  return concat(LABEL, kid, nonce);
};
const INPUT_LEN = PREFIX + LABEL.length + 32 + NONCE;

/**
 * Step 1 (app): make a new pass and blind it for `key`.
 * Returns { draft, blinded }. Keep `draft` (persist it) until finalize: if the app
 * dies mid-request, it can resend the same `blinded` and still get its pass.
 */
export function blind(key) {
  const input = concat(randomBytes(PREFIX), passMessage(key.id, randomBytes(NONCE)));
  const m = os2ip(pssEncode(input, key.bits - 1));
  if (gcd(m, key.n) !== 1n) throw new PassError("not_coprime", "Pick a new pass"); // negligible; RFC 9474 §4.2 step 3
  let r;
  do {
    const b = randomBytes(key.k);
    b[0] &= 0xff >> (8 * key.k - key.bits);
    r = os2ip(b);
  } while (r === 0n || r >= key.n || gcd(r, key.n) !== 1n);
  const inv = modInv(r, key.n);
  const z = (m * modPow(r, key.e, key.n)) % key.n;
  const blinded = i2osp(z, key.k);
  return {
    blinded,
    draft: { v: PASS_VERSION, kid: key.id, input: b64u(input), inv: inv.toString(16), blinded: b64u(blinded) },
  };
}

/** Step 3 (app): unblind the server's answer and check it. Returns the pass, ready to spend. */
export function finalize(key, draft, blindSig) {
  if (draft.kid !== key.id) throw new PassError("wrong_key", "Pass was blinded for another key");
  const z = os2ip(blindSig);
  if (blindSig.length !== key.k || z >= key.n) throw new PassError("bad_signature", "The server's signature is malformed");
  const s = (z * BigInt(`0x${draft.inv}`)) % key.n;
  const pass = { v: PASS_VERSION, kid: key.id, input: draft.input, sig: b64u(i2osp(s, key.k)) };
  if (!verifyPass(key, pass)) throw new PassError("bad_signature", "The server's signature did not check out. Your access code may not have been accepted.");
  return pass;
}

/** Anyone holding the public key can check a pass (RSASSA-PSS-VERIFY). */
export function verifyPass(key, pass) {
  try {
    if (pass?.v !== PASS_VERSION || pass.kid !== key.id) return false;
    const input = unb64u(pass.input), sig = unb64u(pass.sig);
    if (input.length !== INPUT_LEN || sig.length !== key.k) return false;
    const label = input.subarray(PREFIX, PREFIX + LABEL.length);
    if (!label.every((x, i) => x === LABEL[i])) return false;
    if (toHex(input.subarray(PREFIX + LABEL.length, PREFIX + LABEL.length + 32)) !== key.id) return false;
    const s = os2ip(sig);
    if (s >= key.n) return false;
    const emLen = Math.ceil((key.bits - 1) / 8);
    const m = modPow(s, key.e, key.n);
    if (m >= 1n << BigInt(8 * emLen)) return false;
    return pssVerify(input, i2osp(m, emLen), key.bits - 1);
  } catch { return false; }
}

/** What the server stores once a pass is spent: a hash of the pass, nothing else. */
export const spentId = (pass) => toHex(sha256(unb64u(pass.input)));

/* ---------------- access codes (what a person buys) ---------------- */
// 22 random characters (110 bits) + 2 check characters, Crockford base32,
// shown as HA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. Typos are caught on the phone.

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_DATA = 22;
const check2 = (data) => {
  const h = sha256(new TextEncoder().encode(`HUMID-ACCESS-v1 ${data}`));
  return B32[h[0] & 31] + B32[h[1] & 31];
};

/** New access code (operators: minting; tests). */
export function newAccessCode() {
  const r = randomBytes(CODE_DATA);
  const data = Array.from(r, (x) => B32[x & 31]).join("");
  return formatAccessCode(data + check2(data));
}

export const formatAccessCode = (c) => `HA-${c.match(/.{4}/g).join("-")}`;

/** Normalise what a person typed. Returns the 24 characters, or null if it isn't a valid code. */
export function parseAccessCode(input) {
  let s = String(input || "").toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  if (s.startsWith("HA") && s.length === CODE_DATA + 4) s = s.slice(2);
  if (s.length !== CODE_DATA + 2 || [...s].some((ch) => !B32.includes(ch))) return null;
  return check2(s.slice(0, CODE_DATA)) === s.slice(CODE_DATA) ? s : null;
}

/** What the server stores for a code: its hash (110 random bits: not guessable from the hash). */
export const accessCodeHash = (parsed) => toHex(sha256(new TextEncoder().encode(`HUMID-ACCESS-v1 ${parsed}`)));
