// @humid/recovery — the pieces that let an account seed reach a new device
// without the server ever holding it. See docs/RECOVERY.md.
//
//   codes     short codes a person reads from one screen and types on another;
//             each is a hash of public keys, so a server cannot swap the keys
//   card      a printable recovery card that unlocks a backup of the seed
//   shamir    split the seed among recovery contacts; any majority rebuilds it

import { sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";

const te = new TextEncoder();
const td = new TextDecoder();
const utf8 = (s) => te.encode(s);
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const lp = (...parts) => concat(...parts.flatMap((p) => [u32(p.length), p]));

/* ---------------- base32 (Crockford): no I, L, O, U; forgiving on input ---------------- */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DECODE = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));
Object.assign(DECODE, { O: 0, I: 1, L: 1 });

export function base32(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decode exactly `nBytes` from Crockford base32. Throws on a character that is not in the alphabet. */
export function unbase32(text, nBytes) {
  let bits = 0, value = 0;
  const out = new Uint8Array(nBytes);
  let o = 0;
  for (const ch of text) {
    const v = DECODE[ch];
    if (v === undefined) throw new Error(`"${ch}" is not a valid character`);
    value = ((value << 5) | v) & 0xffff; bits += 5;
    if (bits >= 8 && o < nBytes) { out[o++] = (value >>> (bits - 8)) & 255; bits -= 8; }
  }
  if (o !== nBytes) throw new Error("Code is too short");
  return out;
}

/** Upper-case, map look-alikes, drop spaces and dashes. */
export const normalize = (s) => String(s || "").toUpperCase().replace(/[\s\-_.]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");

/* ---------------- key codes: XXXX-XXXX-XXXX ---------------- */

export const CODE_LENGTH = 12; // 60 bits

/**
 * A short code that commits to public keys. The device that shows it made the
 * keys; the device that types it recomputes the code from the keys the server
 * hands it, so a server that substituted keys is caught.
 */
export function keyCode(label, ...publicKeys) {
  return base32(sha3_256(concat(utf8(label), lp(...publicKeys)))).slice(0, CODE_LENGTH);
}

export const formatCode = (code) => normalize(code).match(/.{1,4}/g)?.join("-") ?? "";

/** Normalised 12-character code, or null if the input cannot be one. */
export function parseCode(input) {
  const c = normalize(input);
  return c.length === CODE_LENGTH && [...c].every((ch) => ch in DECODE) ? c : null;
}

export const LINK_LABEL = "HUMID-LINK-v1";       // a new device asking to join
export const OFFER_LABEL = "HUMID-CONTACT-v1";   // someone offering to be a recovery contact
export const REQUEST_LABEL = "HUMID-RECOVER-v1"; // a device asking contacts for help

/* ---------------- recovery card ---------------- */

const CARD_BYTES = 15; // 120 bits
const CARD_PREFIX = "HUMID";

// Check character: sum of c_i * a^(i+1) over GF(32) (a = generator, x^5 + x^2 + 1).
// Distinct non-zero weights catch every single-character typo and every swap
// of two neighbouring characters.
const GF32_EXP = [];
{ let v = 1; for (let i = 0; i < 31; i++) { GF32_EXP.push(v); v <<= 1; if (v & 32) v ^= 0b100101; } }
const GF32_LOG = Object.fromEntries(GF32_EXP.map((v, i) => [v, i]));
const mul32 = (a, b) => (a && b ? GF32_EXP[(GF32_LOG[a] + GF32_LOG[b]) % 31] : 0);
function checkOf(chars) {
  let s = 0;
  [...chars].forEach((ch, i) => { s ^= mul32(DECODE[ch], GF32_EXP[(i + 1) % 31]); });
  return ALPHABET[s];
}
const checkChar = (secret) => checkOf(base32(secret));

/** A new card: 120 random bits as HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (last character is a check). */
export function newCard() {
  const secret = random(CARD_BYTES);
  return { secret, code: formatCard(secret) };
}

export function formatCard(secret) {
  const body = base32(secret) + checkChar(secret);
  return [CARD_PREFIX, ...body.match(/.{5}/g)].join("-");
}

/** Parse what a person typed. Returns the 15-byte secret; throws a readable error. */
export function parseCard(input) {
  let c = String(input || "").toUpperCase().replace(/[\s\-_.]/g, "");
  if (c.startsWith(CARD_PREFIX)) c = c.slice(CARD_PREFIX.length);
  c = normalize(c);
  if (c.length !== 25) throw new Error("A recovery card has 25 characters after HUMID.");
  const secret = unbase32(c.slice(0, 24), CARD_BYTES);
  if (checkChar(secret) !== c[24]) throw new Error("That card code has a typo. Check each group of five.");
  return secret;
}

const cardKdf = (secret, what, len) => hkdf(sha3_256, secret, undefined, utf8(`HUMID-CARD-v1 ${what}`), len);

/** What the server indexes the card by. Reveals nothing about the card. */
export const cardTag = (secret) => base32(cardKdf(secret, "tag", 16));

const subtle = () => globalThis.crypto.subtle;
const aad = (accountId) => utf8(`HUMID-CARD-v1|${accountId}`);

/** Encrypt the account seed under the card. Output: nonce (12) ‖ AES-256-GCM ciphertext. */
export async function sealCard(secret, seed, accountId) {
  const raw = cardKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  wipe(raw);
  const nonce = random(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(accountId) }, key, seed));
  return concat(nonce, ct);
}

export async function openCard(secret, blob, accountId) {
  const raw = cardKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  wipe(raw);
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: aad(accountId) }, key, blob.subarray(12)));
  } catch {
    throw new Error("This recovery card does not open this vault.");
  }
}

/* ---------------- Shamir secret sharing over GF(2^8) ---------------- */
// Field: x^8 + x^4 + x^3 + x + 1 (0x11b), generator 3. Each byte of the
// secret is the constant term of its own random polynomial of degree t-1.

const EXP = new Uint8Array(510);
const LOG = new Uint8Array(256);
{
  let v = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = v; LOG[v] = i;
    let d = v << 1; if (d & 0x100) d ^= 0x11b;
    v = d ^ v; // multiply by 3
  }
  for (let i = 255; i < 510; i++) EXP[i] = EXP[i - 255];
}
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
const div = (a, b) => { if (!b) throw new Error("division by zero"); return a ? EXP[LOG[a] + 255 - LOG[b]] : 0; };

/** Majority threshold: 2 of 2, 2 of 3, 3 of 4, 3 of 5. */
export const thresholdFor = (n) => Math.floor(n / 2) + 1;
export const MIN_CONTACTS = 2;
export const MAX_CONTACTS = 5;

/** Split `secret` into n shares; any t rebuild it, fewer reveal nothing. Share = { x: 1..n, y: bytes }. */
export function split(secret, n, t) {
  if (!(Number.isInteger(n) && Number.isInteger(t) && t >= 2 && t <= n && n <= 255)) throw new Error("Need 2 ≤ t ≤ n ≤ 255");
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: new Uint8Array(secret.length) }));
  const coeffs = new Uint8Array(t);
  for (let k = 0; k < secret.length; k++) {
    coeffs[0] = secret[k];
    globalThis.crypto.getRandomValues(coeffs.subarray(1));
    for (const s of shares) {
      let y = 0; // Horner
      for (let c = t - 1; c >= 0; c--) y = mul(y, s.x) ^ coeffs[c];
      s.y[k] = y;
    }
  }
  wipe(coeffs);
  return shares;
}

/** Rebuild the secret from at least t shares (extra shares are fine only if all are genuine). */
export function combine(shares) {
  if (shares.length < 2) throw new Error("Need at least two shares");
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length || xs.some((x) => !(x >= 1 && x <= 255))) throw new Error("Shares must have distinct x values");
  const len = shares[0].y.length;
  if (shares.some((s) => s.y.length !== len)) throw new Error("Shares have different lengths");
  const out = new Uint8Array(len);
  for (let i = 0; i < shares.length; i++) {
    let li = 1; // Lagrange basis at 0: prod x_j / (x_j - x_i), and minus is xor here
    for (let j = 0; j < shares.length; j++) if (j !== i) li = mul(li, div(xs[j], xs[j] ^ xs[i]));
    for (let k = 0; k < len; k++) out[k] ^= mul(shares[i].y[k], li);
  }
  return out;
}

/* ---------------- what a contact holds ---------------- */
// The owner seals this to each contact. `label` is the name the owner wants
// the contact to see ("Parker"), so the contact knows who is asking later.

const b64 = (b) => btoa(String.fromCharCode(...b));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function encodeShare({ owner, label, x, t, n, y }) {
  return utf8(JSON.stringify({ v: 1, kind: "humid-recovery-share", owner, label: String(label || "").slice(0, 60), x, t, n, y: b64(y) }));
}

export function decodeShare(bytes) {
  const j = JSON.parse(td.decode(bytes));
  if (j?.kind !== "humid-recovery-share" || j.v !== 1) throw new Error("Not a HumID recovery share");
  return { owner: String(j.owner), label: String(j.label || ""), x: j.x, t: j.t, n: j.n, y: unb64(j.y) };
}
