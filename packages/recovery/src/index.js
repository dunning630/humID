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

export const CODE_LENGTH = 12; // 60 bits: codes that live minutes (links, witness offers, admin)
/**
 * Recovery-request codes live up to a week while witnesses respond, long enough that a 60-bit
 * second preimage (a server finding its own keys for someone's code) is within reach of a
 * well-funded attacker (CRYPTO-08). They have 16 characters: 80 bits.
 */
export const LONG_CODE_LENGTH = 16;

/**
 * A short code that commits to public keys. The device that shows it made the
 * keys; the device that types it recomputes the code from the keys the server
 * hands it, so a server that substituted keys is caught.
 */
export function keyCode(label, ...publicKeys) {
  return base32(sha3_256(concat(utf8(label), lp(...publicKeys)))).slice(0, codeLengthFor(label));
}
const codeLengthFor = (label) => (label === REQUEST_LABEL ? LONG_CODE_LENGTH : CODE_LENGTH);

export const formatCode = (code) => normalize(code).match(/.{1,4}/g)?.join("-") ?? "";

/** A normalised 12- or 16-character code, or null if the input cannot be one. */
export function parseCode(input) {
  const c = normalize(input);
  return (c.length === CODE_LENGTH || c.length === LONG_CODE_LENGTH) && [...c].every((ch) => ch in DECODE) ? c : null;
}

export const LINK_LABEL = "HUMID-LINK-v1";       // a new device asking to join
export const OFFER_LABEL = "HUMID-CONTACT-v1";   // someone offering to be a recovery contact
export const REQUEST_LABEL = "HUMID-RECOVER-v1"; // a device asking contacts for help
/**
 * Becoming a server administrator (docs/ADMIN.md): the phone shows this code for its own
 * device key, the admin console shows it for the key the approval arrived with, and the
 * person compares the two before the console trusts that phone.
 */
export const ADMIN_CHECK_LABEL = "HUMID-ADMIN-v1";
export const adminCheck = (deviceDsaPk) => formatCode(keyCode(ADMIN_CHECK_LABEL, deviceDsaPk));

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

/** `epoch`: which set of recovery pieces the share belongs to (omitted for the first, 1). */
export function encodeShare({ owner, label, x, t, n, y, epoch }) {
  return utf8(JSON.stringify({ v: 1, kind: "humid-recovery-share", owner, label: String(label || "").slice(0, 60), x, t, n, y: b64(y), ...(epoch > 1 ? { e: epoch } : {}) }));
}

export function decodeShare(bytes) {
  const j = JSON.parse(td.decode(bytes));
  if (j?.kind !== "humid-recovery-share" || j.v !== 1) throw new Error("Not a HumID recovery share");
  return { owner: String(j.owner), label: String(j.label || ""), x: j.x, t: j.t, n: j.n, y: unb64(j.y), epoch: Number.isSafeInteger(j.e) && j.e > 1 ? j.e : 1 };
}

/* ---------------- two-proof recovery (quorum, v2) ----------------
 * The account seed A is split 2-of-3. Each part is protected by a different
 * KIND of evidence, so getting A back always takes two independent proofs that
 * you are the person who set it up:
 *
 *   x = 1  witness   further split among recovery contacts (any majority)
 *   x = 2  anchor    held by the server, encrypted under the identity anchor
 *                    (your passport or ID chip); released only when that chip
 *                    is proven again, in person at a station or live remotely
 *   x = 3  card      encrypted under the seal card you keep offline
 *   x = 4  key       encrypted under a FIDO2 security key's hmac-secret, which the
 *                    key gives out only with its PIN (4.0, docs/SECURITY-KEY.md)
 *
 * Any two different parts OF ONE EPOCH rebuild A (the polynomial has degree 1). Within an
 * epoch, parts made at different times fit together, so a key added later works with an
 * older card. The split is deterministic (coefficients come from A and the epoch), so any
 * device holding A can make any part of the current epoch at any time.
 *
 * Epochs (CRYPTO-02): a new epoch is a new line through A. Every part of an older epoch is
 * then useless with every part of the new one, so pieces a removed witness still holds, or an
 * old card (and its blob in a server backup), can't be combined with anything current. The
 * account's epoch is in its signed recovery-mode statement; each part carries it (in the card
 * and key AAD and the witness share, from epoch 2 on), and combineQuorum refuses a mix.
 */

export const QUORUM = Object.freeze({ witness: 1, anchor: 2, card: 3, key: 4 });
export const QUORUM_KINDS = Object.freeze(Object.keys(QUORUM));
export const QUORUM_THRESHOLD = 2;
const QUORUM_PART_BYTES = 65; // x ‖ y(64)

/** The parts of `seed` for `epoch`, any two of which rebuild it. Returns { witness, anchor, card, key }: { x, y, epoch }. */
export function quorumParts(seed, epoch = 1) {
  if (!(seed instanceof Uint8Array) || seed.length !== 64) throw new Error("Account seed must be 64 bytes");
  if (!(Number.isSafeInteger(epoch) && epoch >= 1)) throw new Error("Unknown recovery epoch");
  const coeff = hkdf(sha3_256, seed, undefined, utf8(`HUMID-QUORUM-v1 coefficient epoch ${epoch}`), seed.length);
  const out = {};
  for (const [kind, x] of Object.entries(QUORUM)) {
    const y = new Uint8Array(seed.length);
    for (let k = 0; k < seed.length; k++) y[k] = mul(coeff[k], x) ^ seed[k]; // degree 1: A + c·x
    out[kind] = { x, y, epoch };
  }
  wipe(coeff);
  return out;
}

export function encodeQuorumPart({ x, y }) {
  if (!QUORUM_KINDS.some((k) => QUORUM[k] === x) || y.length !== 64) throw new Error("Not a recovery part");
  return concat(new Uint8Array([x]), y);
}

export function decodeQuorumPart(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== QUORUM_PART_BYTES) throw new Error("A recovery part has 65 bytes");
  const x = bytes[0];
  if (!QUORUM_KINDS.some((k) => QUORUM[k] === x)) throw new Error("Unknown recovery part");
  return { x, y: bytes.slice(1) };
}

export const kindOfPart = (x) => QUORUM_KINDS.find((k) => QUORUM[k] === x);

const epochOf = (p) => p?.epoch ?? 1;
/** Rebuild the seed from any two different parts of the same epoch. */
export function combineQuorum(parts) {
  const distinct = [...new Map(parts.map((p) => [p.x, p])).values()];
  if (distinct.length < QUORUM_THRESHOLD) throw new Error("Recovery needs two different kinds of proof");
  const two = distinct.slice(0, QUORUM_THRESHOLD);
  if (epochOf(two[0]) !== epochOf(two[1])) throw new Error("These proofs are from different sets of recovery pieces, so they don't fit together.");
  return combine(two);
}

/* Seal card (v2): the card part, encrypted under the card. Same card code format.
 * The epoch is in the AAD from epoch 2 on (epoch 1 keeps the original bytes). */
const aad2 = (accountId, epoch = 1) => utf8(`HUMID-CARD-v2|${accountId}${epoch > 1 ? `|epoch ${epoch}` : ""}`);

export async function sealCardPart(secret, part, accountId, epoch = epochOf(part)) {
  const raw = cardKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  wipe(raw);
  const nonce = random(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad2(accountId, epoch) }, key, encodeQuorumPart(part)));
  return concat(nonce, ct);
}

export async function openCardPart(secret, blob, accountId, epoch = 1) {
  const raw = cardKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  wipe(raw);
  try {
    return { ...decodeQuorumPart(new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: aad2(accountId, epoch) }, key, blob.subarray(12)))), epoch };
  } catch {
    throw new Error("This seal card does not open this vault.");
  }
}
export const CARD_PART_BLOB_BYTES = 12 + QUORUM_PART_BYTES + 16;
export const CARD_FULL_BLOB_BYTES = 12 + 64 + 16;

/* Security key (4.0): the key part, encrypted under the 32-byte secret a FIDO2 key's
 * hmac-secret gives out only with its PIN (docs/SECURITY-KEY.md). The server finds the
 * part by the tag and can open neither. */
export const KEY_SECRET_BYTES = 32;
export const KEY_PART_BLOB_BYTES = 12 + QUORUM_PART_BYTES + 16;
const keyKdf = (secret, what, len) => {
  if (!(secret instanceof Uint8Array) || secret.length !== KEY_SECRET_BYTES) throw new Error("A security key's secret has 32 bytes");
  return hkdf(sha3_256, secret, undefined, utf8(`HUMID-KEY-v1 ${what}`), len);
};
const aadKey = (accountId, epoch = 1) => utf8(`HUMID-KEY-v1|${accountId}${epoch > 1 ? `|epoch ${epoch}` : ""}`);

/** What the server finds the key part by: base32 of 16 bytes, 26 characters. Reveals nothing about the secret. */
export const keyTag = (secret) => base32(keyKdf(secret, "tag", 16));

export async function sealKeyPart(secret, part, accountId, epoch = epochOf(part)) {
  if (part?.x !== QUORUM.key) throw new Error("That isn't the key part");
  const raw = keyKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  wipe(raw);
  const nonce = random(12);
  const plain = encodeQuorumPart(part);
  try {
    const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aadKey(accountId, epoch) }, key, plain));
    return concat(nonce, ct);
  } finally { wipe(plain); }
}

export async function openKeyPart(secret, blob, accountId, epoch = 1) {
  const raw = keyKdf(secret, "key", 32);
  const key = await subtle().importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  wipe(raw);
  let plain;
  try {
    plain = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: aadKey(accountId, epoch) }, key, blob.subarray(12)));
  } catch {
    throw new Error("This security key doesn't open this vault.");
  }
  try {
    const part = decodeQuorumPart(plain);
    if (part.x !== QUORUM.key) throw new Error("This security key doesn't open this vault.");
    return { ...part, epoch };
  } finally { wipe(plain); }
}

/* ID chip anchor (v2): the anchor part, sealed on the holder's phone under a key from the chip's
 * Active Authentication public key (DG15), before it is sent. This BINDS the part to one chip
 * (another passport, an old one or a namesake's has a different DG15), and the chip proves it's
 * there by answering a fresh challenge when it's linked and when it's used.
 *
 * It is NOT a secret against the server (V74-03): DG15 is public chip data, readable by anyone
 * who taps the passport with its MRZ, and the server receives it in every link and recovery
 * (it needs it to check the chip). The server doesn't store it, but a server that records one
 * request can open the part. No passport exposes a static secret (Chip Authentication is an
 * ephemeral exchange), so the real fix is a split wrap with an independent cosigner
 * (docs/CONTINUITY.md, "The anchor and the operator"), for the owner to decide. */
export const ANCHOR_PART_BLOB_BYTES = 12 + QUORUM_PART_BYTES + 16;
const aadAnchor = (accountId, epoch) => utf8(`HUMID-ANCHOR-PART-v2|${accountId}|epoch ${epoch}`);

/** The 32-byte key the anchor part is sealed under, from the chip's DG15 file (as read from the chip). */
export function anchorPartKey(dg15) {
  if (!(dg15 instanceof Uint8Array) || dg15.length < 16) throw new Error("This chip has no authentication key, so it can't hold a recovery part.");
  return hkdf(sha3_256, dg15, undefined, utf8("HUMID-ANCHOR-PART-v2 key"), 32);
}

export async function sealAnchorPart(key, part, accountId, epoch = epochOf(part)) {
  if (part?.x !== QUORUM.anchor) throw new Error("That isn't the anchor part");
  const k = await subtle().importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const nonce = random(12);
  const plain = encodeQuorumPart(part);
  try { return concat(nonce, new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aadAnchor(accountId, epoch) }, k, plain))); }
  finally { wipe(plain); }
}

export async function openAnchorPart(key, blob, accountId, epoch = 1) {
  const k = await subtle().importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  let plain;
  try { plain = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: aadAnchor(accountId, epoch) }, k, blob.subarray(12))); }
  catch { throw new Error("This ID chip doesn't open this vault's part. Use the passport or ID card you linked."); }
  try {
    const part = decodeQuorumPart(plain);
    if (part.x !== QUORUM.anchor) throw new Error("This ID chip doesn't open this vault's part.");
    return { ...part, epoch };
  } finally { wipe(plain); }
}

/* ---------------- how long a recovery waits ----------------
 * The stronger the evidence, the shorter the wait. `base` is the server's
 * RECOVERY_DELAY_MS (72 hours in production). Kinds: witness | card | anchor | key;
 * anchorMode: "station" (in person, operator-verified) | "remote" (live chip).
 *
 *   station + anything                   base / 3     (24 h)
 *   witnesses + card, key or chip        base         (72 h)
 *   any two of card, key, chip (no people)  base × 7/3   (7 days)
 *   a duress signal in the last 14 days  × 2
 */
export const DURESS_WINDOW_MS = 14 * 24 * 3600_000;

export function quorumDelay(kinds, { base, anchorMode = null, duress = false } = {}) {
  const set = new Set(kinds);
  if (set.size < QUORUM_THRESHOLD) return null;
  let ms;
  if (set.has("anchor") && anchorMode === "station") ms = base / 3;
  else if (set.has("witness")) ms = base;
  else ms = (base * 7) / 3;
  return Math.round(duress ? ms * 2 : ms);
}

/** Words for the evidence behind a recovery, for alerts and the continuity record. */
export function evidenceLabel(kinds, anchorMode) {
  const words = { witness: "witnesses", card: "seal card", key: "security key", anchor: anchorMode === "station" ? "ID chip at a station" : "live ID chip" };
  return [...kinds].sort((a, b) => QUORUM_KINDS.indexOf(a) - QUORUM_KINDS.indexOf(b)).map((k) => words[k] || k).join(" + ");
}

/* ---------------- QR payloads ----------------
 * A QR carries the same 12-character code you could type, plus what it's for
 * and when it expires: HUMID:2:LINK:XXXXXXXXXXXX:<expiry, unix seconds, base 36>.
 * The code is what commits to the keys (each side recomputes it), so a QR is
 * data to check, never a command: nothing in it is opened, followed or run.
 *
 * Why the code and not a signature: the QR introduces keys the scanner doesn't
 * know yet (a new device, a stranger offering to be a witness), so there is no
 * key it could already trust to check a signature with. The code is a
 * commitment to those keys that a person can also read out or type; the
 * scanning device fetches the keys and refuses unless they hash to it, and the
 * showing device refuses to show a code that isn't its own keys'.
 * The expiry is a convenience (stale QRs are refused before anything is
 * fetched); the server's own expiry is what counts.
 */
export const QR_VERSION = 2;
export const QR_MAX = 48;
export const QR_KINDS = Object.freeze({ link: "LINK", recover: "RECOVER", contact: "CONTACT", admin: "ADMIN" });
// One spelling per payload: no leading zeros in the version or the expiry.
const QR_RE = /^HUMID:([1-9][0-9]{0,2}):([A-Z]{1,10}):([0-9A-Z]{12}|[0-9A-Z]{16}):([1-9A-Z][0-9A-Z]{0,7})$/;

/** The text for a QR code. expiresAt in ms. */
export function qrPayload(kind, code, expiresAt) {
  const k = QR_KINDS[kind];
  const c = parseCode(code);
  if (!k || !c || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new Error("Nothing to put in a QR code");
  return `HUMID:${QR_VERSION}:${k}:${c}:${Math.ceil(expiresAt / 1000).toString(36).toUpperCase()}`;
}

/**
 * { kind, code, expiresAt } from scanned text, or null for anything that isn't
 * exactly a current-version HumID QR: too long, another version, an unknown kind,
 * a malformed code, extra fields, a URL. Bare codes are not accepted from the camera.
 */
export function parseQr(text) {
  if (typeof text !== "string" || text.length > QR_MAX) return null;
  const m = QR_RE.exec(text);
  if (!m || Number(m[1]) !== QR_VERSION) return null;
  const kind = Object.keys(QR_KINDS).find((k) => QR_KINDS[k] === m[2]);
  if (!kind || parseCode(m[3]) !== m[3]) return null;
  const expiresAt = parseInt(m[4], 36) * 1000;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) return null;
  return { kind, code: m[3], expiresAt };
}

/* ---------------- recovery modes ----------------
 * Each holder chooses at setup (docs/RECOVERY.md#two-recovery-modes):
 *   holder-only  only a live check on one of the holder's own enrolled devices opens anything.
 *                No recovery part is ever made for the server, and it refuses to store one.
 *                Lose every device and the vault is gone.
 *   hardened     two different proofs, a wait, and a veto from any surviving device.
 * The choice is signed by the account key over this statement, so a server can't change it
 * without the holder's devices noticing. `version` only ever goes up. `epoch` is which split
 * of the seed the account's recovery parts are made from (quorumParts): a new epoch retires
 * every part made before it.
 */
export const RECOVERY_MODES = Object.freeze({ holderOnly: "holder-only", hardened: "hardened" });
export const RECMODE_LABEL = "HUMID-RECMODE-v1";
export const isRecoveryMode = (m) => m === RECOVERY_MODES.holderOnly || m === RECOVERY_MODES.hardened;
const u32ok = (n) => Number.isSafeInteger(n) && n >= 1 && n < 2 ** 32;

/**
 * Statements form a chain (V74-01/02): each names the hash of the one before it (`prev`, 64 hex
 * characters; all zeros for version 1), and versions go up by one. So a server can't put an
 * older genuine statement back, show a different one to different devices, or delete the
 * record and pass the account off as "from before modes", without the holder's devices
 * noticing: each keeps the highest statement it has checked and compares.
 */
export const RECMODE_GENESIS = "0".repeat(64);
const prevBytes = (prev) => {
  const h = String(prev ?? RECMODE_GENESIS);
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error("Not a recovery mode statement");
  return Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
};
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/** The bytes the account key signs to set the recovery mode, the recovery epoch, and the link to the statement before. */
export function recoveryModeMessage(accountId, mode, version, epoch, prev = RECMODE_GENESIS) {
  if (!accountId || !isRecoveryMode(mode) || !u32ok(version) || !u32ok(epoch)) throw new Error("Not a recovery mode statement");
  if ((version === 1) !== (String(prev) === RECMODE_GENESIS)) throw new Error("Not a recovery mode statement");
  return concat(utf8(RECMODE_LABEL), lp(utf8(String(accountId)), utf8(mode), u32(version), u32(epoch), prevBytes(prev)));
}

/** A statement's hash: what the next one names as `prev`. */
export const recoveryModeHash = (accountId, { mode, version, epoch, prev }) => hex(sha3_256(recoveryModeMessage(accountId, mode, version, epoch, prev)));

/**
 * May `next` replace `cur` (both already signature-checked, so both came from the holder)?
 * The same statement again is fine (a retried request). Otherwise its version is higher and its
 * epoch no lower; the very next version must name `cur`'s hash (a gap is fine: the holder's
 * other device may have switched in between, and only the account key can sign). Never back.
 * `cur` null or version 0: an account from before modes.
 */
export function followsMode(accountId, cur, next) {
  if (!cur || !cur.version) return next.version >= 1;
  if (next.version === cur.version) return recoveryModeHash(accountId, next) === recoveryModeHash(accountId, cur);
  if (next.version < cur.version || next.epoch < cur.epoch) return false;
  return next.version > cur.version + 1 || next.prev === recoveryModeHash(accountId, cur);
}

/** What a holder-only account may use to bring a device in: only another of its own devices. */
export const routesFor = (mode) => (mode === RECOVERY_MODES.holderOnly ? ["link"] : ["link", "quorum", "card", "contacts"]);

/* ---------------- account check ----------------
 * Adding a device: both screens show this short string, and the person compares them before
 * the new device finishes. A server that sealed some other account's key to the new device
 * would show a different one.
 *
 * v2 (CRYPTO-08): it commits to the account AND this link's own public keys, which the new
 * device made for this link and which live 10 minutes. v1 hashed the account id alone, so a
 * server could grind, ahead of time and at leisure, an account of its own whose 40-bit check
 * matched a victim's. Now any such grinding has to start after the link exists and finish
 * inside its 10 minutes, for those keys only.
 */
export const ACCOUNT_CHECK_LABEL = "HUMID-ACCOUNT-CHECK-v2";
export function accountCheck(accountId, linkKemPk, linkXPk) {
  if (!accountId) throw new Error("No account");
  if (!(linkKemPk instanceof Uint8Array) || !(linkXPk instanceof Uint8Array) || !linkKemPk.length || !linkXPk.length) throw new Error("The match code needs this link's keys");
  return base32(sha3_256(concat(utf8(ACCOUNT_CHECK_LABEL), lp(utf8(String(accountId)), linkKemPk, linkXPk)))).slice(0, 8).match(/.{4}/g).join("-");
}
