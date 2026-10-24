// @humid/share — asking a HumID holder for named facts, and answering inside a live check.
//
//   verifier                      server (gateway + share)                    holder's phone
//   ────────                      ────────────────────────                    ──────────────
//   types the holder's share code
//   lookup(code) ───────────────► the code's inbox keys ─────────────────────► (made by the phone)
//   recomputes the code from them: a server that swaps in its own keys is caught (code_mismatch)
//   sealRequest(): signed, padded to one size, sealed to the inbox keys
//                 ───────────────► stores it, can't open it ───────────────────► opens it while unlocked
//                                                                              (inbox keys come from the
//                                                                               vault-index key)
//                                                                              chooses what to share,
//                                                                              live check → step-up
//                 ◄─────────────── ledger first (fail closed), then forwards ◄── sealAnswer(): padded,
//   openAnswer() with the one-time key made for this request                     sealed to the verifier's
//                                                                                one-time key
//
// The server learns: a code exists for an account, a request of the fixed size arrived for it,
// and it was answered (when, by which device, with which proof). It can't learn what was asked,
// why, by whom (the verifier's name is inside the sealed request), whether the answer was yes or
// no (approvals and denials are the same size), or any value.
//
// Sealing is the construction of packages/htp/src/share.js, for any payload and label:
//   sealed = kemCt (1568) | xEph (32) | iv (12) | AES-256-GCM(key, plaintext)
//   key    = HKDF-SHA3-256(kemSs || xSs, salt = SHA3-256(kemCt || xEph || xPk), info = label ‖ context)

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { keyCode, parseCode, formatCode } from "@humid/recovery";
import { canonicalJson } from "@humid/htp";

export const VERSION = 1;
export const CODE_LABEL = "HUMID-SHARE-v1";
const L = { request: "HUMID-SHARE-REQUEST-v1", answer: "HUMID-SHARE-ANSWER-v1", note: "HUMID-SHARE-NOTE-v1", inbox: "HUMID-SHARE-INBOX-v1", sign: "HUMID-SHARE-SIGN-v1" };

/** Plaintext buckets: every request, answer and note is exactly this size before sealing. */
export const BUCKET = { request: 16384, answer: 4096, note: 2048 };
const HYBRID = 1568 + 32 + 12 + 16;
/** Sealed sizes on the wire. The server refuses anything else, so a size never says anything. */
export const SEALED = { request: BUCKET.request + HYBRID, answer: BUCKET.answer + HYBRID, note: 12 + BUCKET.note + 16 };
export const SALT_BYTES = 16;
/** How long a request waits for an answer. */
export const REQUEST_TTL_MS = 24 * 3600_000;

const te = new TextEncoder(), td = new TextDecoder();
const utf8 = (s) => te.encode(s);
export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const lp = (...parts) => concat(...parts.flatMap((p) => [u32(p.length), p]));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const b64u = (bytes) => {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export function unb64u(s) {
  const t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const kdf = (ikm, salt, info, len = 32) => hkdf(sha3_256, ikm, salt, utf8(info), len);
const subtle = () => globalThis.crypto.subtle;
async function aesSeal(key, iv, plain, aad) {
  const k = await subtle().importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv, additionalData: aad }, k, plain));
}
async function aesOpen(key, iv, ct, aad) {
  const k = await subtle().importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv, additionalData: aad }, k, ct));
}
const err = (code, message) => Object.assign(new Error(message), { code });

/* ---------------- codes ---------------- */

/** The share code for an inbox's public keys: 12 characters that commit to them. */
export const shareCode = (kemPk, xPk) => keyCode(CODE_LABEL, kemPk, xPk);
export { parseCode, formatCode };
/** True when `code` is exactly what these keys make: a verifier checks the keys the server returned. */
export const codeMatches = (code, kemPk, xPk) => !!parseCode(code) && shareCode(kemPk, xPk) === parseCode(code);

/**
 * A code's inbox keys, derived from the vault-index key and the code's salt, so every device of
 * the account (they share the account seed, so the index key) opens the same requests while
 * unlocked, and the server holds only the salt and the public halves.
 */
export function inboxKeys(indexKey, salt) {
  if (!(indexKey instanceof Uint8Array) || indexKey.length < 32) throw err("bad_key", "Unlock HumID first.");
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) throw err("bad_salt", "Bad share code salt.");
  const seed = kdf(indexKey, salt, `${L.inbox} ml-kem-1024`, 64);
  const xSk = kdf(indexKey, salt, `${L.inbox} x25519`, 32);
  const kem = ml_kem1024.keygen(seed);
  wipe(seed);
  return { kemPk: kem.publicKey, kemSk: kem.secretKey, xPk: x25519.getPublicKey(xSk), xSk };
}

/* ---------------- sealing ---------------- */

const hkey = (label, kemSs, xSs, kemCt, xEph, xPk, ctx) => kdf(concat(kemSs, xSs), sha3_256(concat(kemCt, xEph, xPk)), `${label} key\0${ctx.join("\0")}`);
const haad = (label, ctx) => concat(utf8(label), lp(...ctx.map((c) => utf8(String(c)))));

export async function hybridSeal(label, to, plain, ctx = []) {
  if (!(to?.kemPk instanceof Uint8Array) || to.kemPk.length !== 1568 || !(to.xPk instanceof Uint8Array) || to.xPk.length !== 32) throw err("bad_keys", "Keys must be ML-KEM-1024 (1568 bytes) and X25519 (32 bytes).");
  const { cipherText: kemCt, sharedSecret: kemSs } = ml_kem1024.encapsulate(to.kemPk);
  const xEphSk = random(32);
  const xEph = x25519.getPublicKey(xEphSk);
  const xSs = x25519.getSharedSecret(xEphSk, to.xPk);
  const key = hkey(label, kemSs, xSs, kemCt, xEph, to.xPk, ctx);
  const iv = random(12);
  try { return concat(kemCt, xEph, iv, await aesSeal(key, iv, plain, haad(label, ctx))); }
  finally { wipe(kemSs, xSs, xEphSk, key); }
}

export async function hybridOpen(label, keys, sealed, ctx = []) {
  if (!(sealed instanceof Uint8Array) || sealed.length < HYBRID) throw err("bad_sealed", "That isn't a sealed share message.");
  const kemCt = sealed.subarray(0, 1568), xEph = sealed.subarray(1568, 1600), iv = sealed.subarray(1600, 1612), ct = sealed.subarray(1612);
  const kemSs = ml_kem1024.decapsulate(kemCt, keys.kemSk);
  const xSs = x25519.getSharedSecret(keys.xSk, xEph);
  const key = hkey(label, kemSs, xSs, kemCt, xEph, keys.xPk, ctx);
  try { return await aesOpen(key, iv, ct, haad(label, ctx)); }
  catch { throw err("not_for_you", "This wasn't sealed for these keys, or it was changed on the way."); }
  finally { wipe(kemSs, xSs, key); }
}

/** Pad JSON to an exact bucket. */
export function pad(obj, bucket) {
  const b = utf8(JSON.stringify(obj));
  if (b.length + 4 > bucket) throw err("too_large", `This doesn't fit in ${bucket} bytes.`);
  const out = new Uint8Array(bucket);
  out.set(u32(b.length)); out.set(b, 4);
  return out;
}
export function unpad(b) {
  const n = new DataView(b.buffer, b.byteOffset, 4).getUint32(0);
  if (n + 4 > b.length) throw err("bad_padding", "Malformed share message.");
  return JSON.parse(td.decode(b.subarray(4, 4 + n)));
}

/* ---------------- the facts a verifier may ask for ---------------- */

/**
 * Each fact is taken from one ID in the holder's vault (an @humid/idscan record) on the phone.
 * Derived facts (over 18, over 21, valid) share a yes or no, never the date behind it.
 */
export const FACTS = {
  full_name:      { label: "Full name" },
  birth_date:     { label: "Date of birth" },
  age_over_18:    { label: "Over 18", derived: true },
  age_over_21:    { label: "Over 21", derived: true },
  address:        { label: "Home address" },
  document_number:{ label: "Document number" },
  document_expiry:{ label: "Document expiry" },
  document_valid: { label: "ID is valid today", derived: true },
  issuer:         { label: "Issued by" },
  nationality:    { label: "Nationality" },
};
export const FACT_KEYS = Object.keys(FACTS);
export const factLabel = (k) => FACTS[k]?.label || k;

const nice = (s) => (!s ? "" : s === s.toUpperCase() ? s.toLowerCase().replace(/(^|[\s'-])\p{L}/gu, (m) => m.toUpperCase()) : s);
function yearsOn(birth, today) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(birth || ""));
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  let age = today.getUTCFullYear() - y;
  if (today.getUTCMonth() + 1 < mo || (today.getUTCMonth() + 1 === mo && today.getUTCDate() < d)) age--;
  return age;
}

/** The facts this ID can answer, as { key: text }. `places`: optional { region(code), country(code) } names. */
export function factsFromId(rec, { today = new Date(), places = {} } = {}) {
  const f = rec?.fields || {};
  const out = {};
  const name = [nice(f.given), nice(f.surname), f.suffix].filter(Boolean).join(" ");
  if (name) out.full_name = name;
  if (f.birth) out.birth_date = f.birth;
  const age = yearsOn(f.birth, today);
  if (age !== null) { out.age_over_18 = age >= 18 ? "Yes" : "No"; out.age_over_21 = age >= 21 ? "Yes" : "No"; }
  const a = rec?.address;
  if (a && (a.street || a.city)) out.address = [nice(a.street), nice(a.street2), [nice(a.city), a.region].filter(Boolean).join(", "), a.postalCode].filter(Boolean).join(", ").replace(/, (\d{5})/, " $1");
  if (f.number) out.document_number = f.number;
  if (f.expiry) {
    out.document_expiry = f.expiry;
    out.document_valid = f.expiry >= today.toISOString().slice(0, 10) ? "Yes" : "No";
  }
  const region = f.region ? (places.region?.(f.region) || f.region) : "";
  const country = f.issuer ? (places.country?.(f.issuer) || f.issuer) : "";
  if (region || country) out.issuer = [region, country].filter(Boolean).join(", ");
  if (f.nationality) out.nationality = places.country?.(f.nationality) || f.nationality;
  return out;
}

/* ---------------- verifier side ---------------- */

/** A verifier's signing key. Keep `sk` private; `fp` is what a holder sees. */
export function verifierKeys(seed = random(32)) {
  const k = ml_dsa87.keygen(seed);
  return { pk: k.publicKey, sk: k.secretKey, fp: verifierFp(k.publicKey) };
}
/** "3F2A-91C0-7B44-0D12": first 8 bytes of SHA3-256 of the verifier's key. */
export const verifierFp = (pk) => toHex(sha3_256(pk).subarray(0, 8)).toUpperCase().match(/.{4}/g).join("-");

const signBytes = (payload) => concat(utf8(L.sign), new Uint8Array([0]), utf8(canonicalJson(payload)));

/**
 * Build and seal a request. Returns { sealed, receiver, payload }: keep `receiver` (its secret
 * half opens the answer), discard it after. `to`: the inbox keys the server returned for `code`,
 * already checked with codeMatches.
 */
export async function sealRequest({ code, to, verifier, name, purpose, facts, retention, now = Date.now() }) {
  const c = parseCode(code);
  if (!c) throw err("bad_code", "That code isn't valid.");
  if (!codeMatches(c, to.kemPk, to.xPk)) throw err("code_mismatch", "The server returned different keys for this code. Nothing was sent.");
  const asked = [...new Set(facts)].filter((k) => k in FACTS);
  if (!asked.length) throw err("no_facts", "Ask for at least one thing.");
  const rx = { kem: ml_kem1024.keygen(), xSk: random(32) };
  const receiver = { kemPk: rx.kem.publicKey, kemSk: rx.kem.secretKey, xPk: x25519.getPublicKey(rx.xSk), xSk: rx.xSk };
  const payload = {
    v: VERSION, code: c,
    verifier: { name: String(name || "").slice(0, 80), pk: b64u(verifier.pk) },
    purpose: String(purpose || "").slice(0, 200), facts: asked, retention: String(retention || "").slice(0, 120),
    receiver: { kemPk: b64u(receiver.kemPk), xPk: b64u(receiver.xPk) },
    nonce: b64u(random(16)), at: now, exp: now + REQUEST_TTL_MS,
  };
  const sig = b64u(ml_dsa87.sign(signBytes(payload), verifier.sk));
  const sealed = await hybridSeal(L.request, to, pad({ payload, sig }, BUCKET.request), [c]);
  return { sealed, receiver, payload };
}

/** Open an answer with the receiver kept from sealRequest. Wipes the receiver's secret halves. */
export async function openAnswer(sealed, receiver, { id, payload }) {
  try {
    if (sealed.length !== SEALED.answer) throw err("bad_size", "The answer isn't the right size.");
    const a = unpad(await hybridOpen(L.answer, receiver, sealed, [id]));
    if (a.nonce !== payload.nonce) throw err("wrong_request", "This answer is for another request.");
    if (a.decision !== "approve" && a.decision !== "deny") throw err("bad_answer", "Malformed answer.");
    const shared = a.decision === "approve" ? Object.fromEntries(Object.entries(a.facts || {}).filter(([k]) => payload.facts.includes(k)).map(([k, v]) => [k, String(v)])) : {};
    return { decision: a.decision, facts: shared, at: Number(a.at), assurance: a.assurance || null };
  } finally { wipe(receiver.kemSk, receiver.xSk); }
}

/* ---------------- holder side ---------------- */

/**
 * Open a request with a code's inbox keys. Returns { payload, signed, verifierFp, expired }.
 * `signed`: the verifier's own key signed exactly this request. The name is the verifier's own
 * claim: HumID shows it with the key's fingerprint, never as checked.
 */
export async function openRequest(sealed, inbox, { code, now = Date.now() }) {
  if (sealed.length !== SEALED.request) throw err("bad_size", "The request isn't the right size.");
  const c = parseCode(code);
  const { payload, sig } = unpad(await hybridOpen(L.request, inbox, sealed, [c]));
  let signed = false, pk;
  try { pk = unb64u(payload?.verifier?.pk); signed = ml_dsa87.verify(unb64u(sig), signBytes(payload), pk); } catch { signed = false; }
  if (payload?.v !== VERSION || payload.code !== c) signed = false;
  const facts = Array.isArray(payload?.facts) ? payload.facts.filter((k) => k in FACTS) : [];
  return { payload: { ...payload, facts }, signed, verifierFp: pk ? verifierFp(pk) : "", expired: !(Number(payload?.exp) > now) };
}

/**
 * The answer and the note for the account's other devices, both fixed size. `facts`: the values
 * the holder chose to share (approve), ignored for deny. The note carries labels, never values.
 */
export async function sealAnswer({ id, request, decision, facts = {}, indexKey, device, assurance, now = Date.now() }) {
  if (decision !== "approve" && decision !== "deny") throw err("bad_answer", "Approve or deny.");
  const p = request.payload;
  const chosen = decision === "approve" ? Object.fromEntries(Object.entries(facts).filter(([k]) => p.facts.includes(k)).map(([k, v]) => [k, String(v).slice(0, 300)])) : {};
  if (decision === "approve" && !Object.keys(chosen).length) throw err("nothing_chosen", "Choose at least one thing to share, or deny.");
  const receiver = { kemPk: unb64u(p.receiver.kemPk), xPk: unb64u(p.receiver.xPk) };
  const answer = await hybridSeal(L.answer, receiver, pad({ v: VERSION, decision, facts: chosen, nonce: p.nonce, at: now, ...(assurance ? { assurance } : {}) }, BUCKET.answer), [id]);
  const note = await sealNote(indexKey, id, {
    v: VERSION, id, decision, verifier: p.verifier.name, verifierFp: verifierFp(unb64u(p.verifier.pk)), purpose: p.purpose,
    asked: p.facts, shared: Object.keys(chosen), device: device || "", at: now,
  });
  return { answer, note };
}

const noteKey = (indexKey) => kdf(indexKey, undefined, L.note);
export async function sealNote(indexKey, id, note) {
  const key = noteKey(indexKey), iv = random(12);
  try { return concat(iv, await aesSeal(key, iv, pad(note, BUCKET.note), utf8(`${L.note}\0${id}`))); }
  finally { wipe(key); }
}
export async function openNote(indexKey, id, sealed) {
  const key = noteKey(indexKey);
  try { return unpad(await aesOpen(key, sealed.subarray(0, 12), sealed.subarray(12), utf8(`${L.note}\0${id}`))); }
  finally { wipe(key); }
}
