// Shared byte helpers for @humid/msg. Nothing here is new cryptography: HKDF
// and HMAC over SHA3-256 (noble-hashes) and AES-256-GCM (WebCrypto), the same
// primitives HTP/1 and HUMID-PQ1 use.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";

export const VERSION = "HUMID-MSG-v1";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);

/** Every label in this module is prefixed with the version, so no value can be reused across versions. */
export const label = (s) => utf8(`${VERSION} ${s}`);

export class MsgError extends Error {
  constructor(code, message) { super(message || code); this.code = code; this.name = "MsgError"; }
}

export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
export const readU32 = (b, at) => new DataView(b.buffer, b.byteOffset + at, 4).getUint32(0);

/** Length-prefixed concatenation, so no two field lists encode to the same bytes. */
export const lp = (...parts) => concat(...parts.flatMap((p) => [u32(p.length), p]));

/** Inverse of lp for exactly `count` fields. Throws MsgError on anything malformed or trailing. */
export function unlp(bytes, count, max = 1 << 24) {
  const out = [];
  let at = 0;
  for (let i = 0; i < count; i++) {
    if (at + 4 > bytes.length) throw new MsgError("malformed", "Truncated field");
    const n = readU32(bytes, at); at += 4;
    if (n > max || at + n > bytes.length) throw new MsgError("malformed", "Field length out of range");
    out.push(bytes.subarray(at, at + n)); at += n;
  }
  if (at !== bytes.length) throw new MsgError("malformed", "Trailing bytes");
  return out;
}

export const H = (...parts) => sha3_256(concat(...parts));
export const kdf = (ikm, salt, info, len = 32) => hkdf(sha3_256, ikm, salt, label(info), len);
export const mac = (key, msg) => hmac(sha3_256, key, msg);

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(s) {
  if (typeof s !== "string" || s.length % 2 || !/^[0-9a-f]*$/.test(s)) throw new MsgError("malformed", "Bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(s, expectLen) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new MsgError("malformed", "Bad base64url");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  let out;
  try { out = Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0)); }
  catch { throw new MsgError("malformed", "Bad base64url"); }
  if (expectLen !== undefined && out.length !== expectLen) throw new MsgError("malformed", "Wrong key or value length");
  return out;
}

export const encodeJSON = (v) => utf8(JSON.stringify(v));
export function decodeJSON(bytes) {
  try { return JSON.parse(fromUtf8(bytes)); }
  catch { throw new MsgError("malformed", "Bad JSON"); }
}

/** Constant-time comparison. */
export function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export const wipe = (...bufs) => { for (const b of bufs) if (b && b.fill) b.fill(0); };

const subtle = globalThis.crypto.subtle;
export async function aeadSeal(key, nonce, plain, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, plain));
}
/** Throws MsgError(code) instead of a bare DOMException, so callers see one error type. */
export async function aeadOpen(key, nonce, ct, aad, code = "decrypt_failed") {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try { return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, ct)); }
  catch { throw new MsgError(code, "Could not decrypt: wrong key, or the bytes were changed"); }
}

/** Day number (UTC). Mailbox ids rotate on it. */
export const dayOf = (ms) => Math.floor(ms / 86_400_000);

/** Run fn; turn any non-MsgError into MsgError("malformed") so parsers have exactly one failure type. */
export function guard(fn) {
  try {
    const r = fn();
    if (r && typeof r.then === "function") return r.catch((e) => { throw e instanceof MsgError ? e : new MsgError("malformed", e?.message); });
    return r;
  } catch (e) { throw e instanceof MsgError ? e : new MsgError("malformed", e?.message); }
}

/* Uint8Array-safe JSON for the state. */
export function toPlain(v) {
  if (v instanceof Uint8Array) return { $b: b64u(v) };
  if (Array.isArray(v)) return v.map(toPlain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toPlain(x)]));
  return v;
}
export function fromPlain(v) {
  if (v && typeof v === "object" && !Array.isArray(v) && typeof v.$b === "string" && Object.keys(v).length === 1) return unb64u(v.$b);
  if (Array.isArray(v)) return v.map(fromPlain);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fromPlain(x)]));
  return v;
}
