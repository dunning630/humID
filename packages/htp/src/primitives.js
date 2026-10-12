// Primitives used by HTP/1. All from audited, widely used libraries
// (noble-post-quantum, noble-curves, noble-hashes) plus WebCrypto AES-GCM.
// Nothing here is home-made cryptography; HTP only composes these.

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";

export { ml_kem1024, ml_dsa87, x25519, sha3_256 };

const te = new TextEncoder();
const td = new TextDecoder();
export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);

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
export function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }
export const readU32 = (b, at) => new DataView(b.buffer, b.byteOffset + at, 4).getUint32(0);
export const readU64 = (b, at) => Number(new DataView(b.buffer, b.byteOffset + at, 8).getBigUint64(0));

/** Length-prefixed concatenation, so no two field lists can encode to the same bytes. */
export const lp = (...parts) => concat(...parts.flatMap((p) => [u32(p.length), p]));

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function fromHex(s) {
  if (s.length % 2) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad base64url");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad), (c) => c.charCodeAt(0));
}

export const kdf = (ikm, salt, info, len = 32) => hkdf(sha3_256, ikm, salt, utf8(info), len);
export const mac = (key, msg) => hmac(sha3_256, key, msg);

/** Constant-time comparison for MACs. */
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
export async function aeadOpen(key, nonce, ct, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, ct));
}
