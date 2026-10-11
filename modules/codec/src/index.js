// @humid/codec — the .humid container. Framing only; it never touches keys.
//
//   MAGIC "HUMID" 0x01 | u32 manifestLen | manifest JSON | u32 sigLen | signature | ciphertext
//
// The layout is frozen at format v1. A future format bumps the magic's version
// byte and gets its own parse branch here, so envelopes sealed today stay readable.

export const FORMAT_VERSION = 1;
export const MAGIC = new Uint8Array([72, 85, 77, 73, 68, 1]); // "HUMID" + v1
export const MEDIA_TYPE = "application/vnd.humid.envelope";
export const EXTENSION = ".humid";

const te = new TextEncoder();
const td = new TextDecoder();

export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export const u32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

export const readU32 = (bytes, at) =>
  new DataView(bytes.buffer, bytes.byteOffset + at, 4).getUint32(0);

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export const toB64 = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i += 32768) s += String.fromCharCode(...b.subarray(i, i + 32768));
  return btoa(s);
};

export const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const isEnvelope = (bytes) =>
  bytes.length > MAGIC.length && MAGIC.every((m, i) => bytes[i] === m);

/** Serialise manifest bytes, signature and ciphertext into one envelope. */
export function pack(manifestBytes, signature, ciphertext) {
  return concat(MAGIC, u32(manifestBytes.length), manifestBytes, u32(signature.length), signature, ciphertext);
}

/** Split an envelope into its parts. Throws on anything that is not format v1. */
export function unpack(bytes) {
  if (bytes.length < 14 || !isEnvelope(bytes)) throw new Error("Not a HumID envelope.");
  let at = MAGIC.length;
  const mLen = readU32(bytes, at); at += 4;
  if (at + mLen + 4 > bytes.length) throw new Error("Envelope is truncated.");
  const manifestBytes = bytes.subarray(at, at + mLen); at += mLen;
  const sLen = readU32(bytes, at); at += 4;
  if (at + sLen > bytes.length) throw new Error("Envelope is truncated.");
  const signature = bytes.subarray(at, at + sLen); at += sLen;
  const ciphertext = bytes.subarray(at);
  return { manifest: JSON.parse(td.decode(manifestBytes)), manifestBytes, signature, ciphertext };
}

export const encodeJSON = (obj) => te.encode(JSON.stringify(obj));
export const decodeJSON = (bytes) => JSON.parse(td.decode(bytes));
export const utf8 = (s) => te.encode(s);
