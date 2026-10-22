// CBOR (RFC 8949) as ISO/IEC 18013-5 uses it. Small on purpose: definite and
// indefinite lengths, tags, floats, and one special case that matters for
// security: tag 24 ("encoded CBOR data item"). The mdoc digests and signatures
// cover the exact bytes of every tag-24 item, so the decoder keeps them
// (Encoded.raw) instead of re-encoding.
//
// Decoding gives: numbers (BigInt beyond 2^53), Uint8Array, string, Array,
// Map (keys of any type), Encoded (tag 24), Tagged (any other tag), true,
// false, null, undefined.

export class CborError extends Error {}

/** Tag 24: a CBOR item carried as a byte string. `bytes` is the inner encoding; `raw` the whole tag-24 item. */
export class Encoded {
  constructor(bytes, raw = null) { this.bytes = bytes; this.raw = raw; this._v = undefined; }
  get value() { if (this._v === undefined) this._v = decode(this.bytes); return this._v; }
  /** The tag-24 item's own encoding: what digests and transcripts hash. */
  get encoded() { return this.raw || encode(this); }
  static of(item) { return new Encoded(encode(item)); }
}

/** Any other tag: 0 (date-time text), 1004 (full-date text), 1 (epoch seconds)… */
export class Tagged {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

/* ---------------- encode ---------------- */

function head(major, n) {
  if (typeof n === "bigint") {
    if (n > 0xffffffffffffffffn) throw new CborError("integer too large for CBOR without a bignum tag");
    if (n < 0x100000000n) return head(major, Number(n));
    const b = new Uint8Array(9);
    b[0] = (major << 5) | 27;
    new DataView(b.buffer).setBigUint64(1, n);
    return b;
  }
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of((major << 5) | 26, n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  return head(major, BigInt(n));
}

function enc(v, out) {
  if (v === null) return out.push(Uint8Array.of(0xf6));
  if (v === undefined) return out.push(Uint8Array.of(0xf7));
  if (v === false) return out.push(Uint8Array.of(0xf4));
  if (v === true) return out.push(Uint8Array.of(0xf5));
  if (typeof v === "bigint") return out.push(v >= 0n ? head(0, v) : head(1, -1n - v));
  if (typeof v === "number") {
    if (Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER) return out.push(v >= 0 ? head(0, v) : head(1, -1 - v));
    const b = new Uint8Array(9); b[0] = 0xfb; new DataView(b.buffer).setFloat64(1, v); return out.push(b);
  }
  if (typeof v === "string") { const b = te.encode(v); out.push(head(3, b.length)); return out.push(b); }
  if (v instanceof Uint8Array) { out.push(head(2, v.length)); return out.push(v); }
  if (v instanceof Encoded) { if (v.raw) return out.push(v.raw); out.push(Uint8Array.of(0xd8, 24)); out.push(head(2, v.bytes.length)); return out.push(v.bytes); }
  if (v instanceof Tagged) { out.push(head(6, v.tag)); return enc(v.value, out); }
  if (Array.isArray(v)) { out.push(head(4, v.length)); for (const x of v) enc(x, out); return; }
  if (v instanceof Map) { out.push(head(5, v.size)); for (const [k, x] of v) { enc(k, out); enc(x, out); } return; }
  if (typeof v === "object") { const e = Object.entries(v).filter(([, x]) => x !== undefined); out.push(head(5, e.length)); for (const [k, x] of e) { enc(k, out); enc(x, out); } return; }
  throw new CborError(`can't encode ${typeof v}`);
}

export function encode(v) {
  const parts = [];
  enc(v, parts);
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/* ---------------- decode ---------------- */

const MAX_DEPTH = 64;

function half(h) {
  const s = h & 0x8000 ? -1 : 1, e = (h >> 10) & 0x1f, f = h & 0x3ff;
  if (e === 0) return s * 2 ** -14 * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * 2 ** (e - 15) * (1 + f / 1024);
}

function decodeAt(b, pos, depth) {
  if (depth > MAX_DEPTH) throw new CborError("CBOR nested too deeply");
  if (pos >= b.length) throw new CborError("CBOR ended early");
  const start = pos;
  const ib = b[pos++];
  const major = ib >> 5, ai = ib & 0x1f;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const need = (n) => { if (pos + n > b.length) throw new CborError("CBOR ended early"); };
  let n;
  if (ai < 24) n = ai;
  else if (ai === 24) { need(1); n = b[pos]; pos += 1; }
  else if (ai === 25) { need(2); n = dv.getUint16(pos); pos += 2; }
  else if (ai === 26) { need(4); n = dv.getUint32(pos); pos += 4; }
  else if (ai === 27) { need(8); const big = dv.getBigUint64(pos); pos += 8; n = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big; }
  else if (ai === 31) n = -1; // indefinite
  else throw new CborError("CBOR reserved value");

  if (major === 7) {
    if (ai === 25) return [half(n), pos];
    if (ai === 26) return [dv.getFloat32(pos - 4), pos];
    if (ai === 27) return [dv.getFloat64(pos - 8), pos];
    if (ai === 31) throw new CborError("unexpected CBOR break");
    if (n === 20) return [false, pos];
    if (n === 21) return [true, pos];
    if (n === 22) return [null, pos];
    if (n === 23) return [undefined, pos];
    throw new CborError(`unknown CBOR simple value ${n}`);
  }
  if (n === -1 && (major === 0 || major === 1 || major === 6)) throw new CborError("CBOR indefinite length not allowed here");
  if (typeof n === "bigint" && major >= 2 && major <= 5) throw new CborError("CBOR length too large");

  switch (major) {
    case 0: return [n, pos];
    case 1: return [typeof n === "bigint" ? -1n - n : -1 - n, pos];
    case 2:
    case 3: {
      let bytes;
      if (n === -1) {
        const chunks = [];
        while (b[pos] !== 0xff) {
          if ((b[pos] >> 5) !== major) throw new CborError("CBOR chunk of the wrong type");
          const [c, p] = decodeAt(b, pos, depth + 1);
          chunks.push(major === 2 ? c : te.encode(c)); pos = p;
          if (pos >= b.length) throw new CborError("CBOR ended early");
        }
        pos++;
        bytes = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
        let o = 0; for (const c of chunks) { bytes.set(c, o); o += c.length; }
      } else { need(n); bytes = b.slice(pos, pos + n); pos += n; }
      if (major === 2) return [bytes, pos];
      try { return [td.decode(bytes), pos]; } catch { throw new CborError("CBOR text isn't valid UTF-8"); }
    }
    case 4: {
      const a = [];
      if (n === -1) { while (b[pos] !== 0xff) { const [v, p] = decodeAt(b, pos, depth + 1); a.push(v); pos = p; if (pos >= b.length) throw new CborError("CBOR ended early"); } pos++; }
      else for (let i = 0; i < n; i++) { const [v, p] = decodeAt(b, pos, depth + 1); a.push(v); pos = p; }
      return [a, pos];
    }
    case 5: {
      const m = new Map();
      const one = () => {
        const [k, p1] = decodeAt(b, pos, depth + 1);
        const [v, p2] = decodeAt(b, p1, depth + 1);
        const key = k instanceof Uint8Array ? hex(k) : k; // byte-string keys compared by value
        if (m.has(key)) throw new CborError("CBOR map has a duplicate key");
        m.set(key, v); pos = p2;
      };
      if (n === -1) { while (b[pos] !== 0xff) { one(); if (pos >= b.length) throw new CborError("CBOR ended early"); } pos++; }
      else for (let i = 0; i < n; i++) one();
      return [m, pos];
    }
    case 6: {
      const [v, p] = decodeAt(b, pos, depth + 1);
      if (n === 24) {
        if (!(v instanceof Uint8Array)) throw new CborError("CBOR tag 24 must wrap a byte string");
        return [new Encoded(v, b.slice(start, p)), p];
      }
      return [new Tagged(n, v), p];
    }
  }
  throw new CborError("bad CBOR");
}

const hex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, "0")).join("");

/** Decode exactly one item; trailing bytes are an error. */
export function decode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const [v, end] = decodeAt(b, 0, 0);
  if (end !== b.length) throw new CborError("CBOR has trailing bytes");
  return v;
}

/** Look up a key in a decoded map (or plain object). */
export const get = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);

/** Decoded value → plain JSON-friendly JS: Map → object, full-date/tdate tags → strings, Encoded → its value. */
export function plain(v) {
  if (v instanceof Encoded) return plain(v.value);
  if (v instanceof Tagged) return v.tag === 0 || v.tag === 1004 ? String(v.value) : v.tag === 1 ? new Date(Number(v.value) * 1000).toISOString() : plain(v.value);
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), plain(x)]));
  if (Array.isArray(v)) return v.map(plain);
  if (typeof v === "bigint") return v.toString();
  return v;
}
