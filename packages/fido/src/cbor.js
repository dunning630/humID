// CTAP2 canonical CBOR (CTAP 2.1 §8): the subset FIDO2 uses, nothing else.
//
// Encoding is canonical: shortest integer forms, definite lengths, map keys sorted by
// their encoded bytes (shorter first, then bytewise). Maps with integer keys are passed
// as `Map`s; maps with text keys may be plain objects.
//
// Decoding reads what an authenticator sends, which is untrusted input from a device
// held to the phone. It refuses anything outside that subset (tags, floats, indefinite
// lengths, integers beyond 2^53) and is bounded: depth, item count and total size.

export class CborError extends Error {
  constructor(message) { super(message); this.name = "CborError"; this.code = "invalid_cbor"; }
}

export const LIMITS = Object.freeze({ bytes: 64 * 1024, depth: 8, items: 512 });

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

/* ---------------- encode ---------------- */

function head(major, n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new CborError("Integer out of range");
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of(m | 26, n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  const hi = Math.floor(n / 0x100000000), lo = n >>> 0;
  return Uint8Array.of(m | 27, hi >>> 24, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** CTAP2 canonical order: shorter encoded key first, then bytewise. */
function compareKeys(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function enc(v, parts) {
  if (v === true) { parts.push(Uint8Array.of(0xf5)); return; }
  if (v === false) { parts.push(Uint8Array.of(0xf4)); return; }
  if (v === null) { parts.push(Uint8Array.of(0xf6)); return; }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new CborError("Only integers can be encoded");
    parts.push(v >= 0 ? head(0, v) : head(1, -1 - v));
    return;
  }
  if (typeof v === "string") { const b = te.encode(v); parts.push(head(3, b.length), b); return; }
  if (v instanceof Uint8Array) { parts.push(head(2, v.length), v); return; }
  if (Array.isArray(v)) {
    parts.push(head(4, v.length));
    for (const x of v) enc(x, parts);
    return;
  }
  const entries = v instanceof Map ? [...v.entries()] : (v && typeof v === "object" ? Object.entries(v) : null);
  if (!entries) throw new CborError(`Can't encode ${typeof v}`);
  const kept = entries.filter(([, x]) => x !== undefined).map(([k, x]) => [encode(k), x]);
  kept.sort((a, b) => compareKeys(a[0], b[0]));
  for (let i = 1; i < kept.length; i++) if (compareKeys(kept[i - 1][0], kept[i][0]) === 0) throw new CborError("Duplicate map key");
  parts.push(head(5, kept.length));
  for (const [k, x] of kept) { parts.push(k); enc(x, parts); }
}

/** Encode a value. Map entries whose value is `undefined` are left out. */
export function encode(v) {
  const parts = [];
  enc(v, parts);
  return concat(parts);
}

/* ---------------- decode ---------------- */

/**
 * Decode one item from the start of `bytes`. Returns { value, length }.
 * Maps decode to `Map`s (keys: integers or strings), byte strings to Uint8Array copies.
 */
export function decodeFirst(bytes, limits = LIMITS) {
  if (!(bytes instanceof Uint8Array)) throw new CborError("Expected bytes");
  if (bytes.length > limits.bytes) throw new CborError("CBOR message too large");
  let o = 0, items = 0;
  const need = (n) => { if (o + n > bytes.length) throw new CborError("CBOR ends early"); };
  const arg = (info) => {
    if (info < 24) return info;
    if (info === 24) { need(1); return bytes[o++]; }
    if (info === 25) { need(2); const v = (bytes[o] << 8) | bytes[o + 1]; o += 2; return v; }
    if (info === 26) { need(4); const v = ((bytes[o] << 24) >>> 0) + (bytes[o + 1] << 16) + (bytes[o + 2] << 8) + bytes[o + 3]; o += 4; return v; }
    if (info === 27) {
      need(8);
      const hi = ((bytes[o] << 24) >>> 0) + (bytes[o + 1] << 16) + (bytes[o + 2] << 8) + bytes[o + 3];
      const lo = ((bytes[o + 4] << 24) >>> 0) + (bytes[o + 5] << 16) + (bytes[o + 6] << 8) + bytes[o + 7];
      o += 8;
      const v = hi * 0x100000000 + lo;
      if (!Number.isSafeInteger(v)) throw new CborError("Integer too large");
      return v;
    }
    throw new CborError("Indefinite lengths and reserved values aren't allowed");
  };
  const item = (depth) => {
    if (depth > limits.depth) throw new CborError("CBOR nested too deeply");
    if (++items > limits.items) throw new CborError("CBOR has too many items");
    need(1);
    const ib = bytes[o++], major = ib >> 5, info = ib & 31;
    switch (major) {
      case 0: return arg(info);
      case 1: return -1 - arg(info);
      case 2: { const n = arg(info); need(n); const v = bytes.slice(o, o + n); o += n; return v; }
      case 3: {
        const n = arg(info); need(n);
        let s;
        try { s = td.decode(bytes.subarray(o, o + n)); } catch { throw new CborError("Text isn't valid UTF-8"); }
        o += n; return s;
      }
      case 4: { const n = arg(info); if (n > limits.items) throw new CborError("CBOR has too many items"); const a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: {
        const n = arg(info); if (n > limits.items) throw new CborError("CBOR has too many items");
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (typeof k !== "number" && typeof k !== "string") throw new CborError("Map keys must be integers or text");
          if (m.has(k)) throw new CborError("Duplicate map key");
          m.set(k, item(depth + 1));
        }
        return m;
      }
      case 7:
        if (ib === 0xf4) return false;
        if (ib === 0xf5) return true;
        if (ib === 0xf6) return null;
        throw new CborError("Floats and other simple values aren't allowed");
      default: throw new CborError("CBOR tags aren't allowed");
    }
  };
  const value = item(0);
  return { value, length: o };
}

/** Decode exactly one item; trailing bytes are an error. */
export function decode(bytes, limits = LIMITS) {
  const { value, length } = decodeFirst(bytes, limits);
  if (length !== bytes.length) throw new CborError("Trailing bytes after CBOR");
  return value;
}
