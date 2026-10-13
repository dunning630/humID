// Bytes, ISO 7816 APDUs and BER-TLV, as ICAO 9303 uses them.

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (s) => Uint8Array.from(String(s).replace(/\s+/g, "").match(/../g) || [], (h) => parseInt(h, 16));
export const utf8 = (s) => new TextEncoder().encode(s);
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const u32be = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

/** ISO/IEC 9797-1 padding method 2: 0x80 then zeros up to the block size. */
export function pad(data, block) {
  const n = data.length + 1;
  const out = new Uint8Array(Math.ceil(n / block) * block);
  out.set(data); out[data.length] = 0x80;
  return out;
}
export function unpad(data) {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  if (i < 0 || data[i] !== 0x80) throw new ChipError("bad_padding", "The chip's answer had bad padding.");
  return data.subarray(0, i);
}

/** Increment a big-endian counter in place (the secure-messaging send sequence counter). */
export function increment(ssc) {
  for (let i = ssc.length - 1; i >= 0; i--) { ssc[i] = (ssc[i] + 1) & 255; if (ssc[i]) break; }
  return ssc;
}

export class ChipError extends Error {
  constructor(code, message, sw) { super(message); this.code = code; this.sw = sw; }
}

/* ---------------- BER-TLV ---------------- */

export function encodeLength(n) {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  if (n < 0x10000) return Uint8Array.of(0x82, n >> 8, n & 255);
  return Uint8Array.of(0x83, n >> 16, (n >> 8) & 255, n & 255);
}
const tagBytes = (tag) => (tag > 0xffff ? Uint8Array.of(tag >> 16, (tag >> 8) & 255, tag & 255) : tag > 0xff ? Uint8Array.of(tag >> 8, tag & 255) : Uint8Array.of(tag));
export const tlv = (tag, value) => concat(tagBytes(tag), encodeLength(value.length), value);

/** Read one TLV at `pos`. Returns { tag, value, end, headerLength }. */
export function readTlv(b, pos = 0) {
  const start = pos;
  if (pos >= b.length) throw new ChipError("bad_tlv", "Truncated data from the chip.");
  let tag = b[pos++];
  if ((tag & 0x1f) === 0x1f) { do { if (pos >= b.length) throw new ChipError("bad_tlv", "Truncated tag."); tag = (tag << 8) | b[pos]; } while (b[pos++] & 0x80); }
  if (pos >= b.length) throw new ChipError("bad_tlv", "Truncated length.");
  let len = b[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3) throw new ChipError("bad_tlv", "Bad length from the chip.");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[pos++];
  }
  if (pos + len > b.length) throw new ChipError("bad_tlv", "Length past the end of the chip's data.");
  return { tag, value: b.subarray(pos, pos + len), end: pos + len, headerLength: pos - start };
}
export function readTlvs(b) {
  const out = new Map();
  let p = 0;
  while (p < b.length) { if (b[p] === 0x00 || b[p] === 0xff) { p++; continue; } const t = readTlv(b, p); out.set(t.tag, t.value); p = t.end; }
  return out;
}

/** The total length of a file from its first bytes (tag + length), or null if more bytes are needed. */
export function tlvTotalLength(head) {
  try { const t = readTlv(head, 0); return t.headerLength + t.value.length; }
  catch (e) {
    // readTlv throws when the value runs past `head`; work out the length from the header alone.
    let pos = 1;
    if ((head[0] & 0x1f) === 0x1f) while (head[pos++] & 0x80);
    let len = head[pos++];
    if (len === undefined) return null;
    if (len & 0x80) { const n = len & 0x7f; if (pos + n > head.length) return null; len = 0; for (let i = 0; i < n; i++) len = len * 256 + head[pos++]; }
    return pos + len;
  }
}

/** DER OID text → content bytes (no tag/length). */
export function oidBytes(s) {
  const p = s.split(".").map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const b = []; let v = n;
    do { b.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v);
    for (let i = 0; i < b.length - 1; i++) b[i] |= 0x80;
    out.push(...b);
  }
  return Uint8Array.from(out);
}
export function oidText(content) {
  const parts = []; let n = 0;
  for (const b of content) { n = n * 128 + (b & 0x7f); if (!(b & 0x80)) { parts.push(n); n = 0; } }
  const first = parts.shift();
  const a = first < 80 ? Math.floor(first / 40) : 2;
  return [a, first - a * 40, ...parts].join(".");
}

/* ---------------- APDUs ---------------- */

/** { cla, ins, p1, p2, data?, le? } → bytes. le: 1..65536 (256 = "00" short). Uses extended length only when needed. */
export function encodeApdu({ cla, ins, p1, p2, data, le }) {
  const h = Uint8Array.of(cla, ins, p1, p2);
  const d = data && data.length ? data : null;
  const ext = (d && d.length > 255) || (le != null && le > 256);
  if (!ext) {
    return concat(h, d ? concat(Uint8Array.of(d.length), d) : new Uint8Array(0), le != null ? Uint8Array.of(le === 256 ? 0 : le) : new Uint8Array(0));
  }
  const lc = d ? concat(Uint8Array.of(0, d.length >> 8, d.length & 255), d) : new Uint8Array(0);
  const leb = le != null ? (d ? Uint8Array.of((le >> 8) & 255, le & 255) : Uint8Array.of(0, (le >> 8) & 255, le & 255)) : new Uint8Array(0);
  return concat(h, lc, leb);
}

/** bytes → { cla, ins, p1, p2, data, le } (used by the simulated chip in tests). */
export function decodeApdu(b) {
  const [cla, ins, p1, p2] = b;
  const body = b.subarray(4);
  if (!body.length) return { cla, ins, p1, p2, data: new Uint8Array(0), le: null };
  if (body.length === 1) return { cla, ins, p1, p2, data: new Uint8Array(0), le: body[0] || 256 };
  if (body[0] === 0 && body.length >= 3) {
    if (body.length === 3) return { cla, ins, p1, p2, data: new Uint8Array(0), le: ((body[1] << 8) | body[2]) || 65536 };
    const lc = (body[1] << 8) | body[2];
    const data = body.subarray(3, 3 + lc);
    const rest = body.subarray(3 + lc);
    return { cla, ins, p1, p2, data, le: rest.length ? ((rest[0] << 8) | rest[1]) || 65536 : null };
  }
  const lc = body[0];
  const data = body.subarray(1, 1 + lc);
  const rest = body.subarray(1 + lc);
  return { cla, ins, p1, p2, data, le: rest.length ? rest[0] || 256 : null };
}

export const swOf = (r) => (r[r.length - 2] << 8) | r[r.length - 1];
export const bodyOf = (r) => r.subarray(0, r.length - 2);
