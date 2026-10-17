// Just enough DER for X.509 certificates and a CMS signature. Strict: lengths must fit
// their parent, small tag and length forms only. Indefinite lengths (BER) only where a
// caller allows them: the CMS wrapper, which some pass-signing tools write that way;
// never the bytes a signature covers. Anything else is a WalletError, never an
// out-of-range read.
import { WalletError } from "./zip.js";

const bad = (m = "The pass's signature can't be read.") => { throw new WalletError("bad_signature", m); };

export function readTLV(b, pos = 0, ber = false, depth = 0) {
  if (depth > 32) bad();
  const start = pos;
  if (pos >= b.length) bad();
  let t = b[pos++];
  const cls = t >> 6, constructed = (t & 0x20) !== 0;
  let tag = t & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    for (let n = 0; ; n++) {
      if (pos >= b.length || n > 3) bad();
      t = b[pos++];
      tag = tag * 128 + (t & 0x7f);
      if (!(t & 0x80)) break;
    }
  }
  if (pos >= b.length) bad();
  let len = b[pos++];
  if (len === 0x80) {
    // indefinite length: constructed only, children until an end-of-contents (00 00)
    if (!ber || !constructed) bad();
    let p = pos;
    for (;;) {
      if (p + 2 > b.length) bad();
      if (b[p] === 0 && b[p + 1] === 0) break;
      p = readTLV(b, p, true, depth + 1).end;
    }
    return { cls, constructed, tag, value: b.subarray(pos, p), raw: b.subarray(start, p + 2), end: p + 2, ber, indefinite: true };
  }
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || pos + n > b.length) bad();
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[pos++];
  }
  if (pos + len > b.length) bad();
  return { cls, constructed, tag, value: b.subarray(pos, pos + len), raw: b.subarray(start, pos + len), end: pos + len, ber };
}

/** One element covering all of b. ber: allow indefinite lengths (inherited by kids()). */
export function parse(b, ber = false) {
  const t = readTLV(b, 0, ber);
  if (t.end !== b.length) bad();
  return t;
}

export function kids(t) {
  if (!t?.constructed) bad();
  const out = [];
  for (let p = 0; p < t.value.length;) { const c = readTLV(t.value, p, !!t.ber); out.push(c); p = c.end; }
  return out;
}

export const isSeq = (t) => t && t.cls === 0 && t.tag === 16;
export const isSet = (t) => t && t.cls === 0 && t.tag === 17;
export const ctx = (t, n) => t && t.cls === 2 && t.tag === n;

export function oid(t) {
  if (!t || t.cls !== 0 || t.tag !== 6 || !t.value.length) bad();
  const v = t.value, parts = [];
  let n = 0;
  for (let i = 0; i < v.length; i++) {
    n = n * 128 + (v[i] & 0x7f);
    if (n > Number.MAX_SAFE_INTEGER) bad();
    if (!(v[i] & 0x80)) { parts.push(n); n = 0; }
  }
  if (v[v.length - 1] & 0x80) bad();
  const first = parts.shift();
  const a = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [a, first - a * 40, ...parts].join(".");
}

export function octets(t) {
  if (!t || t.cls !== 0 || t.tag !== 4) bad();
  return t.value;
}

/** BIT STRING contents without the unused-bits byte. */
export function bits(t) {
  if (!t || t.cls !== 0 || t.tag !== 3 || !t.value.length) bad();
  return t.value.subarray(1);
}

/** A string type (UTF8String, PrintableString, IA5String, T61String, BMPString) as text. */
export function text(t) {
  if (!t || t.cls !== 0) bad();
  if (t.tag === 30) { let s = ""; for (let i = 0; i + 1 < t.value.length; i += 2) s += String.fromCharCode((t.value[i] << 8) | t.value[i + 1]); return s; }
  if (![12, 19, 20, 22, 26].includes(t.tag)) bad();
  return new TextDecoder().decode(t.value);
}

/** UTCTime or GeneralizedTime → Date. */
export function time(t) {
  if (!t || t.cls !== 0 || (t.tag !== 23 && t.tag !== 24)) bad();
  const s = new TextDecoder().decode(t.value);
  const m = t.tag === 23 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) bad();
  let y = Number(m[1]);
  if (t.tag === 23) y += y < 50 ? 2000 : 1900;
  const d = new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  if (Number.isNaN(d.getTime())) bad();
  return d;
}

export const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
/** An INTEGER's bytes without leading zero padding. */
export const intBytes = (t) => { if (!t || t.cls !== 0 || t.tag !== 2 || !t.value.length) bad(); let i = 0; while (i < t.value.length - 1 && t.value[i] === 0) i++; return t.value.subarray(i); };
