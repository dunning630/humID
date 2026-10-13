// Minimal DER reader: enough to walk X.509 certificates and the Android
// KeyDescription extension. Strict: every length must fit its parent, and
// indefinite lengths (not allowed in DER) are refused.

export const CLASS = { universal: 0, application: 1, context: 2, private: 3 };
export const TAG = { boolean: 1, integer: 2, bitString: 3, octetString: 4, null: 5, oid: 6, enumerated: 10, sequence: 16, set: 17 };

export class DerError extends Error {}

/** Read one TLV at `pos`. Tag numbers above 30 (high-tag form) are supported. */
export function readTLV(bytes, pos = 0) {
  const start = pos;
  if (pos >= bytes.length) throw new DerError("DER: truncated");
  let b = bytes[pos++];
  const cls = b >> 6;
  const constructed = (b & 0x20) !== 0;
  let tag = b & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    let n = 0;
    do {
      if (pos >= bytes.length || ++n > 4) throw new DerError("DER: bad tag");
      b = bytes[pos++];
      tag = tag * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (pos >= bytes.length) throw new DerError("DER: truncated");
  let len = bytes[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new DerError("DER: bad length");
    len = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= bytes.length) throw new DerError("DER: truncated");
      len = len * 256 + bytes[pos++];
    }
  }
  const end = pos + len;
  if (end > bytes.length) throw new DerError("DER: length past end");
  return { cls, constructed, tag, start, end, value: bytes.subarray(pos, end), raw: bytes.subarray(start, end) };
}

/** Parse exactly one TLV covering all of `bytes`. */
export function parse(bytes) {
  const t = readTLV(bytes, 0);
  if (t.end !== bytes.length) throw new DerError("DER: trailing bytes");
  return t;
}

/** The TLVs inside a constructed value. */
export function kids(t) {
  const out = [];
  let p = 0;
  while (p < t.value.length) {
    const c = readTLV(t.value, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

export const is = (t, cls, tag) => t && t.cls === cls && t.tag === tag;

/** Small non-negative INTEGER / ENUMERATED (up to 2^53). */
export function int(t) {
  if (!t || t.cls !== CLASS.universal || (t.tag !== TAG.integer && t.tag !== TAG.enumerated)) throw new DerError("DER: not an integer");
  const v = t.value;
  if (!v.length) throw new DerError("DER: empty integer");
  if (v[0] & 0x80) throw new DerError("DER: negative integer");
  let n = 0;
  for (const b of v) {
    n = n * 256 + b;
    if (n > Number.MAX_SAFE_INTEGER) throw new DerError("DER: integer too large");
  }
  return n;
}

export function bool(t) {
  if (!is(t, CLASS.universal, TAG.boolean) || t.value.length !== 1) throw new DerError("DER: not a boolean");
  return t.value[0] !== 0;
}

export function octets(t) {
  if (!is(t, CLASS.universal, TAG.octetString)) throw new DerError("DER: not an octet string");
  return t.value;
}

export function oid(t) {
  if (!is(t, CLASS.universal, TAG.oid) || !t.value.length) throw new DerError("DER: not an OID");
  const v = t.value;
  const parts = [];
  let n = 0;
  for (let i = 0; i < v.length; i++) {
    n = n * 128 + (v[i] & 0x7f);
    if (!(v[i] & 0x80)) { parts.push(n); n = 0; }
  }
  const first = parts.shift();
  const a = first < 80 ? Math.floor(first / 40) : 2;
  return [a, first - a * 40, ...parts].join(".");
}

/** The value (inner DER) of an X.509 v3 extension, or null if absent. */
export function certExtension(certDer, wanted) {
  const cert = parse(certDer);
  const tbs = kids(cert)[0];
  const ext = kids(tbs).find((t) => t.cls === CLASS.context && t.tag === 3);
  if (!ext) return null;
  for (const e of kids(kids(ext)[0])) {
    const k = kids(e);
    if (oid(k[0]) === wanted) return octets(k[k.length - 1]);
  }
  return null;
}
