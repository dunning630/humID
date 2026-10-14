// Minimal CBOR decoder for Apple App Attest attestation objects: definite
// lengths only; unsigned/negative integers, byte and text strings, arrays,
// maps, tags (unwrapped) and the simple values false/true/null.

export class CborError extends Error {}

export function decodeCbor(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const td = new TextDecoder("utf-8", { fatal: true });
  let p = 0;
  const need = (n) => { if (p + n > buf.length) throw new CborError("CBOR: truncated"); };

  function length(ai) {
    if (ai < 24) return ai;
    if (ai === 24) { need(1); return buf[p++]; }
    if (ai === 25) { need(2); const v = view.getUint16(p); p += 2; return v; }
    if (ai === 26) { need(4); const v = view.getUint32(p); p += 4; return v; }
    if (ai === 27) {
      need(8);
      const v = view.getBigUint64(p); p += 8;
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("CBOR: integer too large");
      return Number(v);
    }
    throw new CborError("CBOR: indefinite or reserved length");
  }

  function item(depth) {
    if (depth > 16) throw new CborError("CBOR: nested too deeply");
    need(1);
    const ib = buf[p++];
    const major = ib >> 5;
    const ai = ib & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new CborError("CBOR: unsupported simple value");
    }
    const n = length(ai);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { need(n); const b = buf.slice(p, p + n); p += n; return b; }
      case 3: { need(n); const s = td.decode(buf.subarray(p, p + n)); p += n; return s; }
      case 4: { const a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: {
        const m = new Map();
        for (let i = 0; i < n; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); }
        return m;
      }
      case 6: return item(depth + 1);
      default: throw new CborError("CBOR: bad major type");
    }
  }

  const out = item(0);
  if (p !== buf.length) throw new CborError("CBOR: trailing bytes");
  return out;
}
