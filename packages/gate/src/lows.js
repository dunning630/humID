// Low-S for liveness signatures (ATT-01). The Android Keystore and the Secure
// Enclave return either of the two valid forms of an ECDSA signature, (r, s) or
// (r, n − s). Servers accept only the low one (s ≤ n/2), so each approval has
// one encoding; this turns the high form into the low one. No key is involved:
// it is the same signature, written the other way.

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; // P-256 order

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function derInt(x) {
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  const b = h.match(/../g).map((p) => parseInt(p, 16));
  if (b[0] & 0x80) b.unshift(0);
  return [0x02, b.length, ...b];
}

/** The low-S form of a DER ECDSA P-256 signature (unchanged if it already is, or isn't one). */
export function lowS(sig) {
  const d = Uint8Array.from(sig);
  // SEQUENCE (short form) { INTEGER r, INTEGER s }: always under 128 bytes for P-256
  if (d.length < 8 || d[0] !== 0x30 || d[1] !== d.length - 2 || d[2] !== 0x02) return d;
  const rLen = d[3];
  const sAt = 4 + rLen;
  if (d[sAt] !== 0x02 || sAt + 2 + d[sAt + 1] !== d.length) return d;
  const s = BigInt("0x" + hex(d.subarray(sAt + 2)));
  if (s <= N >> 1n || s >= N) return d;
  const r = d.subarray(4, sAt);
  const body = [0x02, rLen, ...r, ...derInt(N - s)];
  return Uint8Array.from([0x30, body.length, ...body]);
}
