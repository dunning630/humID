// ECDSA signature shape (ATT-01). For any valid ECDSA signature (r, s), (r, n − s)
// is valid too, so anyone who sees one can make a second, different one without
// the key. HumID's own liveness keys must use the low half (s ≤ n/2) so each
// approval has exactly one valid encoding. The phones' secure hardware doesn't
// guarantee that by itself: the app normalises (packages/gate/src/lows.js).
//
// Who requires low-S, and who doesn't:
//   verifyLiveSig (HumID liveness keys: sign-in, step-up, seal, admin approvals)  required
//   @humid/mdoc COSE and X.509, @humid/sdjwt JWS, @humid/anchor Active Authentication,
//   @humid/wallet X.509, FIDO security keys in recovery                             not required:
//     ISO 18013-5, RFC 5480, RFC 7518, ICAO 9303 and WebAuthn don't require it, and
//     issuers, chips and authenticators sign with either half. Those checks trust
//     what was signed, never the signature bytes, so a second encoding gains nothing.

import { parse, kids, is, CLASS, TAG } from "./der.js";

/** The order of the P-256 group. */
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** A positive, minimally encoded DER INTEGER as a BigInt; throws otherwise. */
function uint(t) {
  if (!is(t, CLASS.universal, TAG.integer) || t.constructed) throw new Error("not an integer");
  const v = t.value;
  if (!v.length || v[0] & 0x80) throw new Error("not positive");
  if (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) throw new Error("not minimal");
  return BigInt("0x" + Buffer.from(v).toString("hex"));
}

/** { r, s } of a DER ECDSA-Sig-Value, or null when it isn't exactly one. */
export function ecdsaRS(sig) {
  try {
    const t = parse(Uint8Array.from(sig));
    if (!is(t, CLASS.universal, TAG.sequence) || !t.constructed) return null;
    const k = kids(t);
    if (k.length !== 2) return null;
    return { r: uint(k[0]), s: uint(k[1]) };
  } catch { return null; }
}

/** True when `sig` is a well-formed DER signature with 0 < r < n and 0 < s ≤ n/2. */
export function isLowS(sig, n = P256_N) {
  const rs = sig && ecdsaRS(sig);
  return !!rs && rs.r > 0n && rs.r < n && rs.s > 0n && rs.s <= n >> 1n;
}
