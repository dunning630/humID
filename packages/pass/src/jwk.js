// @humid/pass/jwk — a signer for the in-app SIMULATION build only, where the
// "server" runs inside the browser and Node's OpenSSL isn't available. Plain
// BigInt, not constant-time: never use it for a real server.

import { importKey, unb64u, os2ip, i2osp, modPow, PassError } from "./index.js";

/** A new simulation issuer key from WebCrypto. */
export async function newSimIssuerKey(bits = 2048) {
  const kp = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-384" }, true, ["sign", "verify"]);
  return simIssuerKey(await crypto.subtle.exportKey("jwk", kp.privateKey));
}

/** Load a private JWK { n, e, d, p, q, dp, dq, qi }. */
export function simIssuerKey(jwk) {
  const pub = importKey({ n: jwk.n, e: jwk.e });
  const big = (s) => os2ip(unb64u(s));
  const [p, q, dp, dq, qi] = [jwk.p, jwk.q, jwk.dp, jwk.dq, jwk.qi].map(big);
  return { id: pub.id, jwk, pub, publicView: { id: pub.id, n: pub.n64, e: pub.e64, bits: pub.bits }, crt: { p, q, dp, dq, qi } };
}

export function blindSignJwk(key, blinded) {
  const { n, e, k } = key.pub;
  if (blinded.length !== k) throw new PassError("bad_request", "Blinded pass has the wrong length");
  const m = os2ip(blinded);
  if (m >= n) throw new PassError("bad_request", "Blinded pass is out of range");
  const { p, q, dp, dq, qi } = key.crt;
  const m1 = modPow(m, dp, p), m2 = modPow(m, dq, q);
  const s = (m2 + q * ((((m1 - m2) % p) + p) * qi % p)) % n;
  if (modPow(s, e, n) !== m) throw new PassError("signing_fault", "Signature check failed");
  return i2osp(s, k);
}
