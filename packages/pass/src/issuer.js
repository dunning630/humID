// @humid/pass/issuer — the server's half (Node only). Signs blinded passes with
// OpenSSL's RSA private-key operation (CRT, with OpenSSL's own blinding against
// timing), and checks every signature before releasing it (RFC 9474 §4.3: a
// faulty signature can leak the private key).

import { generateKeyPairSync, createPrivateKey, privateDecrypt, publicEncrypt, createPublicKey, constants, timingSafeEqual } from "node:crypto";
import { keyIdOf, importKey, b64u, unb64u, PassError } from "./index.js";

export const KEY_BITS = 4096;

/** A new issuer key. `pem` is the private key: keep it on the issuer's own volume. */
export function newIssuerKey(bits = KEY_BITS) {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: bits, publicExponent: 65537 });
  return issuerKey(privateKey.export({ type: "pkcs8", format: "pem" }));
}

/** Load a private key and derive its public form { id, n, e } as the app sees it. */
export function issuerKey(pem) {
  const sk = createPrivateKey(pem);
  const jwk = createPublicKey(sk).export({ format: "jwk" });
  const nB = unb64u(jwk.n), eB = unb64u(jwk.e);
  const pub = importKey({ n: b64u(nB), e: b64u(eB) });
  return { id: keyIdOf(nB, eB), pem, sk, pub, publicView: { id: pub.id, n: pub.n64, e: pub.e64, bits: pub.bits } };
}

/** BlindSign: s = blinded^d mod n, checked. */
export function blindSign(key, blinded) {
  const k = key.pub.k;
  if (!(blinded instanceof Uint8Array) || blinded.length !== k) throw new PassError("bad_request", "Blinded pass has the wrong length");
  // OpenSSL rejects inputs >= n itself; NO_PADDING makes this the raw RSASP1 primitive.
  let s;
  try { s = privateDecrypt({ key: key.sk, padding: constants.RSA_NO_PADDING }, blinded); }
  catch { throw new PassError("bad_request", "Blinded pass is out of range"); }
  const back = publicEncrypt({ key: createPublicKey(key.sk), padding: constants.RSA_NO_PADDING }, s);
  if (!timingSafeEqual(back, Buffer.from(blinded))) throw new PassError("signing_fault", "Signature check failed");
  return new Uint8Array(s);
}
