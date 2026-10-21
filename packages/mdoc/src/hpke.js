// HPKE (RFC 9180), base mode, one suite: DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256, AES-128-GCM. That is the suite ISO/IEC 18013-7 Annex C uses for
// mobile IDs requested through the browser's Digital Credentials API
// (protocol "org-iso-mdoc"), and the one Apple's in-app identity requests use.
//
// Only what a verifier needs: open one message. `seal` exists so tests and
// simulated wallets can talk to it; tests also check it against an
// independent implementation (@hpke/core).

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";

export class HpkeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const te = new TextEncoder();
const cat = (...parts) => { const n = parts.reduce((s, p) => s + p.length, 0); const o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };
const i2osp = (n, w) => { const b = new Uint8Array(w); for (let i = w - 1; i >= 0; i--) { b[i] = n & 0xff; n >>>= 8; } return b; };

const KEM_ID = 0x0010, KDF_ID = 0x0001, AEAD_ID = 0x0001;
const N_SECRET = 32, N_K = 16, N_N = 12;
const V1 = te.encode("HPKE-v1");
const KEM_SUITE = cat(te.encode("KEM"), i2osp(KEM_ID, 2));
const SUITE = cat(te.encode("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
const EMPTY = new Uint8Array(0);

const labeledExtract = (suite, salt, label, ikm) => extract(sha256, cat(V1, suite, te.encode(label), ikm), salt);
const labeledExpand = (suite, prk, label, info, len) => expand(sha256, prk, cat(i2osp(len, 2), V1, suite, te.encode(label), info), len);

function sharedSecret(dh, enc, pkR) {
  const prk = labeledExtract(KEM_SUITE, EMPTY, "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", cat(enc, pkR), N_SECRET);
}

function schedule(ss, info) {
  const pskIdHash = labeledExtract(SUITE, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(SUITE, EMPTY, "info_hash", info);
  const ctx = cat(Uint8Array.of(0), pskIdHash, infoHash);
  const secret = labeledExtract(SUITE, ss, "secret", EMPTY);
  return { key: labeledExpand(SUITE, secret, "key", ctx, N_K), nonce: labeledExpand(SUITE, secret, "base_nonce", ctx, N_N) };
}

const point = (bytes, what) => {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 65 || bytes[0] !== 4) throw new HpkeError("bad_key", `The ${what} isn't an uncompressed P-256 point.`);
  try { p256.Point.fromBytes(bytes); } catch { throw new HpkeError("bad_key", `The ${what} isn't on the P-256 curve.`); }
  return bytes;
};

/** A fresh recipient key pair. publicKey: 65-byte uncompressed point. */
export function hpkeKeyPair(secretKey = p256.utils.randomSecretKey()) {
  return { secretKey, publicKey: p256.getPublicKey(secretKey, false) };
}

/** Open a single-shot HPKE message (sequence number 0). Throws HpkeError("decrypt") on any failure. */
export function hpkeOpen({ secretKey, publicKey }, enc, ciphertext, { info = EMPTY, aad = EMPTY } = {}) {
  point(enc, "sender's ephemeral key");
  const pkR = publicKey || p256.getPublicKey(secretKey, false);
  const dh = p256.getSharedSecret(secretKey, enc, true).slice(1);
  const { key, nonce } = schedule(sharedSecret(dh, enc, pkR), info);
  try { return gcm(key, nonce, aad).decrypt(ciphertext); }
  catch { throw new HpkeError("decrypt", "The response couldn't be decrypted. It wasn't made for this request."); }
}

/** Seal a single-shot message to `publicKey` (tests and simulated wallets). Returns { enc, ciphertext }. */
export function hpkeSeal(publicKey, plaintext, { info = EMPTY, aad = EMPTY, ephemeralSecret } = {}) {
  point(publicKey, "recipient key");
  const e = hpkeKeyPair(ephemeralSecret);
  const dh = p256.getSharedSecret(e.secretKey, publicKey, true).slice(1);
  const { key, nonce } = schedule(sharedSecret(dh, e.publicKey, publicKey), info);
  return { enc: e.publicKey, ciphertext: gcm(key, nonce, aad).encrypt(plaintext) };
}
