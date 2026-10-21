// HUMID-PQ1 — the sealing suite shipped in the original HumID Vault.
//   KEM:  ML-KEM-1024 (FIPS 203) combined with X25519; both secrets feed the KDF
//   KDF:  HKDF-SHA3-256
//   AEAD: AES-256-GCM, 96-bit nonce, KEM material bound as associated data
//   Sign: ML-DSA-87 (FIPS 204) over "HUMID-MANIFEST-v1" || manifest JSON
//   Hash: SHA3-512 over plaintext and ciphertext
//
// Byte-for-byte compatible with envelopes and identities created by the
// original single-file app (tests/compat.test.js proves it against that bundle).
// Suites are frozen once released: a change to any primitive is a new suite id.

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import {
  concat, u32, readU32, toHex, toB64, fromB64, pack, unpack, encodeJSON, decodeJSON, utf8,
} from "@humid/codec";

export const ID = "HUMID-PQ1";
export const DESCRIPTION =
  "ML-KEM-1024 + X25519 hybrid KEM / HKDF-SHA3-256 / AES-256-GCM / ML-DSA-87 / SHA3-512";

const subtle = globalThis.crypto.subtle;
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const kdf = (ikm, salt, info, len = 32) => hkdf(sha3_256, ikm, salt, utf8(info), len);

export const wipe = (...bufs) => { for (const b of bufs) if (b && b.fill) b.fill(0); };

async function aesEncrypt(key, iv, plain, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, k, plain));
}

async function aesDecrypt(key, iv, ct, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, k, ct));
}

/** Expand the 64-byte identity seed into every key pair. Deterministic. */
export function deriveKeys(seed) {
  const kemSeed = kdf(seed, undefined, "HUMID-PQ1 ml-kem-1024", 64);
  const dsaSeed = kdf(seed, undefined, "HUMID-PQ1 ml-dsa-87", 32);
  const xSk = kdf(seed, undefined, "HUMID-PQ1 x25519", 32);
  const kem = ml_kem1024.keygen(kemSeed);
  const dsa = ml_dsa87.keygen(dsaSeed);
  wipe(kemSeed, dsaSeed);
  return {
    kemPk: kem.publicKey, kemSk: kem.secretKey,
    dsaPk: dsa.publicKey, dsaSk: dsa.secretKey,
    xPk: x25519.getPublicKey(xSk), xSk,
  };
}

export const wipeKeys = (k) => k && wipe(k.kemSk, k.dsaSk, k.xSk);
export const publicOf = (k) => ({ kemPk: k.kemPk, dsaPk: k.dsaPk, xPk: k.xPk });

export const identityCommit = (pub, credIdHash) =>
  sha3_256(concat(utf8("HUMID-ID-COMMIT-v1"), sha3_512(pub.kemPk), sha3_512(pub.dsaPk), pub.xPk, credIdHash));

/** Encrypt the identity seed under the secret the biometric gate releases. */
export async function wrapSeed(gateSecret, seed, aad) {
  const salt = random(32), nonce = random(12);
  const key = kdf(gateSecret, salt, "HUMID-PQ1 seed-wrap");
  const ct = await aesEncrypt(key, nonce, seed, aad);
  wipe(key);
  return { salt: toB64(salt), nonce: toB64(nonce), ct: toB64(ct) };
}

export async function unwrapSeed(gateSecret, wrapped, aad) {
  const key = kdf(gateSecret, fromB64(wrapped.salt), "HUMID-PQ1 seed-wrap");
  try { return await aesDecrypt(key, fromB64(wrapped.nonce), fromB64(wrapped.ct), aad); }
  finally { wipe(key); }
}

const payloadKey = (kemSs, xSs, kemCt, xEph, recipient) =>
  kdf(concat(kemSs, xSs), sha3_256(concat(kemCt, xEph, sha3_256(recipient.kemPk), recipient.xPk)), "HUMID-PQ1 payload-key");

const aeadAad = (kemCt, xEph, nonce) => concat(utf8(ID), kemCt, xEph, nonce);
const signedManifest = (mBytes) => concat(utf8("HUMID-MANIFEST-v1"), mBytes);

/**
 * Seal a file to a recipient and sign it with the holder's ML-DSA-87 key.
 * @param file {bytes, name, type}
 * @param signer full key set (needs dsaSk, dsaPk)
 * @param recipient {kemPk, xPk}
 * @param ctx {identityCommit, interrupt} — the interrupt record is signed into the manifest
 */
export async function seal(file, signer, recipient, ctx) {
  return finishSeal(await prepareSeal(file, recipient), signer, ctx);
}

/**
 * Seal in two steps (added in @humid/crypto 1.2.0; same envelope format).
 * prepareSeal encrypts with the recipient's PUBLIC keys only, so it needs no
 * biometric check. Its ciphertextHash is what the device's liveness key signs
 * during the check that then releases the signing key for finishSeal.
 */
export async function prepareSeal({ bytes, name, type }, recipient) {
  const plainHash = sha3_512(bytes);
  const meta = encodeJSON({ name, type: type || "application/octet-stream", size: bytes.length, sha3_512: toHex(plainHash) });
  const framed = concat(u32(meta.length), meta, bytes);

  const { cipherText: kemCt, sharedSecret: kemSs } = ml_kem1024.encapsulate(recipient.kemPk);
  const xEphSk = random(32);
  const xEph = x25519.getPublicKey(xEphSk);
  const xSs = x25519.getSharedSecret(xEphSk, recipient.xPk);
  const key = payloadKey(kemSs, xSs, kemCt, xEph, recipient);
  const nonce = random(12);
  const ct = await aesEncrypt(key, nonce, framed, aeadAad(kemCt, xEph, nonce));
  wipe(kemSs, xSs, xEphSk, key, framed);
  return { kemCt, xEph, nonce, ct, recipient, plainHash: toHex(plainHash), ciphertextHash: toHex(sha3_512(ct)) };
}

/** Sign the manifest. ctx: { identityCommit, interrupt } (the interrupt may carry the liveness signature). */
export function finishSeal(p, signer, ctx) {
  const manifest = {
    format: "humid-envelope", v: 1, suite: ID, suiteDesc: DESCRIPTION,
    created: new Date().toISOString(),
    kem: { mlkem1024Ct: toB64(p.kemCt), x25519Eph: toB64(p.xEph) },
    nonce: toB64(p.nonce),
    ciphertext: { bytes: p.ct.length, sha3_512: p.ciphertextHash },
    recipient: { kemPkFp: toHex(sha3_256(p.recipient.kemPk)) },
    signer: { mldsa87Pk: toB64(signer.dsaPk), identityCommit: ctx.identityCommit },
    interrupt: ctx.interrupt,
  };
  const mBytes = encodeJSON(manifest);
  const sig = ml_dsa87.sign(signedManifest(mBytes), signer.dsaSk);
  return { envelope: pack(mBytes, sig, p.ct), manifest, plainHash: p.plainHash };
}

/** Check signature and ciphertext hash. Needs no keys. */
export function verify(envelope) {
  const { manifest, manifestBytes, signature, ciphertext } = unpack(envelope);
  const sigOk = ml_dsa87.verify(signature, signedManifest(manifestBytes), fromB64(manifest.signer.mldsa87Pk));
  const ctOk = toHex(sha3_512(ciphertext)) === manifest.ciphertext.sha3_512;
  return { ok: sigOk && ctOk, sigOk, ctOk, manifest };
}

const sameBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};

/**
 * Verify, then decrypt with the holder's keys.
 *
 * The signature alone only proves that whoever made the envelope signed it: the key it
 * is checked against travels inside the envelope. Anyone holding the recipient's public
 * keys (every server, every recovery contact) can seal and sign one. So when the caller
 * knows who must have sealed it, it passes `signer` (that ML-DSA-87 public key) and an
 * envelope signed by anyone else is refused before anything is decrypted. A holder's own
 * documents are always sealed by the holder's account key, so the vault's read path
 * passes the account key here.
 */
export async function open(envelope, keys, { signer } = {}) {
  const v = verify(envelope);
  if (!v.ok) throw new Error(v.sigOk ? "Ciphertext does not match its signed hash." : "ML-DSA-87 signature is invalid.");
  if (signer && !sameBytes(fromB64(v.manifest.signer.mldsa87Pk), signer)) {
    throw Object.assign(new Error("This document wasn't sealed by your HumID, so it wasn't opened."), { code: "wrong_signer" });
  }
  const { manifest, ciphertext } = unpack(envelope);
  const kemCt = fromB64(manifest.kem.mlkem1024Ct);
  const xEph = fromB64(manifest.kem.x25519Eph);
  const nonce = fromB64(manifest.nonce);
  const kemSs = ml_kem1024.decapsulate(kemCt, keys.kemSk);
  const xSs = x25519.getSharedSecret(keys.xSk, xEph);
  const key = payloadKey(kemSs, xSs, kemCt, xEph, keys);
  let framed;
  try { framed = await aesDecrypt(key, nonce, ciphertext, aeadAad(kemCt, xEph, nonce)); }
  catch { throw new Error("Decryption failed. This envelope was not sealed to this identity."); }
  finally { wipe(kemSs, xSs, key); }
  const mLen = readU32(framed, 0);
  const meta = decodeJSON(framed.subarray(4, 4 + mLen));
  const bytes = framed.slice(4 + mLen);
  if (toHex(sha3_512(bytes)) !== meta.sha3_512) throw new Error("Payload hash mismatch.");
  return { meta, bytes, manifest };
}

export const isAddressedTo = (manifest, kemPk) => manifest.recipient.kemPkFp === toHex(sha3_256(kemPk));
export const fingerprint = (bytes, chars = 16) => toHex(sha3_256(bytes)).slice(0, chars);
export { sha3_256, sha3_512 };

/* ---------- vault index (added in @humid/crypto 1.1.0) ----------
 * The server lists your items without learning their names: each item's
 * metadata (name, type, category, size) is encrypted under a key derived from
 * the identity seed. The app derives it during the unlock interrupt and keeps
 * it in memory only while unlocked.
 */
export const indexKey = (seed) => kdf(seed, undefined, "HUMID-PQ1 vault-index");

// Entries are padded to 64-byte buckets before sealing (1.6.0), so the size of a sealed
// entry, and the size change when one is re-sealed, says nothing about what it holds:
// a pin or a decoy flag is 13-14 bytes of JSON, and the server sees PATCH sizes.
const INDEX_BUCKET = 64;
const padIndex = (entry) => {
  const base = encodeJSON({ ...entry, p: "" }).length;
  const want = Math.ceil(base / INDEX_BUCKET) * INDEX_BUCKET;
  return { ...entry, p: " ".repeat(want - base) };
};

export async function sealIndex(key, entry) {
  const nonce = random(12);
  const ct = await aesEncrypt(key, nonce, encodeJSON(padIndex(entry)), utf8("HUMID-INDEX-v1"));
  return concat(nonce, ct);
}

export async function openIndex(key, blob) {
  const entry = decodeJSON(await aesDecrypt(key, blob.subarray(0, 12), blob.subarray(12), utf8("HUMID-INDEX-v1")));
  if (typeof entry?.p === "string") delete entry.p; // the padding
  return entry;
}

/* ---------- offline copy (added in @humid/crypto 1.4.0) ----------
 * What the app shows while it can't reach the vault: the document list (each
 * entry still sealed under the index key), devices, recovery status and recent
 * activity. Never a document or a document key. Kept on the device under a key
 * derived from the identity seed, so it reads only after a live check.
 */
export const offlineKey = (seed) => kdf(seed, undefined, "HUMID-PQ1 offline-copy");

export async function sealOffline(key, value) {
  const nonce = random(12);
  return concat(nonce, await aesEncrypt(key, nonce, encodeJSON(value), utf8("HUMID-OFFLINE-v1")));
}

export async function openOffline(key, blob) {
  return decodeJSON(await aesDecrypt(key, blob.subarray(0, 12), blob.subarray(12), utf8("HUMID-OFFLINE-v1")));
}

/* ---------- device settings (added in @humid/crypto 1.5.0) ----------
 * Settings that must not sit on the device in the clear (which duress gesture
 * is set), sealed under a key derived from the identity seed, so they read only
 * after a live check. The app decides what to do with them after the check.
 */
export const settingsKey = (seed) => kdf(seed, undefined, "HUMID-PQ1 device-settings");

export async function sealSetting(key, value) {
  const nonce = random(12);
  return concat(nonce, await aesEncrypt(key, nonce, encodeJSON(value), utf8("HUMID-SETTING-v1")));
}

export async function openSetting(key, blob) {
  return decodeJSON(await aesDecrypt(key, blob.subarray(0, 12), blob.subarray(12), utf8("HUMID-SETTING-v1")));
}
