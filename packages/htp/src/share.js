// A split document's key in transit (CRYPTO-03 a). The keyshare service releases it sealed to
// a one-time key pair the phone made for this one open, so the gateway in between forwards only
// ciphertext. The phone's public half travels in the step-up body, which its device key signs
// during the live check, and keyshare checks that signature itself (SRV-30), so the gateway
// can't swap in a key of its own. Hybrid like every HumID seal: ML-KEM-1024 + X25519,
// HKDF-SHA3-256, AES-256-GCM, bound to the account and the document.
//
//   sealed = kemCt (1568) | xEph (32) | iv (12) | AES-256-GCM(key, share) (32 + 16)

import { ml_kem1024, x25519, sha3_256, utf8, concat, lp, random, wipe, kdf, aeadSeal, aeadOpen } from "./primitives.js";

const LABEL = "HUMID-SHARE-TRANSPORT-v1";
export const SHARE_SEALED_BYTES = 1568 + 32 + 12 + 32 + 16;
const aad = (account, object) => concat(utf8(LABEL), lp(utf8(account), utf8(object)));
const keyOf = (kemSs, xSs, kemCt, xEph, xPk, account, object) =>
  kdf(concat(kemSs, xSs), sha3_256(concat(kemCt, xEph, xPk)), `${LABEL} key\0${account}\0${object}`);

/** A one-time key pair for receiving one document key: { pub: { kemPk, xPk }, sk: { kemSk, xSk } }. */
export function shareReceiver() {
  const kem = ml_kem1024.keygen();
  const xSk = random(32);
  return { pub: { kemPk: kem.publicKey, xPk: x25519.getPublicKey(xSk) }, sk: { kemSk: kem.secretKey, xSk } };
}

/** Server side (keyshare): seal a 32-byte document key to the phone's one-time key. */
export async function sealShare(share, to, { account, object }) {
  if (!(to?.kemPk instanceof Uint8Array) || to.kemPk.length !== 1568 || !(to.xPk instanceof Uint8Array) || to.xPk.length !== 32) {
    throw Object.assign(new Error("A one-time key is ML-KEM-1024 (1568 bytes) and X25519 (32 bytes)."), { code: "bad_receiver" });
  }
  const { cipherText: kemCt, sharedSecret: kemSs } = ml_kem1024.encapsulate(to.kemPk);
  const xEphSk = random(32);
  const xEph = x25519.getPublicKey(xEphSk);
  const xSs = x25519.getSharedSecret(xEphSk, to.xPk);
  const key = keyOf(kemSs, xSs, kemCt, xEph, to.xPk, account, object);
  const iv = random(12);
  try { return concat(kemCt, xEph, iv, await aeadSeal(key, iv, share, aad(account, object))); }
  finally { wipe(kemSs, xSs, xEphSk, key); }
}

/** Phone side: open a sealed document key with the one-time key, then wipe the one-time key. */
export async function openShare(sealed, receiver, { account, object }) {
  try {
    if (!(sealed instanceof Uint8Array) || sealed.length !== SHARE_SEALED_BYTES) {
      throw Object.assign(new Error("This document needs its key from your vault, which didn't arrive. Try again."), { code: "share_missing" });
    }
    const kemCt = sealed.subarray(0, 1568), xEph = sealed.subarray(1568, 1600), iv = sealed.subarray(1600, 1612), ct = sealed.subarray(1612);
    const kemSs = ml_kem1024.decapsulate(kemCt, receiver.sk.kemSk);
    const xSs = x25519.getSharedSecret(receiver.sk.xSk, xEph);
    const key = keyOf(kemSs, xSs, kemCt, xEph, receiver.pub.xPk, account, object);
    try { return await aeadOpen(key, iv, ct, aad(account, object)); }
    catch { throw Object.assign(new Error("This document's key from your vault doesn't fit it."), { code: "share_mismatch" }); }
    finally { wipe(kemSs, xSs, key); }
  } finally { wipe(receiver.sk.kemSk, receiver.sk.xSk); }
}
