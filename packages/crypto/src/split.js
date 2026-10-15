// Split keys: a document that needs TWO keys to open.
//
//   1. the account's keys (ML-KEM-1024 + X25519), as every envelope always has, and
//   2. a random 256-bit document key that lives only in the keyshare service,
//      released for one document at a time, inside a live chip-signed check.
//
// The document is encrypted under (2) first, then the result is sealed to (1) as an
// ordinary envelope. So spyware that copies the account keys out of a phone's memory
// still opens nothing: every document also needs its own key from the keyshare service,
// one live biometric check per document. And the server, which has (2) and the
// envelope, can't open anything without (1). See docs/SECURITY.md#compromised-phone.
//
// Inner format (the bytes the envelope carries):
//   "HUMID-SPLIT-v1\0" | iv (12) | AES-256-GCM(docKey, u32 metaLen | meta JSON | bytes)
// with the header as associated data. meta = { name, type }: the real name and type
// sit inside this layer, so the account keys alone don't reveal them either.

import { concat, u32, readU32, encodeJSON, decodeJSON, utf8 } from "@humid/codec";

export const SPLIT_TYPE = "application/vnd.humid.split+v1";
export const SHARE_BYTES = 32;
const MAGIC = utf8("HUMID-SPLIT-v1\0");
const subtle = globalThis.crypto.subtle;
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };

/**
 * Encrypt a file under a new document key. Returns the file to seal as usual, and the
 * share to send with the upload (the keyshare service keeps it; the phone forgets it).
 */
export async function splitWrap({ bytes, name, type }) {
  const share = random(SHARE_BYTES);
  const iv = random(12);
  const meta = encodeJSON({ name, type: type || "application/octet-stream" });
  const framed = concat(u32(meta.length), meta, bytes);
  const k = await subtle.importKey("raw", share, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: MAGIC }, k, framed));
  wipe(framed);
  return { file: { bytes: concat(MAGIC, iv, ct), name: "sealed", type: SPLIT_TYPE }, share };
}

export const isSplit = (meta) => meta?.type === SPLIT_TYPE;

/** Open the inner layer with the share the keyshare service released. Returns { bytes, meta: { name, type } }. */
export async function splitUnwrap(inner, share) {
  if (!(share instanceof Uint8Array) || share.length !== SHARE_BYTES) {
    throw Object.assign(new Error("This document needs its key from your vault, which didn't arrive. Try again."), { code: "share_missing" });
  }
  if (inner.length < MAGIC.length + 12 + 16 || !MAGIC.every((b, i) => inner[i] === b)) throw new Error("Not a split document.");
  const iv = inner.subarray(MAGIC.length, MAGIC.length + 12);
  const k = await subtle.importKey("raw", share, "AES-GCM", false, ["decrypt"]);
  let framed;
  try { framed = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: MAGIC }, k, inner.subarray(MAGIC.length + 12))); }
  catch { throw Object.assign(new Error("This document's key from your vault doesn't fit it."), { code: "share_mismatch" }); }
  const mLen = readU32(framed, 0);
  const meta = decodeJSON(framed.subarray(4, 4 + mLen));
  return { bytes: framed.slice(4 + mLen), meta: { name: String(meta.name || "Document"), type: String(meta.type || "application/octet-stream") } };
}
