// The backup key and its three parts.
//
// Every repository has one random 256-bit backup key (B). B feeds
// HKDF-SHA3-256 for the chunk-id key, per-chunk keys, the snapshot key and a
// key check; data is never sealed to B directly. B is stored only wrapped, in
// config.json, under a second random key, the part key (P). P is never stored
// anywhere. It is split 2-of-3 (Shamir over GF(256), the same code
// @humid/recovery uses for recovery contacts):
//
//   x = 1  vault    sealed to the person's own HumID keys (HUMID-PQ1) AND split
//                   with the keyshare service, so it opens only inside a live
//                   biometric check. Stored in the repository as vault-part.humid.
//   x = 2  sheet    printed backup sheet, HUMIDBK-XXXXXX-…, kept offline.
//   x = 3  contact  a part the person gives someone they trust (or a safe).
//
// Any two rebuild P, which unwraps B:
//   vault + sheet     the normal restore: HumID check plus something you keep
//   vault + contact   the sheet is lost
//   sheet + contact   HumID itself is unavailable (lost account, or the service
//                     is gone). This is the continuity path; it deliberately does
//                     not need HumID, so the backup outlives the company.
//
// Replacing the parts (a lost sheet, a contact you no longer trust, a new HumID
// account) makes a new P and re-wraps the same B, so old parts stop opening the
// repository and no data is re-encrypted.
//
// A new computer needs no old hardware: the HumID identity comes back through
// the normal two-proof recovery (docs/CONTINUITY.md) with the SAME seed, so the
// vault part still opens there.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { suite, suiteForEnvelope, splitWrap, splitUnwrap } from "@humid/crypto";
import { concat, toB64, fromB64, utf8 } from "@humid/codec";
import { split, combine, base32, unbase32, normalize, encodeShare, decodeShare, wipe } from "@humid/recovery";

export const KEY_BYTES = 32;
export const PART = Object.freeze({ vault: 1, sheet: 2, contact: 3 });
export const PART_KINDS = Object.freeze(Object.keys(PART));
export const THRESHOLD = 2;
export const VAULT_PART_TYPE = "application/vnd.humid.backup-part+v1";
export const SHEET_PREFIX = "HUMIDBK";

const subtle = globalThis.crypto.subtle;
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export { wipe };

/** A new backup key. */
export const newBackupKey = () => random(KEY_BYTES);

/** Derive one purpose key from the backup key. */
export const derive = (key, what, salt) => hkdf(sha3_256, key, salt, utf8(`HUMID-BACKUP-v1 ${what}`), 32);

/** Split a part key into its three parts: { vault, sheet, contact } each { x, y }. */
export function splitBackupKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) throw new Error("A part key has 32 bytes");
  const shares = split(key, 3, THRESHOLD);
  return Object.fromEntries(PART_KINDS.map((k) => [k, shares[PART[k] - 1]]));
}

/** Rebuild the part key from any two different parts. */
export function combineParts(parts) {
  const distinct = [...new Map(parts.filter(Boolean).map((p) => [p.x, p])).values()];
  if (distinct.length < THRESHOLD) throw new Error("Opening a backup takes two different parts: HumID, the backup sheet, or your contact's part.");
  return combine(distinct.slice(0, THRESHOLD));
}

/* ---------------- key check: tells a wrong pair of parts from a damaged repository ---------------- */

const CHECK_TEXT = "HUMID-BACKUP-v1 key check";

export async function keyCheck(key, repoId) {
  const k = await subtle.importKey("raw", derive(key, "check"), "AES-GCM", false, ["encrypt"]);
  const nonce = random(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: utf8(repoId) }, k, utf8(CHECK_TEXT)));
  return toB64(concat(nonce, ct));
}

export async function verifyKey(key, repoId, check) {
  try {
    const blob = fromB64(check);
    const k = await subtle.importKey("raw", derive(key, "check"), "AES-GCM", false, ["decrypt"]);
    await subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: utf8(repoId) }, k, blob.subarray(12));
    return true;
  } catch { return false; }
}

/* ---------------- part key → backup key ----------------
 * The parts rebuild a PART key (P), which unwraps the backup key (B) stored in
 * config.json. The extra layer is what makes parts replaceable: a new split
 * of the SAME key would leave the old sheet and contact part working, so
 * replacing parts means a new P that wraps the same B. Data never moves.
 */

export async function wrapKey(partKey, key, repoId) {
  const k = await subtle.importKey("raw", derive(partKey, "wrap"), "AES-GCM", false, ["encrypt"]);
  const nonce = random(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: utf8(`HUMID-BACKUP-WRAP-v1|${repoId}`) }, k, key));
  return toB64(concat(nonce, ct));
}

export async function unwrapKey(partKey, wrapped, repoId) {
  try {
    const blob = fromB64(wrapped);
    const k = await subtle.importKey("raw", derive(partKey, "wrap"), "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: utf8(`HUMID-BACKUP-WRAP-v1|${repoId}`) }, k, blob.subarray(12)));
  } catch { return null; }
}

/* ---------------- sheet: the printed part ---------------- */
// HUMIDBK- then 54 characters in nine groups of six: 52 for the part, 2 that
// check it against this repository (a typo, or the sheet of another backup).

const sheetCheck = (repoId, y) => base32(sha3_256(concat(utf8(`HUMID-BACKUP-v1 sheet|${repoId}`), y)).subarray(0, 2)).slice(0, 2);

export function formatSheet(part, repoId) {
  if (part.x !== PART.sheet) throw new Error("Not the sheet part");
  const body = base32(part.y) + sheetCheck(repoId, part.y);
  return [SHEET_PREFIX, ...body.match(/.{1,6}/g)].join("-");
}

export function parseSheet(input, repoId) {
  let c = String(input || "").toUpperCase().replace(/[\s\-_.]/g, "");
  if (c.startsWith(SHEET_PREFIX)) c = c.slice(SHEET_PREFIX.length);
  c = normalize(c);
  if (c.length !== 54) throw new Error("A backup sheet has 54 characters after HUMIDBK.");
  const y = unbase32(c.slice(0, 52), KEY_BYTES);
  if (sheetCheck(repoId, y) !== c.slice(52)) throw new Error("That backup sheet has a typo, or it belongs to a different backup.");
  return { x: PART.sheet, y };
}

/* ---------------- contact: the part someone else holds ---------------- */

export const encodeContactPart = (part, repoId, label = "HumID backup") =>
  encodeShare({ owner: repoId, label, x: part.x, t: THRESHOLD, n: 3, y: part.y });

export function decodeContactPart(bytes, repoId) {
  const s = decodeShare(bytes);
  if (s.owner !== repoId) throw new Error("That part belongs to a different backup.");
  if (s.x !== PART.contact) throw new Error("That is not a contact's backup part.");
  return { x: s.x, y: s.y };
}

/* ---------------- vault: the HumID-gated part ---------------- */

const vaultName = (repoId) => `backup-part-${repoId}`;

/**
 * Seal the vault part to the person's own HumID keys, with a split key.
 * @param signer   full key set (dsaSk, dsaPk), released by a live check
 * @param recipient the same identity's public keys
 * @param ctx      { identityCommit, interrupt } as for any seal
 * @returns { envelope, keyshare } — the envelope goes in the repository; the
 *          keyshare goes to the keyshare service and is forgotten here.
 */
export async function sealVaultPart(part, { signer, recipient, ctx, repoId }) {
  if (part.x !== PART.vault) throw new Error("Not the vault part");
  const { file, share } = await splitWrap({ bytes: concat(new Uint8Array([part.x]), part.y), name: vaultName(repoId), type: VAULT_PART_TYPE });
  const { envelope } = await suite().seal(file, signer, recipient, ctx);
  return { envelope, keyshare: share };
}

/** Open the vault part: the account keys (live check) plus the keyshare service's release. */
export async function openVaultPart(envelope, keys, keyshare, repoId) {
  const { bytes } = await suiteForEnvelope(envelope).open(envelope, keys);
  const inner = await splitUnwrap(bytes, keyshare);
  if (inner.meta.name !== vaultName(repoId) || inner.meta.type !== VAULT_PART_TYPE) throw new Error("That HumID part belongs to a different backup.");
  if (inner.bytes[0] !== PART.vault || inner.bytes.length !== 1 + KEY_BYTES) throw new Error("The HumID backup part is damaged.");
  return { x: PART.vault, y: inner.bytes.slice(1) };
}
