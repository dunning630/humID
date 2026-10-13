// Biometric-bound proofs. Each is an ML-DSA-87 signature by the holder's
// identity key, which exists in memory only for the few milliseconds after a
// biological interrupt (Face ID, fingerprint, Windows Hello…) releases it.
// Every proof is bound to this session's transcript hash, so it cannot be
// replayed into another session; step-up proofs are also bound to one request.

import { ml_dsa87, sha3_256, concat, lp, u64, utf8, toHex, fromHex } from "./primitives.js";

export const STEP_UP_MAX_AGE_MS = 60 * 1000;

/** Server-side identity id, derived from the holder's ML-DSA-87 public key. */
export const identityId = (dsaPk) => "hid_" + toHex(sha3_256(dsaPk)).slice(0, 40);

export const registerMessage = (th, keys, commit) =>
  concat(utf8("HTP/1 register"), lp(th, sha3_256(keys.kemPk), sha3_256(keys.dsaPk), keys.xPk, utf8(commit)));

/** Device id, derived from the device's own ML-DSA-87 key (not the account key). */
export const deviceId = (dsaPk) => "dev_" + toHex(sha3_256(dsaPk)).slice(0, 24);

/**
 * A device joins an account. Signed twice over the same bytes: by the account
 * key (only a holder of the account seed can authorise a device) and by the
 * device key (proof of possession). Bound to this session's transcript.
 */
export const deviceMessage = (th, accountId, deviceDsaPk) =>
  concat(utf8("HTP/1 device"), lp(th, utf8(accountId), sha3_256(deviceDsaPk)));

/** Sign-in proof. `id` is "<account id>/<device id>"; the device key signs it. */
export const loginMessage = (th, id, challenge) =>
  concat(utf8("HTP/1 login"), lp(th, utf8(id), challenge));

export const stepUpMessage = (th, seq, method, path, body, at) =>
  concat(utf8("HTP/1 step-up"), lp(th, u64(seq), utf8(method.toUpperCase()), utf8(path), sha3_256(body || new Uint8Array(0)), u64(at)));

/**
 * What a device's hardware liveness key signs for a step-up: this session,
 * this request slot, the method, the path and the time. The body is covered
 * by the ML-DSA-87 step-up signature made with the same biometric check.
 */
export const liveMessage = (th, seq, method, path, at) =>
  concat(utf8("HTP/1 live"), lp(th, u64(seq), utf8(method.toUpperCase()), utf8(path), u64(at)));

/** What the liveness key signs when a document is sealed: the ciphertext's SHA3-512 (hex in the manifest). */
export const sealLiveMessage = (ciphertextSha3Hex) => concat(utf8("HUMID-SEAL-v1"), fromHex(ciphertextSha3Hex));

export const sign = (msg, dsaSk) => ml_dsa87.sign(msg, dsaSk);

export function verify(sig, msg, dsaPk) {
  try { return ml_dsa87.verify(sig, msg, dsaPk); } catch { return false; }
}

/** Short hash of a proof, recorded in the ledger as evidence of the interrupt. */
export const proofHash = (sig) => toHex(sha3_256(sig)).slice(0, 32);
