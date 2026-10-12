// Biometric-bound proofs. Each is an ML-DSA-87 signature by the holder's
// identity key, which exists in memory only for the few milliseconds after a
// biological interrupt (Face ID, fingerprint, Windows Hello…) releases it.
// Every proof is bound to this session's transcript hash, so it cannot be
// replayed into another session; step-up proofs are also bound to one request.

import { ml_dsa87, sha3_256, concat, lp, u64, utf8, toHex } from "./primitives.js";

export const STEP_UP_MAX_AGE_MS = 60 * 1000;

/** Server-side identity id, derived from the holder's ML-DSA-87 public key. */
export const identityId = (dsaPk) => "hid_" + toHex(sha3_256(dsaPk)).slice(0, 40);

export const registerMessage = (th, keys, commit) =>
  concat(utf8("HTP/1 register"), lp(th, sha3_256(keys.kemPk), sha3_256(keys.dsaPk), keys.xPk, utf8(commit)));

export const loginMessage = (th, id, challenge) =>
  concat(utf8("HTP/1 login"), lp(th, utf8(id), challenge));

export const stepUpMessage = (th, seq, method, path, body, at) =>
  concat(utf8("HTP/1 step-up"), lp(th, u64(seq), utf8(method.toUpperCase()), utf8(path), sha3_256(body || new Uint8Array(0)), u64(at)));

export const sign = (msg, dsaSk) => ml_dsa87.sign(msg, dsaSk);

export function verify(sig, msg, dsaPk) {
  try { return ml_dsa87.verify(sig, msg, dsaPk); } catch { return false; }
}

/** Short hash of a proof, recorded in the ledger as evidence of the interrupt. */
export const proofHash = (sig) => toHex(sha3_256(sig)).slice(0, 32);
