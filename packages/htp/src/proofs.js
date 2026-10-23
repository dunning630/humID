// Biometric-bound proofs. Each is an ML-DSA-87 signature by the holder's
// identity key, which exists in memory only for the few milliseconds after a
// biological interrupt (Face ID, fingerprint, Windows Hello…) releases it.
// Every proof is bound to this session's transcript hash, so it cannot be
// replayed into another session; step-up proofs are also bound to one request.

import { ml_dsa87, sha3_256, concat, lp, u64, utf8, toHex, fromHex, unb64u } from "./primitives.js";

export const STEP_UP_MAX_AGE_MS = 60 * 1000;
/** A step-up approval the server hands out is good for this long, and for one request. */
export const STEP_UP_NONCE_MS = 60 * 1000;
/** How far ahead of the server's clock a device's clock may be. */
export const CLOCK_SKEW_MS = 5 * 1000;

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

/**
 * Sign-in that carries the duress report (PC-01). Which gesture means duress is sealed on
 * the device and opens only inside the live check, so the hardware liveness key (whose
 * challenge is fixed before the prompt) signs loginMessage, and the device key, which
 * only that same check releases, signs this: the same sign-in, plus d (0 ordinary,
 * 1 duress). A duress signal therefore exists only as part of a live sign-in, never as a
 * request any session could send later. Same size either way.
 */
export const loginPresenceMessage = (th, id, challenge, d) =>
  concat(utf8("HTP/1 login+presence"), lp(th, utf8(id), challenge, new Uint8Array([d === 1 ? 1 : 0])));

/**
 * The action being approved, as the server issued it (POST /auth/step-up), in one
 * canonical encoding: what it does (method), to what (the path carries the target
 * ids: document, device, recovery request…), from which device, the server's
 * single-use nonce, and when the approval expires (at most 60 s on).
 */
export const actionBytes = ({ method, path, device, nonce, exp }) =>
  concat(utf8("HTP/1 action v2"), lp(utf8(method.toUpperCase()), utf8(path), utf8(device), nonce, u64(exp)));

/** The device key's step-up signature: the session, the slot, the request with its body, the time, and the action. */
export const stepUpMessage = (th, seq, method, path, body, at, action) =>
  concat(utf8("HTP/1 step-up v2"), lp(th, u64(seq), utf8(method.toUpperCase()), utf8(path), sha3_256(body || new Uint8Array(0)), u64(at), action));

/**
 * What a device's hardware liveness key signs for a step-up, during the live check:
 * this session, this request slot, the method, the path, the time and the action the
 * server issued. (The body is chosen with keys that check releases, so it's covered
 * by the ML-DSA-87 step-up signature made in the same check.)
 */
export const liveMessage = (th, seq, method, path, at, action) =>
  concat(utf8("HTP/1 live v2"), lp(th, u64(seq), utf8(method.toUpperCase()), utf8(path), u64(at), action));

/** What the liveness key signs when a document is sealed: the ciphertext's SHA3-512 (hex in the manifest). */
export const sealLiveMessage = (ciphertextSha3Hex) => concat(utf8("HUMID-SEAL-v1"), fromHex(ciphertextSha3Hex));

/**
 * The recovery card made with a new account, signed by the account key inside the registration's
 * live check: there is no step-up yet to approve it, so this is the holder's own approval of
 * exactly this card (tag and the SHA3-256 of its sealed blob), in this session.
 */
export const setupCardMessage = (th, accountId, tag, blob) =>
  concat(utf8("HTP/1 setup-card"), lp(th, utf8(accountId), utf8(tag), sha3_256(blob)));

export const sign = (msg, dsaSk) => ml_dsa87.sign(msg, dsaSk);

export function verify(sig, msg, dsaPk) {
  try { return ml_dsa87.verify(sig, msg, dsaPk); } catch { return false; }
}

/**
 * JSON with object keys in sorted order at every level, so the server and the app
 * sign and check the same bytes for the same value (the policy hint below).
 */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v ?? null);
}

/**
 * The server's policy hint (GET /htp/v1/keys), signed with its static ML-DSA-87 key
 * (CRYPTO-07, PC-13). The key id is in the message, so a signature made for one server
 * key set never checks under another; `at` lets the app refuse a very old one.
 */
export const policyMessage = (kid, policy, at) =>
  concat(utf8("HTP/1 policy"), lp(kid, utf8(canonicalJson(policy)), u64(at)));

/** How old a signed policy the app still believes. The gateway re-signs it every hour. */
export const POLICY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * True when `sig` ({ at, sig }) is the server's signature over exactly this policy, and no
 * more than `maxAgeMs` from now (Infinity: any age, for a policy remembered on the device).
 */
export function verifyPolicy(dsaPk, kid, policy, sig, now = Date.now(), { maxAgeMs = POLICY_MAX_AGE_MS } = {}) {
  if (!policy || typeof policy !== "object" || !sig || typeof sig !== "object") return false;
  const at = Number(sig.at);
  if (!Number.isSafeInteger(at) || at < 0 || Math.abs(now - at) > maxAgeMs) return false;
  try { return ml_dsa87.verify(unb64u(String(sig.sig)), policyMessage(kid, policy, at), dsaPk); } catch { return false; }
}

/** Short hash of a proof, recorded in the ledger as evidence of the interrupt. */
export const proofHash = (sig) => toHex(sha3_256(sig)).slice(0, 32);
