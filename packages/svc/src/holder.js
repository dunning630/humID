// The holder's own approval, checked by the service that releases or destroys a secret
// (SRV-30). The gateway checks every step-up too, but a service that took the gateway's word
// for it would open to anyone holding the gateway's internal key: the one host reachable from
// the internet. So vault, keyshare and identity check the device's ML-DSA-87 signature (and
// its liveness key's, where it has one) over exactly the action they are about to take.
//
// A proof, as the gateway forwards it:
//   { th, seq, at, m, p, body, nonce, exp, device, sig, live?, vouch? }
// th, body, nonce, sig, live: base64url. m and p: the request the holder approved (the app's
// method and path, which name the document or device). vouch: identity's statement that this
// device key (and liveness key) belongs to the account, for services that don't hold device
// keys themselves (verifyStatement, kind "device").
//
// What this trusts: identity, for which device keys belong to an account. Identity adds a
// device only with the account key's own signature, which never leaves the phone, so the
// gateway's key can't make it vouch for a device of its own; whoever controls identity's
// statement key (the core role) can.

import { HttpError, verifyStatement, unb64u } from "./index.js";
import { stepUpMessage, liveMessage, actionBytes, loginMessage, loginPresenceMessage, verify, proofHash, STEP_UP_MAX_AGE_MS, STEP_UP_NONCE_MS, CLOCK_SKEW_MS } from "@humid/htp";
import { verifyLiveSig } from "@humid/attest";

const b = (v) => { try { return unb64u(String(v ?? "")); } catch { return null; } };

/**
 * holderProofs({ corePk }) checks proofs against identity's vouches; holderProofs({ resolve })
 * against device keys the service holds itself (identity): resolve(deviceId, account) -> { dsaPk, livePub } | null.
 */
export function holderProofs({ corePk = null, resolve = null, now = () => Date.now(), max = 100_000 } = {}) {
  if (!corePk && !resolve) throw new Error("holderProofs needs identity's statement key (HUMID_CORE_STATEMENT_PK) or a device resolver");
  const startedAt = now();
  const seen = new Map(); // proof hash -> until
  const prune = () => { const t = now(); for (const [k, until] of seen) if (until < t) seen.delete(k); };

  function deviceKeys(proof, sub) {
    if (resolve) {
      const k = resolve(String(proof.device), sub);
      if (!k) throw new HttpError(401, "bad_proof", "Biometric proof was rejected.");
      return k;
    }
    const v = verifyStatement(corePk, proof.vouch, "device");
    if (v.account !== sub || v.device !== proof.device) throw new HttpError(403, "not_vouched", "That device isn't vouched for on this account.");
    return { dsaPk: b(v.dsaPk), livePub: v.livePub ? b(v.livePub) : null };
  }

  return {
    /**
     * Check `proof` approves `method path` for account `sub`, once. Returns { body, proofHash, device }:
     * body is the request body the holder signed (the app's own, which may carry what it asked for).
     */
    check(proof, { sub, method, path, body: requestBody }) {
      if (!proof || typeof proof !== "object") throw new HttpError(403, "step_up_required", "This needs a fresh biometric check on your device.");
      if (!sub) throw new HttpError(401, "unauthenticated", "Sign in first");
      if (proof.m !== method || proof.p !== path) throw new HttpError(403, "step_up_mismatch", "That approval was for a different action.");
      const t = now();
      const at = Number(proof.at), exp = Number(proof.exp), seq = Number(proof.seq);
      if (!Number.isSafeInteger(at) || t - at > STEP_UP_MAX_AGE_MS || at - t > CLOCK_SKEW_MS || at < startedAt) throw new HttpError(403, "step_up_stale", "Biometric check is too old. Try again.");
      if (!Number.isSafeInteger(exp) || exp < t || exp - t > STEP_UP_NONCE_MS + CLOCK_SKEW_MS) throw new HttpError(403, "step_up_stale", "Biometric check is too old. Try again.");
      if (!Number.isSafeInteger(seq) || seq < 0) throw new HttpError(400, "bad_proof", "Malformed proof");
      // requestBody: the body this service received, when it is the app's own body passed through
      // unchanged (so the gateway can't act on content other than what the holder signed).
      const th = b(proof.th), nonce = b(proof.nonce), sig = b(proof.sig), body = requestBody instanceof Uint8Array ? requestBody : b(proof.body || "");
      if (!th?.length || !nonce?.length || !sig?.length || !body) throw new HttpError(400, "bad_proof", "Malformed proof");
      const { dsaPk, livePub } = deviceKeys(proof, sub);
      const action = actionBytes({ method, path, device: String(proof.device), nonce, exp });
      if (!dsaPk || !verify(sig, stepUpMessage(th, seq, method, path, body, at, action), dsaPk)) throw new HttpError(401, "bad_proof", "Biometric proof was rejected.");
      if (livePub && !verifyLiveSig(livePub, liveMessage(th, seq, method, path, at, action), proof.live ? b(proof.live) : null)) {
        throw new HttpError(401, "bad_live_proof", "This needs a live face or fingerprint check on this device.");
      }
      // One approval, one use, here: a proof seen once (by this service) is refused again.
      const ph = proofHash(sig);
      if (seen.has(ph)) throw new HttpError(403, "step_up_used", "That approval was already used. Try again.");
      if (seen.size >= max) { prune(); if (seen.size >= max) throw new HttpError(503, "busy", "Too many requests in flight"); }
      seen.set(ph, exp + CLOCK_SKEW_MS);
      if (seen.size % 256 === 0) prune();
      return { body, proofHash: ph, device: String(proof.device) };
    },

    /**
     * A duress sign-in (PC-01): the device key signed the sign-in with d = 1, and its liveness
     * key the plain challenge, in one live check. proof: { th, nonce, device, sig, live?, vouch? }.
     * The signed sign-in carries no time, so the caller must keep its own memory of proofs it has
     * acted on (keyshare keeps them on disk). Returns { proofHash, device }.
     */
    checkDuress(proof, { sub }) {
      if (!proof || typeof proof !== "object") throw new HttpError(403, "not_vouched", "A duress erase needs the duress sign-in itself.");
      const th = b(proof.th), nonce = b(proof.nonce), sig = b(proof.sig);
      if (!th?.length || !nonce?.length || !sig?.length) throw new HttpError(400, "bad_proof", "Malformed proof");
      const { dsaPk, livePub } = deviceKeys(proof, sub);
      const who = `${sub}/${proof.device}`;
      if (!dsaPk || !verify(sig, loginPresenceMessage(th, who, nonce, 1), dsaPk)) throw new HttpError(401, "bad_proof", "That isn't a duress sign-in by this account's device.");
      if (livePub && !verifyLiveSig(livePub, loginMessage(th, who, nonce), proof.live ? b(proof.live) : null)) throw new HttpError(401, "bad_live_proof", "That sign-in had no live check.");
      return { proofHash: proofHash(sig), device: String(proof.device) };
    },
  };
}

/** The ledger's receipt for `type` with detail fields `want`, for account `sub` (a 403 otherwise). */
export function checkReceipt(corePk, receipt, { sub, type, want }) {
  const r = verifyStatement(corePk, receipt, "ledger");
  if (r.owner !== sub || r.type !== type) throw new HttpError(403, "not_logged", "This access isn't in your ledger, so it's refused.");
  for (const [k, v] of Object.entries(want)) if (r.detail?.[k] !== v) throw new HttpError(403, "not_logged", "This access isn't in your ledger, so it's refused.");
  return r;
}
