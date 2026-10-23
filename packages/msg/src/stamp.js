// Live stamps: proof that a live human approved THIS message, which the
// recipient can check and nobody can trace back.
//
//   1. The sender's phone computes a commitment to the message (stamp commitment
//      below) and BLINDS it (RFC 9474, RSABSSA-SHA384-PSS-Randomized, the same
//      scheme as access passes).
//   2. It sends the blinded value to the vault server inside a step-up: a live
//      face or fingerprint check that the phone's secure chip signs. The server
//      signs the blinded value, one per check, and counts it. It never sees
//      the message, the conversation, the recipient or the stamp itself.
//   3. The phone unblinds the signature and puts the stamp INSIDE the encrypted
//      message. The recipient checks it against the server's published stamp
//      key and the commitment it recomputes from what it received.
//
// What a stamp proves: someone passed a live check on a proven phone, for these
// exact message bytes in this conversation, while the stamp key was issuing.
// Combined with the ratchet (only the contact's persona could have sent it),
// the recipient knows a live human on the other side approved the message.
//
// What it does not reveal, to anyone: blindness is information-theoretic, so
// the server cannot link a stamp to the check that bought it, even with
// unlimited (quantum) computing. Forgery rests on RSA: a future quantum
// computer could forge stamps, never unmask anyone. Stamps matter only when
// they are received, so a forged stamp in 2040 gains nothing on 2026 traffic.
//
// The stamp key MUST be a separate key from the access-pass key. A blind signer
// signs whatever it is handed; with one shared key, a "stamp" request could be
// a blinded access pass.

import { pssEncode, pssVerify, os2ip, i2osp, modPow, importKeySet, b64u as pb64u, unb64u as punb64u, toHex as ptoHex } from "@humid/pass";
import { MsgError, H, label, lp, utf8, random, concat, fromHex } from "./util.js";

export const STAMP_VERSION = 1;
const LABEL = utf8("HUMID-LIVE-v1\0");
const PREFIX = 32;
const COMMIT = 32;
const INPUT_LEN = PREFIX + LABEL.length + 32 + COMMIT;

const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
function modInv(a, m) {
  let [r0, r1, t0, t1] = [m, a % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
  if (r0 !== 1n) throw new MsgError("stamp_failed", "Value is not invertible");
  return t0 < 0n ? t0 + m : t0;
}

/**
 * Stamp keys as the app accepts them: at most two, one issuing (the access-pass
 * rule, same reason). Pass the server's access-pass keys too: a stamp key that
 * is also a pass key is refused, because a blind signer signs whatever it is
 * handed and a "stamp" could then be a blinded access pass.
 */
export function importStampKeys(list, { passKeys = [] } = {}) {
  let set;
  try { set = importKeySet(list); }
  catch (e) { throw new MsgError(e.code === "too_many_keys" ? "too_many_stamp_keys" : "bad_stamp_key", e.message); }
  const passIds = new Set(passKeys.map((k) => String(k.id).toLowerCase()));
  if (set.keys.some((k) => passIds.has(k.id))) throw new MsgError("bad_stamp_key", "The server uses its access-pass key for stamps. Refusing.");
  return set;
}

const today = (now) => new Date(now).toISOString().slice(0, 10);

/**
 * What a message's stamp commits to. Recomputed by the recipient from what it decrypted.
 * Besides the conversation, sender, message id, kind and body, it covers WHEN (at), its
 * disappearing time (x) and, for a timer change, the change's time (ta): a stamp can't be
 * moved onto a later copy of the same message to look live again (security review H1).
 */
export function messageCommitment({ convId, senderFp, nonce, kind, body, at = 0, x = 0, ta = 0 }) {
  return H(label("stamp message"), lp(convId, senderFp, nonce, utf8(kind), body, utf8(`${at}|${x}|${ta}`)));
}

/** What a contact request's stamp commits to: this handshake and this requester. */
export function requestCommitment({ th0, senderFp }) {
  return H(label("stamp request"), lp(th0, senderFp));
}

const inputOf = (prefix, kidHex, commitment) => concat(prefix, LABEL, fromHex(kidHex), commitment);

/**
 * Step 1 (phone): blind a commitment for the issuing key.
 * Send `blinded` to the server inside a live step-up; keep `draft` until the answer.
 */
export function blindStamp(keyset, commitment) {
  if (!(commitment instanceof Uint8Array) || commitment.length !== COMMIT) throw new MsgError("bad_commitment");
  const key = keyset.issuing;
  const input = inputOf(random(PREFIX), key.id, commitment);
  const m = os2ip(pssEncode(input, key.bits - 1));
  if (gcd(m, key.n) !== 1n) throw new MsgError("stamp_failed", "Try again");
  let r;
  do {
    const b = random(key.k);
    b[0] &= 0xff >> (8 * key.k - key.bits);
    r = os2ip(b);
  } while (r === 0n || r >= key.n || gcd(r, key.n) !== 1n);
  const blinded = i2osp((m * modPow(r, key.e, key.n)) % key.n, key.k);
  return { blinded, draft: { kid: key.id, input: pb64u(input), inv: modInv(r, key.n).toString(16) } };
}

/** Step 3 (phone): unblind and check. Returns the stamp to put inside the message. */
export function finalizeStamp(keyset, draft, blindSig) {
  const key = keyset.keys.find((k) => k.id === draft.kid);
  if (!key) throw new MsgError("bad_stamp_key", "Stamp was blinded for an unknown key");
  const z = os2ip(blindSig);
  if (blindSig.length !== key.k || z >= key.n) throw new MsgError("stamp_failed", "Malformed stamp signature");
  const s = (z * BigInt(`0x${draft.inv}`)) % key.n;
  const stamp = { v: STAMP_VERSION, kid: key.id, input: draft.input, sig: pb64u(i2osp(s, key.k)) };
  const commitment = punb64u(draft.input).subarray(PREFIX + LABEL.length + 32);
  if (!verifyStamp(keyset, stamp, commitment, { now: 0 })) throw new MsgError("stamp_failed", "The server's stamp did not check out");
  return stamp;
}

/** Recipient: does this stamp cover exactly this commitment, under a published stamp key? */
export function verifyStamp(keyset, stamp, commitment, { now = Date.now() } = {}) {
  try {
    if (stamp?.v !== STAMP_VERSION) return false;
    const key = keyset.keys.find((k) => k.id === stamp.kid);
    if (!key) return false;
    if (key.acceptUntil && today(now) > key.acceptUntil) return false; // a retired key's stamps stop counting
    const input = punb64u(stamp.input), sig = punb64u(stamp.sig);
    if (input.length !== INPUT_LEN || sig.length !== key.k) return false;
    if (!input.subarray(PREFIX, PREFIX + LABEL.length).every((x, i) => x === LABEL[i])) return false;
    if (ptoHex(input.subarray(PREFIX + LABEL.length, PREFIX + LABEL.length + 32)) !== key.id) return false;
    const c = input.subarray(PREFIX + LABEL.length + 32);
    if (c.length !== commitment.length || !c.every((x, i) => x === commitment[i])) return false;
    const s = os2ip(sig);
    if (s >= key.n) return false;
    const emLen = Math.ceil((key.bits - 1) / 8);
    const m = modPow(s, key.e, key.n);
    if (m >= 1n << BigInt(8 * emLen)) return false;
    return pssVerify(input, i2osp(m, emLen), key.bits - 1);
  } catch { return false; }
}

/**
 * Convenience for callers: `stamper(commitment) => Promise<stamp|null>` wraps
 * blind → server (inside a live check) → finalize. The app supplies `askServer`.
 */
export const makeStamper = (keyset, askServer) => async (commitment) => {
  const { blinded, draft } = blindStamp(keyset, commitment);
  return finalizeStamp(keyset, draft, await askServer(blinded));
};
