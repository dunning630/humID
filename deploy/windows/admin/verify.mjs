// What the admin console trusts, and how it checks it (docs/ADMIN.md).
//
// A change is described by the console in one canonical JSON object; its SHA3-256 is
// the digest an administrator's phone approves with a live check. The approval comes
// back through the HumID server, which the console does not trust: it re-checks the
// phone's ML-DSA-87 step-up signature (and, on phones with a secure chip, the chip's
// P-256 liveness signature) against the keys it pinned when that phone was enrolled,
// and that the signed request names exactly this code and this digest.
import { stepUpMessage, liveMessage, actionBytes, verify, proofHash, deviceId, sha3_256, toHex, utf8, unb64u, fromUtf8, random } from "@humid/htp";
import { verifyLiveSig } from "@humid/attest";
import { adminCheck } from "@humid/recovery";

/** How long a request waits for a phone, and how old an approval may be when it arrives. */
export const REQUEST_TTL_MS = 5 * 60_000;
export const APPROVAL_MAX_AGE_MS = 2 * 60_000;
const SKEW_MS = 5_000;

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32, as the app's codes
export const CODE_RE = /^[0-9A-HJKMNP-TV-Z]{12}$/;

/** A fresh 12-character request code (60 bits). */
export function newCode(rand = random) {
  const b = rand(8);
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  for (let i = 0; i < 12; i++) { s += ALPHABET[Number(n & 31n)]; n >>= 5n; }
  return s;
}
export const formatCode = (c) => c.match(/.{4}/g).join("-");

/** JSON with keys in a fixed order, so the same change always has the same digest. */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/**
 * The digest a phone approves: this server (its HTP key id), this code, what kind of
 * request, the change and its arguments, and when the console asked.
 */
export function requestDigest({ kid, code, kind, type, args = {}, createdAt }) {
  return toHex(sha3_256(utf8(canonical({ v: 1, label: "HUMID-ADMIN-REQUEST", kid, code, kind, type, args, createdAt }))));
}
/** The short form both screens show, so a person can see they approve the same thing. */
export const digestCheck = (digest) => digest.slice(0, 8).toUpperCase().match(/.{4}/g).join("-");

export class ApprovalError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/**
 * Check an approval the server handed over.
 *   rec       what the gateway wrote (data\admin\approvals\<code>.json)
 *   request   the console's own pending request { code, kind, digest, createdAt }
 *   admins    pinned administrators [{ account, device, deviceDsaPk, livePub }]
 * Returns { admin, proof, enrolCheck? } or throws ApprovalError.
 */
export function verifyApproval(rec, request, admins, now = Date.now()) {
  const no = (code, msg) => { throw new ApprovalError(code, msg); };
  if (!rec || typeof rec !== "object") no("bad_record", "The approval couldn't be read.");
  if (rec.code !== request.code) no("wrong_code", "The approval is for another request.");
  const path = `/admin/requests/${request.code}/approve`;
  if (rec.method !== "POST" || rec.path !== path) no("wrong_request", "The signed request isn't this approval.");
  let body, approved;
  try { body = unb64u(String(rec.body)); approved = JSON.parse(fromUtf8(body)); } catch { no("bad_record", "The approval couldn't be read."); }
  if (approved?.digest !== request.digest) no("wrong_digest", "The phone approved something else.");

  const at = Number(rec.at), seq = Number(rec.seq), exp = Number(rec.exp);
  if (![at, seq, exp].every(Number.isSafeInteger)) no("bad_record", "The approval couldn't be read.");
  if (at < request.createdAt - SKEW_MS || at > now + SKEW_MS || now - at > APPROVAL_MAX_AGE_MS) no("stale", "The approval is too old, or from before the request.");
  if (exp < at) no("stale", "The approval had already expired.");

  let admin;
  if (request.kind === "enrol") {
    // Not trusted yet: the keys come with the approval, and the person compares the
    // check code on the phone with the one the console shows before they're pinned.
    let pk;
    try { pk = unb64u(String(rec.deviceDsaPk)); } catch { no("bad_record", "The approval couldn't be read."); }
    if (deviceId(pk) !== rec.device) no("bad_record", "The device id doesn't match its key.");
    if (!/^hid_[0-9a-f]{40}$/.test(String(rec.account))) no("bad_record", "The account id isn't valid.");
    admin = { account: rec.account, device: rec.device, deviceDsaPk: rec.deviceDsaPk, livePub: rec.livePub || null, platform: String(rec.platform || "phone").slice(0, 40), proofLevel: String(rec.proofLevel || "none").slice(0, 40), assurance: String(rec.assurance || "").slice(0, 20) };
  } else {
    admin = admins.find((a) => a.device === rec.device && a.account === rec.account);
    if (!admin) no("not_admin", "That phone isn't an administrator of this console.");
  }

  const th = unb64u(String(rec.th));
  const action = actionBytes({ method: rec.method, path, device: admin.device, nonce: unb64u(String(rec.nonce)), exp });
  const sig = unb64u(String(rec.sig));
  if (!verify(sig, stepUpMessage(th, seq, rec.method, path, body, at, action), unb64u(admin.deviceDsaPk))) no("bad_signature", "The phone's signature doesn't check out against its pinned key.");
  if (admin.livePub) {
    const live = rec.live ? unb64u(String(rec.live)) : null;
    if (!verifyLiveSig(unb64u(admin.livePub), liveMessage(th, seq, rec.method, path, at, action), live)) no("no_live_check", "The phone's secure chip didn't sign this approval.");
  }
  return { admin, proof: proofHash(sig), ...(request.kind === "enrol" ? { enrolCheck: adminCheck(unb64u(admin.deviceDsaPk)) } : {}) };
}
