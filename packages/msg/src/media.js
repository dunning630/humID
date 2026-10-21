// Stamped media: a voice note, photo or clip that proves a live human made it.
//
// Two forms:
//
// 1. Inside a conversation (kind "media"). The body carries the capture details
//    and the bytes; the message's live stamp already commits to the whole body,
//    and the ratchet proves it came from the contact. The rule for the people
//    you talk to: if it claims to be you and isn't stamped, treat it as
//    unverified.
//
// 2. A portable credential, for media you publish outside HumID (a video on a
//    website, a statement to a platform). A sidecar file that says: the holder
//    of PUBLIC persona HC-… signed these exact bytes, and a live human approved
//    them on a proven phone. Anyone can check it against the persona ID you
//    publish. It is dual-signed, ML-DSA-87 AND SLH-DSA-SHA2-256f, so it outlives
//    a break of lattice maths, and it carries a blind live stamp over the same
//    statement.
//
// Use a dedicated PUBLIC persona for credentials, never one of your contact
// personas: a credential is meant to be attributable, so signing with a
// contact persona would let anyone link that contact to your public self.
//
// What a credential does NOT prove: when the media was captured. `capturedAt`
// is what the signer says. Anchoring the statement to an independent
// timestamp is on the list below the docs.
//
// Nothing here looks inside the media. It is hashed, never analysed.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { personaFingerprint, personaId, encodePub, decodePub, dualSign, dualVerify } from "./persona.js";
import { verifyStamp } from "./stamp.js";
import { SIZES } from "./backend.js";
import { MsgError, H, label, lp, unlp, utf8, u32, concat, b64u, unb64u, encodeJSON, decodeJSON, guard, equal } from "./util.js";

export const MEDIA_VERSION = 1;
export const MEDIA_KINDS = Object.freeze(["voice", "photo", "video", "other"]);
export const MAX_IN_MESSAGE = 1_800_000; // in-conversation bodies stay under the message limit
const MIME_RE = /^[a-z]+\/[a-z0-9.+-]{1,64}$/;

function checkMeta({ kind = "other", mime, capturedAt }) {
  if (!MEDIA_KINDS.includes(kind)) throw new MsgError("bad_media", `Unknown media kind "${kind}"`);
  if (typeof mime !== "string" || !MIME_RE.test(mime)) throw new MsgError("bad_media", "Media type must look like audio/mp4");
  if (!Number.isSafeInteger(capturedAt) || capturedAt < 0) throw new MsgError("bad_media", "capturedAt must be a time in ms");
  return { kind, mime, capturedAt };
}

/** Hash of the media bytes, domain-separated. The only thing this module computes from them. */
export const mediaHash = (bytes) => sha3_256(concat(label("media bytes"), bytes));

/* ---------- 1. in a conversation ---------- */

/** Body for a kind "media" message. Send it with a stamper so it arrives stamped. */
export function encodeMedia({ bytes, kind, mime, capturedAt }) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new MsgError("bad_media", "No media bytes");
  if (bytes.length > MAX_IN_MESSAGE) throw new MsgError("too_large", "Too large to send in a message; send it as an attachment");
  const meta = checkMeta({ kind, mime, capturedAt });
  return lp(encodeJSON({ v: MEDIA_VERSION, ...meta }), bytes);
}

/** Read a decrypted kind "media" message. `live` is the message's stamp result. */
export function decodeMedia(msg) {
  return guard(() => {
    if (msg?.kind !== "media") throw new MsgError("bad_media", "Not a media message");
    const [m, bytes] = unlp(msg.body, 2);
    const meta = decodeJSON(m);
    if (meta?.v !== MEDIA_VERSION) throw new MsgError("bad_media", "Unsupported media version");
    return { ...checkMeta(meta), bytes, live: msg.live, verified: msg.live === true };
  });
}

/* ---------- 2. portable credential ---------- */

function statement({ hash, size, kind, mime, capturedAt, fp }) {
  return lp(utf8("HUMID-MEDIA-v1"), hash, u32(size), utf8(kind), utf8(mime), utf8(String(capturedAt)), fp);
}
/** What the credential's live stamp commits to. */
export const mediaCommitment = (st) => H(label("stamp media"), st);

/**
 * Make a credential for `bytes`, signed by `persona` (a public persona) and
 * stamped live. `stamper(commitment)` runs one live check. Returns plain JSON
 * to save next to the media (e.g. clip.mp4.humid.json).
 */
export async function makeMediaCredential({ persona, bytes, kind = "other", mime, capturedAt, stamper }) {
  if (!persona?.keys || !persona?.pub) throw new MsgError("bad_persona", "A persona with its keys is needed to sign");
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new MsgError("bad_media", "No media bytes");
  if (bytes.length > 0xffffffff) throw new MsgError("too_large", "Media too large");
  if (typeof stamper !== "function") throw new MsgError("stamp_required", "A credential takes a live check");
  const meta = checkMeta({ kind, mime, capturedAt });
  const hash = mediaHash(bytes);
  const fp = personaFingerprint(persona.pub);
  const st = statement({ hash, size: bytes.length, ...meta, fp });
  const stamp = await stamper(mediaCommitment(st));
  const sig = dualSign("media credential", concat(st, utf8(JSON.stringify(stamp))), persona.keys);
  return {
    v: MEDIA_VERSION, type: "humid-media-credential",
    hash: b64u(hash), size: bytes.length, ...meta,
    signer: { id: persona.id, pub: encodePub(persona.pub) },
    stamp, sig: { dsa: b64u(sig.dsa), slh: b64u(sig.slh) },
  };
}

/**
 * Check a credential against the media bytes.
 * opts.stampKeys      published stamp keys (importStampKeys)
 * opts.expectSigner   the public persona ID the person publishes. Without it,
 *                     a valid credential only proves "someone", not "them".
 * Returns { ok, reason?, signer, live, kind, mime, capturedAt }.
 *   ok is true only when the bytes match, both signatures verify, the stamp is
 *   valid, and (if given) the signer is the expected persona.
 */
export function verifyMediaCredential(cred, bytes, { stampKeys, expectSigner, now = Date.now() } = {}) {
  const no = (reason, extra = {}) => ({ ok: false, reason, ...extra });
  try {
    if (cred?.v !== MEDIA_VERSION || cred.type !== "humid-media-credential") return no("not_a_credential");
    const meta = checkMeta(cred);
    const pub = decodePub(cred.signer?.pub);
    const signer = personaId(pub);
    if (signer !== cred.signer.id) return no("signer_mismatch");
    const base = { signer, ...meta };
    if (expectSigner && signer !== expectSigner) return no("not_expected_signer", base);
    if (!(bytes instanceof Uint8Array) || bytes.length !== cred.size) return no("bytes_changed", base);
    const hash = mediaHash(bytes);
    if (!equal(hash, unb64u(cred.hash, 32))) return no("bytes_changed", base);
    const st = statement({ hash, size: bytes.length, ...meta, fp: personaFingerprint(pub) });
    const sigs = { dsa: unb64u(cred.sig?.dsa, SIZES.dsaSig), slh: unb64u(cred.sig?.slh, SIZES.slhSig) };
    if (!dualVerify("media credential", concat(st, utf8(JSON.stringify(cred.stamp))), sigs, pub)) return no("bad_signature", base);
    const live = !!stampKeys && verifyStamp(stampKeys, cred.stamp, mediaCommitment(st), { now });
    if (!live) return no(stampKeys ? "not_live" : "no_stamp_keys", { ...base, live: false });
    return { ok: true, ...base, live: true };
  } catch (e) {
    return no(e instanceof MsgError ? e.code : "malformed");
  }
}
