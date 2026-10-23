// The evidence locker: sealed originals of your real voice and face.
//
// What it is for: proving "this is the real me, recorded on this date" to
// someone who needs evidence. A platform's impersonation team, a lawyer, the
// police. You capture in the app; each item is sealed on the device and opens
// only with the locker key, which comes from the account seed (released by a
// live check). The vault server and HumID never hold the key, so they can never
// read an item.
//
// What it is NOT for, ever: checking calls. A clone is built to match a
// reference, so a match proves nothing, and a matcher would mean HumID handles
// biometrics. This module hashes and encrypts bytes; it never extracts
// features from them, compares them with anything, or sends them anywhere.
// Calls are checked with a live challenge (challenge.js), not with these.
//
//   seal     credential (media.js: public persona signs, live stamp) + bytes,
//            encrypted under a random item key, which is wrapped by the locker key
//   open     unwrap and decrypt (the app asks for a live check first)
//   release  a dated, signed and stamped release statement naming who it was
//            released to, for what, and until when, so any copy that travels
//            further carries its own paper trail
//
// Limit: capturedAt and releasedAt are what the holder states, signed. An
// independent timestamp is listed as next in the docs.

import { makeMediaCredential, verifyMediaCredential, mediaHash, MEDIA_KINDS } from "./media.js";
import { personaFingerprint, personaId, encodePub, decodePub, dualSign, dualVerify } from "./persona.js";
import { verifyStamp } from "./stamp.js";
import { SIZES } from "./backend.js";
import {
  MsgError, kdf, H, label, lp, unlp, utf8, concat, random, toHex, fromHex, b64u, unb64u,
  encodeJSON, decodeJSON, aeadSeal, aeadOpen, guard, equal, wipe,
} from "./util.js";

export const EVIDENCE_VERSION = 1;
export const MAX_EVIDENCE = 64 * 1024 * 1024; // 64 MiB per item; longer video goes in pieces
export const MAX_RELEASE_DAYS = 365;
const TEXT_MAX = 140;
const DAY = 86_400_000;

const clean = (s, what) => {
  if (s === undefined || s === null) return "";
  if (typeof s !== "string") throw new MsgError("bad_evidence", `${what} must be text`);
  const t = s.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, " ").trim();
  if (t.length > TEXT_MAX) throw new MsgError("bad_evidence", `${what} is longer than ${TEXT_MAX} characters`);
  return t;
};

/** The locker key, derived on the device from the account seed (which a live check releases). */
export function lockerKey(accountSeed) {
  if (!(accountSeed instanceof Uint8Array) || accountSeed.length !== 64) throw new MsgError("bad_seed", "Account seed must be 64 bytes");
  return kdf(accountSeed, undefined, "evidence locker", 32);
}

const aadItem = (id) => concat(label("evidence item"), id);
const aadKey = (id) => concat(label("evidence key"), id);

/**
 * Seal one capture. `persona` is your PUBLIC persona (the one whose ID you
 * publish); `stamper` runs one live check. Returns a record (plain JSON) to
 * store in the vault. It reveals nothing but its id and rough size.
 */
export async function sealEvidence({ bytes, kind, mime, capturedAt, note }, key, { persona, stamper, now = Date.now() } = {}) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new MsgError("bad_key", "Locker key must be 32 bytes");
  if (!MEDIA_KINDS.includes(kind)) throw new MsgError("bad_evidence", `Unknown kind "${kind}"`);
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new MsgError("bad_evidence", "Nothing to seal");
  if (bytes.length > MAX_EVIDENCE) throw new MsgError("too_large", "Item too large for the locker");
  const credential = await makeMediaCredential({ persona, bytes, kind, mime, capturedAt, stamper });
  const id = random(16);
  const meta = { v: EVIDENCE_VERSION, kind, mime, capturedAt, note: clean(note, "Note"), sealedAt: now, credential };
  const itemKey = random(32);
  const n1 = random(12), n2 = random(12);
  const ct = await aeadSeal(itemKey, n1, lp(encodeJSON(meta), bytes), aadItem(id));
  const wrapped = await aeadSeal(key, n2, itemKey, aadKey(id));
  wipe(itemKey);
  return { v: EVIDENCE_VERSION, type: "humid-evidence", id: toHex(id), key: b64u(concat(n2, wrapped)), blob: b64u(concat(n1, ct)) };
}

/** Open a sealed item. Call only after a live check. Throws MsgError("decrypt_failed") on a wrong key or tampering. */
export async function openEvidence(record, key) {
  return guard(async () => {
    if (record?.v !== EVIDENCE_VERSION || record.type !== "humid-evidence" || !/^[0-9a-f]{32}$/.test(record.id)) throw new MsgError("bad_evidence", "Not a locker item");
    const id = fromHex(record.id);
    const k = unb64u(record.key), b = unb64u(record.blob);
    if (k.length !== 12 + 32 + 16 || b.length < 12 + 16) throw new MsgError("malformed", "Locker item is damaged");
    const itemKey = await aeadOpen(key, k.subarray(0, 12), k.subarray(12), aadKey(id));
    const pt = await aeadOpen(itemKey, b.subarray(0, 12), b.subarray(12), aadItem(id));
    wipe(itemKey);
    const [m, bytes] = unlp(pt, 2, MAX_EVIDENCE);
    const meta = decodeJSON(m);
    if (meta?.v !== EVIDENCE_VERSION) throw new MsgError("malformed", "Unsupported locker item");
    return { id: record.id, ...meta, bytes };
  });
}

/* ---------- release ---------- */

function releaseStatement({ hash, recipient, purpose, releasedAt, expiresAt, fp }) {
  return lp(utf8("HUMID-RELEASE-v1"), hash, utf8(recipient), utf8(purpose), utf8(String(releasedAt)), utf8(String(expiresAt)), fp);
}
export const releaseCommitment = (st) => H(label("stamp release"), st);

/**
 * Release an opened item to someone. Returns a packet { credential, release }
 * to hand over with the bytes. `recipient` and `purpose` are short text, e.g.
 * "LinkedIn trust & safety", "impersonation report 4471". One live check.
 */
export async function makeRelease(item, { persona, recipient, purpose, days = 30, stamper, now = Date.now() } = {}) {
  if (!persona?.keys || !persona?.pub) throw new MsgError("bad_persona", "A persona with its keys is needed to sign");
  if (typeof stamper !== "function") throw new MsgError("stamp_required", "A release takes a live check");
  if (!item?.credential || !(item.bytes instanceof Uint8Array)) throw new MsgError("bad_evidence", "Open the item first (openEvidence)");
  if (item.credential.signer?.id !== persona.id) throw new MsgError("bad_persona", "Release with the same persona that sealed the item");
  if (!Number.isInteger(days) || days < 1 || days > MAX_RELEASE_DAYS) throw new MsgError("bad_evidence", `Release must last 1 to ${MAX_RELEASE_DAYS} days`);
  const r = clean(recipient, "Recipient"), p = clean(purpose, "Purpose");
  if (!r) throw new MsgError("bad_evidence", "Say who it is released to");
  const hash = mediaHash(item.bytes);
  const fields = { hash, recipient: r, purpose: p, releasedAt: now, expiresAt: now + days * DAY, fp: personaFingerprint(persona.pub) };
  const st = releaseStatement(fields);
  const stamp = await stamper(releaseCommitment(st), { at: now });
  const sig = dualSign("evidence release", concat(st, utf8(JSON.stringify(stamp))), persona.keys);
  return {
    credential: item.credential,
    release: {
      v: EVIDENCE_VERSION, type: "humid-evidence-release",
      hash: b64u(hash), recipient: r, purpose: p, releasedAt: now, expiresAt: fields.expiresAt,
      signer: { id: persona.id, pub: encodePub(persona.pub) },
      stamp, sig: { dsa: b64u(sig.dsa), slh: b64u(sig.slh) },
    },
  };
}

/**
 * Recipient: check a released packet against the bytes.
 * Returns { ok, reason?, signer, recipient, purpose, releasedAt, expiresAt, capturedAt, kind }.
 * ok means: the media credential checks out (same bytes, signed, stamped live),
 * the release is signed by the same persona and stamped live, and it hasn't
 * expired. With expectSigner, also that the persona is the one the person publishes.
 */
export function verifyRelease(packet, bytes, { stampKeys, expectSigner, now = Date.now() } = {}) {
  const no = (reason, extra = {}) => ({ ok: false, reason, ...extra });
  try {
    const media = verifyMediaCredential(packet?.credential, bytes, { stampKeys, expectSigner, now });
    if (!media.ok) return no(`media_${media.reason}`);
    const rel = packet.release;
    if (rel?.v !== EVIDENCE_VERSION || rel.type !== "humid-evidence-release") return no("not_a_release");
    const pub = decodePub(rel.signer?.pub);
    if (personaId(pub) !== rel.signer.id || rel.signer.id !== media.signer) return no("signer_mismatch");
    if (!Number.isSafeInteger(rel.releasedAt) || !Number.isSafeInteger(rel.expiresAt) || rel.expiresAt <= rel.releasedAt) return no("malformed");
    const hash = mediaHash(bytes);
    if (!equal(hash, unb64u(rel.hash, 32))) return no("bytes_changed");
    const st = releaseStatement({ hash, recipient: clean(rel.recipient, "Recipient"), purpose: clean(rel.purpose, "Purpose"), releasedAt: rel.releasedAt, expiresAt: rel.expiresAt, fp: personaFingerprint(pub) });
    const sigs = { dsa: unb64u(rel.sig?.dsa, SIZES.dsaSig), slh: unb64u(rel.sig?.slh, SIZES.slhSig) };
    if (!dualVerify("evidence release", concat(st, utf8(JSON.stringify(rel.stamp))), sigs, pub)) return no("bad_signature");
    // by the release's own time, inside its stamp key's epoch, against retired keys too (MSG-10)
    if (!verifyStamp(stampKeys, rel.stamp, releaseCommitment(st), { now, at: rel.releasedAt, longLived: true })) return no("not_live");
    const base = { signer: media.signer, recipient: rel.recipient, purpose: rel.purpose, releasedAt: rel.releasedAt, expiresAt: rel.expiresAt, capturedAt: media.capturedAt, kind: media.kind };
    if (now > rel.expiresAt) return no("expired", base);
    return { ok: true, ...base };
  } catch (e) {
    return no(e instanceof MsgError ? e.code : "malformed");
  }
}
