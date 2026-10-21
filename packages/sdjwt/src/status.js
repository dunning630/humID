// Revocation and suspension: IETF Token Status List (draft-ietf-oauth-status-list).
//
// A credential carries status: { status_list: { idx, uri } }. The issuer
// publishes one signed list at `uri` for many credentials, so fetching it
// tells the issuer nothing about which credential is being checked. The list
// is a bit array (1, 2, 4 or 8 bits per credential, least significant bit
// first), DEFLATE-compressed in ZLIB format: base64url in a statuslist+jwt, or
// raw bytes in a statuslist+cwt (the form mdoc issuers use).
//
//   0 VALID   1 INVALID (revoked)   2 SUSPENDED   3 application-specific
//
// HumID checks the list's signature (the same trust as the credential), that
// its subject is the uri the credential named, and that it isn't stale. The
// app does the fetching; nothing here touches the network.

import { decode, get, parse1, verifySign1, x5chain } from "@humid/mdoc";
import { parseJws, verifyJwsWith, jwkKey, x5cKey, chainKey, unb64u, JoseError } from "./jose.js";

export class StatusError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new StatusError(code, m); };
const jose = (fn) => { try { return fn(); } catch (e) { if (e instanceof JoseError) fail(e.code, e.message); throw e; } };

export const STATUS = { 0: "valid", 1: "revoked", 2: "suspended", 3: "application-specific" };
const MAX_LIST = 16 << 20; // 16 MiB decompressed: far more than any real list; stops a compression bomb

/** ZLIB-format DEFLATE → bytes, with a hard size cap. Works in browsers and Node (DecompressionStream). */
export async function inflate(bytes, max = MAX_LIST) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
  const reader = stream.getReader();
  const chunks = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > max) { await reader.cancel(); fail("bad_status_list", "The status list is too large."); }
      chunks.push(value);
    }
  } catch (e) { if (e instanceof StatusError) throw e; fail("bad_status_list", "The status list can't be decompressed."); }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/** The status at `idx` in a decompressed list of `bits`-wide entries. */
export function statusAt(list, bits, idx) {
  if (![1, 2, 4, 8].includes(bits)) fail("bad_status_list", "The status list has an invalid entry size.");
  if (!Number.isSafeInteger(idx) || idx < 0) fail("bad_status_ref", "The credential's status index is invalid.");
  const bit = idx * bits;
  const byte = Math.floor(bit / 8);
  if (byte >= list.length) fail("bad_status_ref", "The credential's status index is outside the list.");
  const value = (list[byte] >> (bit % 8)) & ((1 << bits) - 1);
  return { value, status: STATUS[value] ?? "application-specific" };
}

/** A credential's status reference from an SD-JWT VC payload or an mdoc MSO. null if it has none. */
export function statusReference(source) {
  const s = source instanceof Map ? get(source, "status") : source?.status;
  if (s == null) return null;
  const sl = s instanceof Map ? get(s, "status_list") : s.status_list;
  if (!sl) return null;
  const idx = sl instanceof Map ? get(sl, "idx") : sl.idx;
  const uri = sl instanceof Map ? get(sl, "uri") : sl.uri;
  if (!Number.isSafeInteger(idx) || idx < 0 || typeof uri !== "string") fail("bad_status_ref", "The credential's status reference is malformed.");
  let u;
  try { u = new URL(uri); } catch { fail("bad_status_ref", "The credential's status list address isn't a URL."); }
  if (u.protocol !== "https:") fail("bad_status_ref", "The credential's status list must be served over https.");
  return { idx, uri };
}

const fresh = ({ iat, exp, ttl }, now, maxAgeSeconds, skew = 60) => {
  const t = Math.floor(now.getTime() / 1000);
  if (typeof iat !== "number") fail("bad_status_list", "The status list has no issue time.");
  if (iat > t + skew) fail("bad_status_list", "The status list was issued in the future.");
  if (exp !== undefined && t > exp + skew) fail("stale_status", "The status list has expired. Fetch it again.");
  if (ttl !== undefined && t > iat + ttl + skew) fail("stale_status", "The status list is past its time to live. Fetch it again.");
  if (maxAgeSeconds && t > iat + maxAgeSeconds) fail("stale_status", "The status list is older than HumID accepts.");
};

/**
 * Check a statuslist+jwt and the reference's entry in it.
 * trust: as verifySdJwtVc ({ roots } for x5c, or { resolveKey }).
 * root: the credential's own root fingerprint; when given, the list must chain to the same root.
 */
export async function checkStatusJwt(token, ref, { trust = {}, now = new Date(), maxAgeSeconds = 86400, root } = {}) {
  const jws = jose(() => parseJws(token));
  if (jws.header.typ !== "statuslist+jwt") fail("bad_status_list", "This isn't a status list token.");
  let key;
  if (jws.header.x5c) {
    const c = jose(() => x5cKey(jws.header.x5c, { roots: trust.roots, now }));
    if (root && c.root.fingerprint !== root) fail("untrusted_issuer", "The status list isn't signed under the credential's own issuer.");
    key = c.key;
  } else if (trust.resolveKey) {
    if (root) fail("untrusted_issuer", "The status list must be signed under the credential's own issuer certificate.");
    key = jose(() => jwkKey(trust.resolveKey({ iss: jws.payload.iss, header: jws.header }) || fail("untrusted_issuer", "No trusted key for the status list.")));
  } else fail("untrusted_issuer", "The status list doesn't say how to find its signer's key.");
  jose(() => verifyJwsWith(jws, key));
  const p = jws.payload;
  if (p.sub !== ref.uri) fail("bad_status_list", "The status list is for a different address than the credential names.");
  fresh(p, now, maxAgeSeconds);
  const sl = p.status_list;
  if (!sl || typeof sl.lst !== "string" || typeof sl.bits !== "number") fail("bad_status_list", "The status list is malformed.");
  const list = await inflate(jose(() => unb64u(sl.lst)));
  return { ...statusAt(list, sl.bits, ref.idx), checkedAt: now.toISOString(), listIssuedAt: new Date(p.iat * 1000).toISOString() };
}

const CWT = { sub: 2, exp: 4, iat: 6, ttl: 65534, statusList: 65533 };

/** Check a statuslist+cwt (COSE_Sign1) and the reference's entry. roots: trusted issuer roots for its x5chain. */
export async function checkStatusCwt(bytes, ref, { roots = [], now = new Date(), maxAgeSeconds = 86400, root } = {}) {
  let s1;
  try { s1 = parse1(bytes instanceof Uint8Array ? decode(bytes) : bytes); } catch { fail("bad_status_list", "The status list can't be read."); }
  const typ = get(s1.protectedMap, 16);
  if (typ !== "application/statuslist+cwt" && typ !== 65533) fail("bad_status_list", "This isn't a status list token.");
  const ders = x5chain(s1);
  if (!ders.length) fail("bad_status_list", "The status list's signer certificate is missing.");
  // The same chain rules as a credential's issuer: every certificate valid now, CAs above, a signing leaf, a trusted root.
  const c = jose(() => chainKey(ders, { roots, now }));
  if (root && c.root.fingerprint !== root) fail("untrusted_issuer", "The status list isn't signed under the credential's own issuer.");
  if (!verifySign1(s1, c.key)) fail("bad_signature", "The status list's signature doesn't verify.");
  let claims;
  try { claims = decode(s1.payload); } catch { fail("bad_status_list", "The status list can't be read."); }
  if (get(claims, CWT.sub) !== ref.uri) fail("bad_status_list", "The status list is for a different address than the credential names.");
  const iat = get(claims, CWT.iat), exp = get(claims, CWT.exp), ttl = get(claims, CWT.ttl);
  fresh({ iat, exp, ttl }, now, maxAgeSeconds);
  const sl = get(claims, CWT.statusList);
  const lst = get(sl, "lst"), bits = get(sl, "bits");
  if (!(lst instanceof Uint8Array) || typeof bits !== "number") fail("bad_status_list", "The status list is malformed.");
  const list = await inflate(lst);
  return { ...statusAt(list, bits, ref.idx), checkedAt: now.toISOString(), listIssuedAt: new Date(iat * 1000).toISOString() };
}
