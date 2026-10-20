// SD-JWT (RFC 9901) and SD-JWT VC (draft-ietf-oauth-sd-jwt-vc): the format
// the EU Digital Identity Wallet's PID uses besides mdoc, and a common one for
// other government and professional credentials.
//
//   <issuer-signed JWT>~<disclosure>~<disclosure>~…~<KB-JWT>
//
// The issuer signs digests of every claim it lets the holder hide. The holder
// sends only the disclosures it chooses, plus a key-binding JWT signed with
// the key the issuer put in `cnf`, over this verifier's nonce and audience and
// a hash of exactly what was presented. HumID checks, in order:
//
//   1. the issuer's signature, with a key from a trusted x5c chain or a key
//      the caller vouches for (pinned, or from the issuer's metadata)
//   2. every disclosure is referenced exactly once by a signed digest, and no
//      digest appears twice; disclosed names can't overwrite signed ones
//   3. SD-JWT VC rules: typ, vct, validity window, cnf
//   4. key binding: signed by cnf, for this nonce and audience, recent, and
//      sd_hash covers every disclosure sent (none added or dropped on the way)

import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { parseJws, verifyJwsWith, jwkKey, x5cKey, unb64u, b64u, JoseError } from "./jose.js";

export class SdJwtError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new SdJwtError(code, m); };
const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);
const HASHES = { "sha-256": sha256, "sha-384": sha384, "sha-512": sha512 };
export const VC_TYPES = ["dc+sd-jwt", "vc+sd-jwt"]; // vc+sd-jwt: the name before draft 06, still sent by some wallets
const NEVER_DISCLOSED = ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status", "_sd", "_sd_alg", "..."];

const jose = (fn) => { try { return fn(); } catch (e) { if (e instanceof JoseError) fail(e.code, e.message); throw e; } };

/** Split a presentation. Returns { jwt, disclosures: [string], kb: string|null, presented: the part sd_hash covers }. */
export function splitSdJwt(s) {
  if (typeof s !== "string" || !s.includes("~")) fail("malformed", "This isn't an SD-JWT.");
  if (s.length > 1 << 20) fail("malformed", "The credential is too large.");
  const parts = s.split("~");
  const kb = parts.pop();
  const [jwt, ...disclosures] = parts;
  if (!jwt || disclosures.some((d) => !d || !/^[A-Za-z0-9_-]+$/.test(d))) fail("malformed", "The SD-JWT has an empty or malformed part.");
  if (disclosures.length > 512) fail("malformed", "Too many disclosures.");
  return { jwt, disclosures, kb: kb || null, presented: s.slice(0, s.length - kb.length) };
}

/** Rebuild the claims from the signed payload and the disclosures. Strict: every disclosure used exactly once. */
export function resolveDisclosures(payload, disclosures) {
  const alg = payload._sd_alg ?? "sha-256";
  const hash = HASHES[alg];
  if (!hash) fail("unsupported_alg", `Disclosure digest ${alg} isn't supported.`);
  const byDigest = new Map();
  for (const d of disclosures) {
    const digest = b64u(hash(te.encode(d)));
    if (byDigest.has(digest)) fail("bad_disclosure", "The same disclosure was sent twice.");
    let arr;
    try { arr = JSON.parse(td.decode(unb64u(d))); } catch { fail("bad_disclosure", "A disclosure can't be read."); }
    if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3) || typeof arr[0] !== "string") fail("bad_disclosure", "A disclosure is malformed.");
    if (arr.length === 3 && (typeof arr[1] !== "string" || NEVER_DISCLOSED.includes(arr[1]) || arr[1] === "__proto__")) fail("bad_disclosure", `"${arr[1]}" can't be a disclosed claim.`);
    byDigest.set(digest, { arr, used: false });
  }
  const seen = new Set();
  const take = (digest, kind) => {
    if (typeof digest !== "string") fail("bad_disclosure", "A signed digest isn't text.");
    if (seen.has(digest)) fail("bad_disclosure", "A digest appears twice in the signed credential.");
    seen.add(digest);
    const d = byDigest.get(digest);
    if (!d) return undefined; // decoy, or a claim the holder chose not to show
    if ((kind === "obj") !== (d.arr.length === 3)) fail("bad_disclosure", "A disclosure is used in the wrong place.");
    d.used = true;
    return d.arr;
  };
  const walk = (v, depth) => {
    if (depth > 32) fail("malformed", "The credential is nested too deeply.");
    if (Array.isArray(v)) {
      const out = [];
      for (const el of v) {
        if (isObj(el) && "..." in el) {
          if (Object.keys(el).length !== 1) fail("bad_disclosure", "An array placeholder has extra members.");
          const d = take(el["..."], "arr");
          if (d) out.push(walk(d[1], depth + 1));
        } else out.push(walk(el, depth + 1));
      }
      return out;
    }
    if (!isObj(v)) return v;
    const out = Object.create(null);
    for (const [k, x] of Object.entries(v)) if (k !== "_sd" && k !== "_sd_alg") out[k] = walk(x, depth + 1);
    if (v._sd !== undefined) {
      if (!Array.isArray(v._sd)) fail("bad_disclosure", "_sd isn't an array.");
      for (const digest of v._sd) {
        const d = take(digest, "obj");
        if (!d) continue;
        if (d[1] in out) fail("bad_disclosure", `"${d[1]}" is both signed and disclosed.`);
        out[d[1]] = walk(d[2], depth + 1);
      }
    }
    return { ...out };
  };
  const claims = walk(payload, 0);
  for (const d of byDigest.values()) if (!d.used) fail("bad_disclosure", "A disclosure isn't covered by the issuer's signature.");
  return { claims, disclosed: [...byDigest.values()].filter((d) => d.arr.length === 3).map((d) => d.arr[1]) };
}

/**
 * Verify an SD-JWT VC presentation.
 *
 *   trust:   { roots: [IACA-style certificates for x5c], issuers?: [allowed iss],
 *              resolveKey?: ({ iss, header }) => JWK }   (pinned keys or issuer metadata)
 *   binding: { nonce, aud } — required unless requireKeyBinding is false
 *
 * Returns { iss, vct, claims, disclosed, issuer, cnf, status, validity, keyBinding }.
 */
export function verifySdJwtVc(presentation, { trust = {}, nonce, aud, now = new Date(), requireKeyBinding = true, maxKbAgeSeconds = 300, skewSeconds = 60, vcts } = {}) {
  const parts = splitSdJwt(presentation);
  const jws = jose(() => parseJws(parts.jwt));
  const { header, payload } = jws;
  if (!VC_TYPES.includes(header.typ)) fail("bad_type", "This isn't an SD-JWT VC (typ dc+sd-jwt).");
  if (typeof payload.vct !== "string" || !payload.vct) fail("bad_type", "The credential has no type (vct).");
  if (vcts && !vcts.includes(payload.vct)) fail("bad_type", `A ${payload.vct} credential wasn't asked for.`);
  if (payload.iss !== undefined && typeof payload.iss !== "string") fail("malformed", "The issuer isn't text.");
  if (trust.issuers && !trust.issuers.includes(payload.iss)) fail("untrusted_issuer", "This credential's issuer isn't in HumID's trusted list.");

  // 1. The issuer's key, then its signature.
  let issuer;
  if (header.x5c) issuer = jose(() => x5cKey(header.x5c, { roots: trust.roots, now }));
  else if (trust.resolveKey) {
    const jwk = trust.resolveKey({ iss: payload.iss, header });
    if (!jwk) fail("untrusted_issuer", "No trusted key for this credential's issuer.");
    issuer = { key: jose(() => jwkKey(jwk)), leaf: null, root: null, pinned: true };
  } else fail("untrusted_issuer", "The credential doesn't say how to find its issuer's key, and none is pinned.");
  jose(() => verifyJwsWith(jws, issuer.key));

  // 2. Validity window.
  const t = Math.floor(now.getTime() / 1000);
  const num = (v, name) => { if (v !== undefined && (typeof v !== "number" || !Number.isFinite(v))) fail("malformed", `${name} isn't a number.`); return v; };
  const exp = num(payload.exp, "exp"), nbf = num(payload.nbf, "nbf"), iat = num(payload.iat, "iat");
  if (exp !== undefined && t > exp + skewSeconds) fail("expired", "The credential has expired. Refresh it in the wallet, then share again.");
  if (nbf !== undefined && t < nbf - skewSeconds) fail("not_yet_valid", "The credential isn't valid yet.");
  if (iat !== undefined && iat > t + skewSeconds) fail("not_yet_valid", "The credential was issued in the future.");

  // 3. Disclosures.
  const { claims, disclosed } = resolveDisclosures(payload, parts.disclosures);
  // (Registered claims can't be disclosed and disclosed names can't shadow signed ones: resolveDisclosures refuses both.)

  // 4. Key binding.
  let keyBinding = { ok: false };
  if (parts.kb) {
    const cnf = payload.cnf?.jwk;
    if (!cnf) fail("no_key_binding", "The credential isn't bound to a holder key, so its presentation can't be checked.");
    const kb = jose(() => parseJws(parts.kb));
    if (kb.header.typ !== "kb+jwt") fail("bad_key_binding", "The key-binding token has the wrong type.");
    jose(() => verifyJwsWith(kb, jwkKey(cnf)));
    const p = kb.payload;
    if (nonce === undefined || aud === undefined) fail("bad_request", "Checking key binding needs the request's nonce and audience.");
    if (p.nonce !== nonce) fail("bad_key_binding", "The presentation was made for a different request (nonce).");
    if (p.aud !== aud) fail("bad_key_binding", "The presentation was made for a different site (audience).");
    if (typeof p.iat !== "number" || p.iat > t + skewSeconds || p.iat < t - maxKbAgeSeconds) fail("bad_key_binding", "The presentation is too old or from the future.");
    const alg = payload._sd_alg ?? "sha-256";
    if (p.sd_hash !== b64u(HASHES[alg](te.encode(parts.presented)))) fail("bad_key_binding", "The presentation was altered after the holder signed it.");
    keyBinding = { ok: true, iat: p.iat };
  } else if (requireKeyBinding) fail("no_key_binding", "The wallet didn't prove it holds the credential (no key-binding signature). The data may have been copied.");

  return {
    iss: payload.iss ?? null, vct: payload.vct, typ: header.typ, claims, disclosed,
    issuer: { leaf: issuer.leaf, root: issuer.root, pinned: !!issuer.pinned },
    cnf: payload.cnf ?? null, status: payload.status ?? null,
    validity: { iat: iat ?? null, nbf: nbf ?? null, exp: exp ?? null },
    keyBinding,
  };
}

/**
 * Where an issuer's JWT VC Issuer Metadata lives (draft-ietf-oauth-sd-jwt-vc):
 * the well-known path goes between the host and the path, trailing "/" removed.
 * The app fetches it; checkIssuerMetadata then picks the key.
 */
export function issuerMetadataUrl(iss) {
  let u;
  try { u = new URL(iss); } catch { fail("bad_issuer", "The issuer isn't a URL."); }
  if (u.protocol !== "https:" || u.search || u.hash) fail("bad_issuer", "The issuer must be an https URL without query or fragment.");
  return `${u.origin}/.well-known/jwt-vc-issuer${u.pathname.replace(/\/$/, "")}`;
}

/** The JWK to use from fetched issuer metadata: its `issuer` must equal iss; choose by kid when given. */
export function keyFromIssuerMetadata(metadata, { iss, kid }) {
  if (!isObj(metadata) || metadata.issuer !== iss) fail("bad_issuer", "The issuer's metadata is for a different issuer.");
  if (metadata.jwks_uri && metadata.jwks) fail("bad_issuer", "The issuer's metadata has both jwks and jwks_uri.");
  const keys = metadata.jwks?.keys;
  if (!Array.isArray(keys)) fail("bad_issuer", "The issuer's metadata has no inline keys (fetch jwks_uri first).");
  const usable = keys.filter((k) => !k.use || k.use === "sig");
  const k = kid ? usable.find((x) => x.kid === kid) : usable.length === 1 ? usable[0] : null;
  if (!k) fail("untrusted_issuer", "The issuer's metadata doesn't name the key this credential was signed with.");
  return k;
}
