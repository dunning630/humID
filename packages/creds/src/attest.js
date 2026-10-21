// From a verified credential to the least that answers the question.
//
// A verified mobile license holds a name, address, number and photo. Most
// questions need one fact: over 21, a valid ID from Illinois, the name
// matches. `minimise` keeps only the facts asked for, derives age facts from
// the birth date when the issuer didn't state them, and drops everything else.
// The result is what HumID stores or shares; the full credential isn't kept
// unless the holder files their own ID in their vault.
//
// `commitment` binds the minimised claims to one persona (HumID 4.0): it is a
// SHA3-256 over a canonical encoding that includes a random 32-byte salt, the same shape a live stamp commits to,
// so a stamped message can carry "a live human approved sharing: over 21,
// valid US-IL license" without the credential or the person.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { CredsError, fail } from "./request.js";

const te = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const CLAIM_SCHEMA = "humid.idclaim/1";

/** Facts minimise can produce. Identifying ones need `identifying: true`. */
export const FACTS = {
  age_over_18: { identifying: false }, age_over_21: { identifying: false }, age_over_25: { identifying: false }, age_over_65: { identifying: false },
  valid_document: { identifying: false }, issuing_country: { identifying: false }, issuing_jurisdiction: { identifying: false },
  given_name: { identifying: true }, family_name: { identifying: true }, birth_date: { identifying: true },
  document_number: { identifying: true }, address: { identifying: true }, portrait: { identifying: true },
};

/** Whole years between a YYYY-MM-DD birth date and `now` (UTC), or null. */
export function ageOn(birth, now = new Date()) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birth || "");
  if (!m) return null;
  const [y, mo, d] = [+m[1], +m[2], +m[3]];
  let age = now.getUTCFullYear() - y;
  if (now.getUTCMonth() + 1 < mo || (now.getUTCMonth() + 1 === mo && now.getUTCDate() < d)) age--;
  return age;
}

/** Canonical JSON: sorted keys, no whitespace. Bytes and undefined are refused. */
export function canonical(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number" || typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (typeof v === "object" && !(v instanceof Uint8Array)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  throw new CredsError("bad_request", "Only plain values can be committed to.");
}

/**
 * Keep only the requested facts from a verified result.
 *   share:       fact names (keys of FACTS)
 *   identifying: must be true to include names, birth date, number, address or photo
 *   persona:     optional persona ID (HC-…) to bind the commitment to
 */
export function minimise(result, { share, identifying = false, persona, now = new Date() } = {}) {
  if (!result || !result.assurance) fail("bad_request", "Minimise a verified result.");
  if (!Array.isArray(share) || !share.length) fail("bad_request", "Say which facts to keep.");
  if (["printed", "signature-only"].includes(result.assurance)) fail("not_verified", "Only a verified credential can back a claim.");
  const c = result.claims;
  const facts = {};
  const derived = [];
  for (const f of share) {
    if (!FACTS[f]) fail("bad_request", `"${f}" isn't a fact HumID shares.`);
    if (FACTS[f].identifying && !identifying) fail("identifying", `"${f}" identifies the person; pass identifying: true to share it.`);
    const age = /^age_over_(\d+)$/.exec(f);
    if (age) {
      const n = +age[1];
      if (typeof c[f] === "boolean") facts[f] = c[f];
      else {
        const years = ageOn(c.birth_date, now);
        if (years == null) fail("not_available", `The credential didn't share enough to tell whether the holder is over ${n}.`);
        facts[f] = years >= n;
        derived.push(f);
      }
      continue;
    }
    if (f === "valid_document") {
      const exp = c.expiry_date ? new Date(`${c.expiry_date}T23:59:59Z`) : result.validUntil ? new Date(result.validUntil) : null;
      facts.valid_document = !!exp && exp >= now && result.status?.status !== "revoked" && result.status?.status !== "suspended";
      continue;
    }
    if (f === "portrait") fail("bad_request", "A photo can't go into a claim; keep it in the vault record.");
    // The issuing country comes from the issuer's trusted certificate when there is one.
    const v = f === "issuing_country" ? result.issuer?.country ?? c.issuing_country : Object.hasOwn(c, f) ? c[f] : null;
    if (v == null) fail("not_available", `The credential didn't share ${f.replace(/_/g, " ")}.`);
    facts[f] = v;
  }
  const claim = {
    schema: CLAIM_SCHEMA, type: result.type, assurance: result.assurance,
    issuer: { country: result.issuer?.country || null, jurisdiction: result.issuer?.jurisdiction || null },
    facts, derived, status: result.status?.status || "unchecked", checkedAt: now.toISOString(),
  };
  if (persona !== undefined) {
    if (typeof persona !== "string" || !/^HC-[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/.test(persona)) fail("bad_request", "That isn't a persona ID.");
    claim.persona = persona;
    // A random salt, so a commitment seen without its claim can't be brute-forced
    // back to low-entropy facts such as a birth date.
    claim.salt = hex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    claim.commitment = commit(claim);
  }
  return claim;
}

/** SHA3-256("HUMID-IDCLAIM-v1" ‖ 0x00 ‖ canonical(claim without commitment)), hex. */
export function commit(claim) {
  const { commitment, ...rest } = claim;
  const body = te.encode(canonical(rest));
  const label = te.encode("HUMID-IDCLAIM-v1");
  const msg = new Uint8Array(label.length + 1 + body.length);
  msg.set(label, 0); msg.set(body, label.length + 1);
  return Array.from(sha3_256(msg), (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Recompute a claim's commitment and compare. */
export const checkCommitment = (claim) => typeof claim?.commitment === "string" && commit(claim) === claim.commitment;
