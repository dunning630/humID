// @humid/creds/server — the parts that run only on a server (Node), because
// the passport checks in @humid/anchor use node:crypto: ICAO 9303 passport and
// ID card chips into the same result shape as wallet credentials, and ICAO
// master lists as a source of trusted country signing CAs.

import { passiveAuth, activeAuth, readMasterList, loadCscas, alpha2Of, AnchorError } from "@humid/anchor";
import { CredsError, fail } from "./request.js";

const wrap = (fn) => { try { return fn(); } catch (e) { if (e instanceof AnchorError) throw new CredsError(e.code, e.message); throw e; } };

/** YYMMDD → YYYY-MM-DD. Birth dates take the century that isn't in the future; expiry dates are 20YY. */
function mrzDate(yymmdd, kind, now = new Date()) {
  if (!/^\d{6}$/.test(yymmdd || "")) return null;
  const yy = +yymmdd.slice(0, 2);
  const cur = now.getUTCFullYear() % 100;
  const century = kind === "birth" ? (yy > cur ? 1900 : 2000) : 2000;
  return `${century + yy}-${yymmdd.slice(2, 4)}-${yymmdd.slice(4, 6)}`;
}

/**
 * Check a passport or ID card chip the server read through the app (DG1,
 * EF.SOD, DG15) and, when the chip has an Active Authentication key, its
 * signature over the server's fresh nonce.
 *   cscas: trusted CSCAs (from a directory, a master list, or both)
 *   active: { nonce, signature, hash? } — required when the chip has an AA key
 */
export function verifyPassportChip(chip, { cscas, active, now = new Date() } = {}) {
  const bytes = (v) => v == null || v instanceof Uint8Array;
  if (!chip || typeof chip !== "object" || !["dg1", "sod", "dg15"].every((k) => bytes(chip[k]))) fail("bad_request", "The chip data must be bytes.");
  if (active && (!bytes(active.nonce) || !bytes(active.signature))) fail("bad_request", "The chip's answer must be bytes.");
  const pa = wrap(() => passiveAuth(chip, { cscas, now }));
  let holder = false;
  if (pa.aaRequired) {
    if (!active?.nonce || !active?.signature) fail("no_chip_proof", "This chip can prove it's the original; answer the challenge to continue.");
    wrap(() => activeAuth({ dg15: chip.dg15, nonce: active.nonce, signature: active.signature, hash: active.hash }));
    holder = true;
  }
  const m = pa.mrz;
  const country = alpha2Of(m.issuer) || null;
  return {
    type: m.documentCode?.startsWith("P") ? "passport_chip" : "id_card_chip", format: "icao-9303", protocol: "nfc",
    assurance: holder ? "issuer+holder" : "issuer", holderBound: holder,
    issuer: { country, jurisdiction: null, root: pa.cscaSubject || null, signer: null, mrzIssuer: m.issuer },
    claims: Object.fromEntries(Object.entries({
      given_name: m.given || null, family_name: m.surname || null, birth_date: mrzDate(m.birth, "birth", now),
      document_number: m.number || null, expiry_date: mrzDate(m.expiry, "expiry", now),
      issuing_country: country, nationality: m.nationality || null, sex: m.sex || null,
    }).filter(([, v]) => v != null)),
    values: null, validUntil: mrzDate(m.expiry, "expiry", now), statusRef: null, status: null,
    note: holder ? null : "This chip has no Active Authentication key, so a copy of its data can't be told from the original.",
  };
}

/**
 * CSCAs from an ICAO master list, checked against the publisher's own CSCA.
 * Returns X509Certificates usable as `cscas`.
 */
export function cscasFromMasterList(bytes, { publisherCscas, now } = {}) {
  return wrap(() => readMasterList(bytes, { publisherCscas, now })).cscas;
}

export { loadCscas };
