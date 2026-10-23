// One record for any identity document, whatever it was read from: the photo
// page's MRZ, a license barcode, a chip, or typed by hand. This is what HumID
// seals into the vault (media type application/vnd.humid.id+json), so it's
// plain JSON with a schema tag, and every field says where it came from.
import { countryName, regionName } from "./places.js";
import { chipIntegrityOk, safeCheckIntegrity, readDg1, readDg2 } from "./chip.js";
import { mdocFields, imageType, alpha3 } from "./mdoc.js";

export const SCHEMA = "humid.id/1";
export const MEDIA_TYPE = "application/vnd.humid.id+json";

export const KINDS = {
  passport: { label: "Passport", short: "Passport", chip: true, sides: ["front"], shape: "td3" },
  driver_license: { label: "Driver's license", short: "License", chip: false, sides: ["front", "back"], shape: "id1" },
  id_card: { label: "ID card", short: "ID card", chip: true, sides: ["front", "back"], shape: "id1" },
  residence_permit: { label: "Residence permit", short: "Permit", chip: true, sides: ["front", "back"], shape: "id1" },
  visa: { label: "Visa", short: "Visa", chip: false, sides: ["front"], shape: "td3" },
  other: { label: "Card", short: "Card", chip: false, sides: ["front", "back"], shape: "id1" },
};
export const kindLabel = (k) => KINDS[k]?.label || "ID";

/**
 * The fields, in display order. `kinds` limits a field to some documents;
 * `group` arranges the review form and the card view.
 */
export const FIELDS = [
  { key: "surname", label: "Surname", group: "person" },
  { key: "given", label: "Given names", group: "person" },
  { key: "suffix", label: "Suffix", group: "person", kinds: ["driver_license", "id_card"], optional: true },
  { key: "birth", label: "Date of birth", group: "person", type: "date" },
  { key: "sex", label: "Sex", group: "person", type: "sex" },
  { key: "nationality", label: "Nationality", group: "person", type: "country", kinds: ["passport", "id_card", "residence_permit", "visa"] },
  { key: "placeOfBirth", label: "Place of birth", group: "person", optional: true },
  { key: "number", label: "Document number", group: "document", mono: true },
  { key: "issuer", label: "Issuing country", group: "document", type: "country" },
  { key: "region", label: "State or province", group: "document", type: "region", kinds: ["driver_license", "id_card"], optional: true },
  { key: "issued", label: "Issued", group: "document", type: "date", optional: true },
  { key: "expiry", label: "Expires", group: "document", type: "date" },
  { key: "vehicleClass", label: "Class", group: "license", kinds: ["driver_license"], optional: true },
  { key: "restrictions", label: "Restrictions", group: "license", kinds: ["driver_license"], optional: true },
  { key: "endorsements", label: "Endorsements", group: "license", kinds: ["driver_license"], optional: true },
  { key: "realId", label: "REAL ID", group: "license", type: "bool", kinds: ["driver_license", "id_card"], optional: true },
  { key: "discriminator", label: "Document discriminator", group: "license", kinds: ["driver_license", "id_card"], optional: true, mono: true },
  { key: "height", label: "Height", group: "physical", kinds: ["driver_license", "id_card"], optional: true },
  { key: "weight", label: "Weight", group: "physical", kinds: ["driver_license", "id_card"], optional: true },
  { key: "eyes", label: "Eyes", group: "physical", kinds: ["driver_license", "id_card"], optional: true },
  { key: "hair", label: "Hair", group: "physical", kinds: ["driver_license", "id_card"], optional: true },
  { key: "organDonor", label: "Organ donor", group: "physical", type: "bool", kinds: ["driver_license", "id_card"], optional: true },
  { key: "veteran", label: "Veteran", group: "physical", type: "bool", kinds: ["driver_license", "id_card"], optional: true },
  { key: "optional", label: "Personal number", group: "document", kinds: ["passport", "id_card", "residence_permit"], optional: true, mono: true },
];
export const fieldsFor = (kind) => FIELDS.filter((f) => !f.kinds || f.kinds.includes(kind));

const nowIso = () => new Date().toISOString();

export function newRecord(kind = "other") {
  return { schema: SCHEMA, kind, fields: {}, source: {}, address: null, verified: {}, images: {}, raw: {}, edited: [], createdAt: nowIso(), updatedAt: nowIso() };
}

/** Set fields, remembering where each came from. A chip or a mobile ID outranks a barcode, which outranks OCR. */
const RANK = { typed: 4, chip: 3, mdoc: 3, barcode: 2, mrz: 1, photo: 0 };
function put(rec, from, values) {
  for (const [k, v] of Object.entries(values)) {
    if (v == null || v === "") continue;
    const had = rec.source[k];
    if (had && had !== from && (RANK[had] ?? 0) > (RANK[from] ?? 0)) continue;
    rec.fields[k] = v;
    rec.source[k] = from;
  }
  rec.updatedAt = nowIso();
  return rec;
}

/** From an MRZ parse (photo OCR). consensus: several frames agreed. */
export function applyMrz(rec, mrz, { consensus = false } = {}) {
  if (!mrz) return rec;
  if (rec.kind === "other" || !rec.kind) rec.kind = mrz.kind;
  put(rec, "mrz", {
    surname: mrz.surname, given: mrz.given, number: mrz.number, issuer: mrz.issuer, nationality: mrz.nationality,
    birth: mrz.birth, expiry: mrz.expiry, sex: mrz.sex, optional: mrz.optional,
  });
  rec.verified.mrz = { format: mrz.format, checks: mrz.checks, valid: !!mrz.valid, consensus: !!consensus, repairs: mrz.repairs || 0 };
  rec.raw.mrz = mrz.lines;
  return rec;
}

/** From a license or ID card barcode (AAMVA). */
export function applyAamva(rec, a) {
  if (!a) return rec;
  const f = a.fields;
  if (rec.kind === "other" || !rec.kind) rec.kind = f.kind;
  put(rec, "barcode", {
    surname: f.surname, given: f.given, suffix: f.suffix, number: f.number, issuer: f.issuer, region: f.region,
    birth: f.birth, issued: f.issued, expiry: f.expiry, sex: f.sex, vehicleClass: f.vehicleClass, restrictions: f.restrictions,
    endorsements: f.endorsements, discriminator: f.discriminator, height: f.height?.text, weight: f.weight, eyes: f.eyes,
    hair: f.hair, placeOfBirth: f.placeOfBirth, realId: f.realId, organDonor: f.organDonor, veteran: f.veteran,
  });
  if (f.address && (!rec.address || rec.addressSource !== "typed")) { rec.address = f.address; rec.addressSource = "barcode"; }
  rec.verified.barcode = { standard: "AAMVA", version: a.version, jurisdictionVersion: a.jurisdictionVersion, iin: a.issuer.iin, truncated: !!f.truncated };
  return rec;
}

/**
 * From a chip: chip = { dg1, sod, dg2?, dg15?, access }, parsed = { mrz, portrait? }, integrity from checkIntegrity.
 * The chip's own files are kept (base64) so the integrity check can be repeated later.
 * Only applied when integrity.ok === true (see chipIntegrityOk); returns the record either way.
 */
export function applyChip(rec, chip, { mrz, integrity, b64 }) {
  // Fail closed: chip data is applied only when its files matched the chip's own hash list.
  // Otherwise nothing from the chip is used or kept, and the record says the chip failed.
  if (!chipIntegrityOk(integrity)) {
    rec.verified.chipFailed = { reason: integrity?.reason || (integrity?.ok === false ? "hash mismatch" : "not checked"), readAt: nowIso() };
    rec.updatedAt = nowIso();
    return rec;
  }
  delete rec.verified.chipFailed;
  if (mrz) {
    if (rec.kind === "other" || !rec.kind) rec.kind = mrz.kind;
    put(rec, "chip", {
      surname: mrz.surname, given: mrz.given, number: mrz.number, issuer: mrz.issuer, nationality: mrz.nationality,
      birth: mrz.birth, expiry: mrz.expiry, sex: mrz.sex, optional: mrz.optional,
    });
    rec.raw.mrz = mrz.lines;
  }
  rec.verified.chip = { integrity: true, algorithm: integrity?.algorithm || null, groups: integrity?.groups || {}, access: chip.access || null, readAt: nowIso() };
  rec.raw.chip = Object.fromEntries(["dg1", "dg2", "dg15", "sod", "com"].filter((k) => chip[k]).map((k) => [k, b64(chip[k])]));
  return rec;
}

/**
 * From a mobile ID (ISO 18013-5), already verified by @humid/mdoc's
 * verifyDeviceResponse. doc: one verified document. keep: the IssuerSigned
 * bytes (encodeIssuerSigned), stored so the issuer check can be repeated.
 */
export function applyMdoc(rec, doc, { b64, keep } = {}) {
  const m = mdocFields(doc.docType, doc.values);
  // Issuer and state from the trust anchor the document was held to, not from its data.
  if (doc.chain === "trusted" && doc.country) {
    m.fields.issuer = alpha3(doc.country);
    m.fields.region = doc.state || "";
  }
  // The mobile ID knows whether it is a license or an ID card; a passport or permit the holder picked stays as picked.
  if (!rec.kind || ["other", "driver_license", "id_card"].includes(rec.kind)) rec.kind = m.kind;
  put(rec, "mdoc", m.fields);
  if (m.address && (!rec.address || rec.addressSource !== "typed")) { rec.address = m.address; rec.addressSource = "mdoc"; }
  if (m.portrait && b64) rec.images.portrait = { type: imageType(m.portrait), data: b64(m.portrait), size: m.portrait.length, source: "mdoc" };
  rec.verified.mdoc = {
    docType: doc.docType, chain: doc.chain, root: doc.root?.subject || null, signer: doc.signer?.subject || null,
    device: doc.device?.method || null, deviceOk: doc.device?.ok ?? null, digestAlgorithm: doc.digestAlgorithm,
    signed: doc.validity?.signed || null, validUntil: doc.validity?.validUntil || null, readAt: nowIso(),
  };
  if (keep && b64) rec.raw.mdoc = { docType: doc.docType, issuerSigned: b64(keep) };
  return rec;
}

/** A person typed or corrected a field. Typed values always win, and are marked as such. */
export function applyTyped(rec, values) {
  const changed = Object.entries(values).filter(([k, v]) => (rec.fields[k] ?? "") !== (v ?? ""));
  for (const [k, v] of changed) {
    if (v === "" || v == null) { delete rec.fields[k]; delete rec.source[k]; }
    else { rec.fields[k] = v; rec.source[k] = "typed"; }
    if (!rec.edited.includes(k)) rec.edited.push(k);
  }
  rec.updatedAt = nowIso();
  return rec;
}

export const setImage = (rec, side, image) => { rec.images[side] = image; rec.updatedAt = nowIso(); return rec; };

/* ---------------- reading it back ---------------- */

const cap = (w) => w.replace(/(^|[\s'’-])([a-zà-ÿ])/g, (_, a, b) => a + b.toUpperCase());
/** "ERIKSSON" → "Eriksson"; names already in mixed case are left alone. */
export const niceName = (s) => (!s ? "" : s === s.toUpperCase() ? cap(s.toLowerCase()) : s);
export const fullName = (rec) => [niceName(rec.fields.given), niceName(rec.fields.surname), rec.fields.suffix].filter(Boolean).join(" ");

/** "Passport · United States", "Driver's license · Illinois". */
export function title(rec) {
  const k = kindLabel(rec.kind);
  const where = rec.fields.region ? regionName(rec.fields.region) : rec.fields.issuer ? countryName(rec.fields.issuer) : "";
  return where ? `${k} · ${where}` : k;
}

/** { state: "valid" | "expiring" | "expired" | "unknown", days } — expiring means within 90 days. */
export function status(rec, now = new Date(), warnDays = 90) {
  const e = rec.fields?.expiry || rec.expiry;
  if (!e) return { state: "unknown", days: null };
  const end = Date.parse(`${e}T23:59:59Z`);
  const days = Math.floor((end - now.getTime()) / 86400e3);
  return { state: days < 0 ? "expired" : days <= warnDays ? "expiring" : "valid", days };
}

/** What the encrypted vault index carries, so the list can show expiry without opening the document. */
export const summary = (rec) => ({ kind: rec.kind, issuer: rec.fields.issuer || "", region: rec.fields.region || "", expiry: rec.fields.expiry || "" });

/** How sure HumID is of the details, in words, strongest source first. */
// The phone checks the chip's files against the chip's own list of hashes, but not
// the issuing country's signature on that list (only the server does that, when an
// ID is used to recover). A cloned or made-up chip supplies both the files and the
// list, so a match proves only that the copy is self-consistent: it gets the amber
// "issuer not verified on this phone" tier, never the top one (CREDS-04). The top
// "chip" tier needs a fresh issuer check from the caller (opts.chip: the SOD
// signature verified and its signer chained to a CSCA the phone trusts), which the
// app can't make yet: it has no CSCA list.
//
// The stored `verified` flags are never trusted on their own: a record is just
// JSON, so anyone who can hand the app a record could set them (precert
// finding APP-05). The chip check is re-run here from the chip's own files
// every time, and the fields the record says came from the chip must still
// match the chip's DG1. A mobile ID's labels need a fresh check from the
// caller (opts.mdoc, from recheckMdoc in the app); without one they say so.
export function provenance(rec, { mdoc, chip } = {}) {
  const v = rec.verified || {};
  const typed = Object.values(rec.source || {}).includes("typed");
  if (v.chip) {
    const c = recheckChip(rec);
    if (!c.ok) return { level: "chip-mismatch", text: `Not verified: ${c.reason}` };
    if (chip && chip.ok !== true) return { level: "chip-mismatch", text: `Not verified: ${chip.reason || "the issuing country's signature doesn't check out"}` };
    if (typed || c.edited) return { level: "chip-edited", text: "Read from the chip, then changed by hand" };
    if (chip?.ok === true && chip.chain === "trusted") return { level: "chip", text: "Read from the chip; signed by the issuing country, checked against its signing certificate on this phone" };
    return { level: "chip-issuer-unverified", text: "Read from the chip, issuer not verified on this phone: its files match the chip's own list of hashes, but the issuing country's signature on that list isn't checked here" };
  }
  if (v.mdoc) {
    if (mdoc && !mdoc.ok) return { level: "mdoc-mismatch", text: `Not verified: ${mdoc.reason || "the issuer's signature no longer checks out"}` };
    if (mdoc && typed) return { level: "mdoc-edited", text: "Shared from a mobile ID, then changed by hand" };
    if (!mdoc) return { level: "mdoc-unchecked", text: "Shared from the mobile ID; open it to re-check the issuer's signature" };
    if (mdoc.chain === "trusted" && v.mdoc.deviceOk) return { level: "mdoc", text: "Shared from the mobile ID; signed by its issuer, checked against the issuer's root, and the wallet proved it holds the original" };
    return { level: "mdoc-unchecked", text: "Shared from the mobile ID; the issuer's signature matches, but its root isn't in HumID's trusted list yet" };
  }
  if (v.chip) return { level: "chip-unchecked", text: "Not verified: read from the chip, but its files weren't checked" };
  if (v.chipFailed && !v.barcode && !v.mrz) return { level: "chip-failed", text: "Not verified: the chip couldn't be verified, so its data was not used" };
  if (v.barcode) return { level: "barcode", text: `Read from the barcode (AAMVA v${v.barcode.version})` };
  if (v.chipFailed) return { level: "mrz-unverified", text: "Not verified: chip couldn't be verified. Details are from the printed document only" };
  if (v.mrz?.valid && v.mrz.consensus) return { level: "mrz", text: "Read from the machine-readable lines; every check digit agrees" };
  if (v.mrz?.valid) return { level: "mrz-single", text: "Read from the machine-readable lines; check digits agree" };
  if (v.mrz) return { level: "mrz-partial", text: "Partly read from the machine-readable lines; check the details" };
  return { level: "typed", text: "Entered by hand" };
}

export function encodeRecord(rec) {
  return new TextEncoder().encode(JSON.stringify({ ...rec, schema: SCHEMA }));
}
export function decodeRecord(bytes) {
  const j = JSON.parse(typeof bytes === "string" ? bytes : new TextDecoder().decode(bytes));
  if (j?.schema !== SCHEMA) throw new Error("not a HumID ID record");
  return { fields: {}, source: {}, verified: {}, images: {}, raw: {}, edited: [], ...j };
}

/* ---------------- re-checking what a record claims ---------------- */

const unb64 = (s) => { const t = atob(String(s)); const o = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) o[i] = t.charCodeAt(i); return o; };
// Record field ← MRZ field, for what applyChip copies from DG1.
const CHIP_FIELDS = { surname: "surname", given: "given", number: "number", issuer: "issuer", nationality: "nationality", birth: "birth", expiry: "expiry", sex: "sex", optional: "optional" };

/**
 * Re-run the chip check from the files kept in the record, never from its flags:
 * the data groups must match the SOD's hash list, and every field the record says
 * came from the chip must equal what DG1 holds. Returns { ok, reason? }.
 * Still a hash check, not the issuing country's signature (that's passive
 * authentication, on the server: @humid/creds/server).
 */
export function recheckChip(rec) {
  const raw = rec?.raw?.chip;
  if (!raw?.dg1 || !raw?.sod) return { ok: false, reason: "the chip's files aren't in this record, so it can't be re-checked" };
  let files;
  try { files = Object.fromEntries(Object.entries(raw).map(([k, x]) => [k, unb64(x)])); }
  catch { return { ok: false, reason: "the chip's files in this record can't be read" }; }
  const groups = { 1: files.dg1, ...(files.dg2 ? { 2: files.dg2 } : {}), ...(files.dg15 ? { 15: files.dg15 } : {}) };
  if (!chipIntegrityOk(safeCheckIntegrity(files.sod, groups))) return { ok: false, reason: "the chip's files don't match its own list of hashes" };
  let mrz;
  try { mrz = readDg1(files.dg1).mrz; } catch { return { ok: false, reason: "the chip's personal data can't be read" }; }
  // Every field the chip holds is compared, whatever source the record claims for
  // it: relabelling a changed field as "mrz" mustn't keep the chip label. Only a
  // correction marked as typed by hand may differ (and the label then says "edited").
  let edited = false;
  for (const [field, m] of Object.entries(CHIP_FIELDS)) {
    const fromChip = mrz?.[m] ?? "";
    if (fromChip === "") continue;
    if (fromChip === (rec.fields?.[field] ?? "")) continue;
    if (rec.source?.[field] === "typed") { edited = true; continue; }
    return { ok: false, reason: "details on this card don't match the chip" };
  }
  // The photo: a JPEG on the chip is kept byte for byte, so it must match. A JPEG
  // 2000 photo is converted when read, so the app re-makes it from DG2 on open
  // (portraitFromChip) instead of showing the stored copy.
  let portrait = null;
  if (files.dg2 && rec.images?.portrait) {
    let img = null;
    try { img = readDg2(files.dg2); } catch { return { ok: false, reason: "the chip's photo can't be read" }; }
    if (img.type === "image/jpeg") {
      let stored = null;
      try { stored = unb64(rec.images.portrait.data); } catch { /* compared below */ }
      if (!stored || stored.length !== img.bytes.length || stored.some((x, i) => x !== img.bytes[i])) return { ok: false, reason: "the photo doesn't match the chip" };
      portrait = "matches";
    } else portrait = "rederive";
  }
  return { ok: true, edited, portrait };
}
