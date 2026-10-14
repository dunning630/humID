// One record for any identity document, whatever it was read from: the photo
// page's MRZ, a license barcode, a chip, or typed by hand. This is what HumID
// seals into the vault (media type application/vnd.humid.id+json), so it's
// plain JSON with a schema tag, and every field says where it came from.
import { countryName, regionName } from "./places.js";

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

/** Set fields, remembering where each came from. A chip outranks a barcode, which outranks OCR. */
const RANK = { typed: 4, chip: 3, barcode: 2, mrz: 1, photo: 0 };
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
 */
export function applyChip(rec, chip, { mrz, integrity, b64 }) {
  if (mrz) {
    if (rec.kind === "other" || !rec.kind) rec.kind = mrz.kind;
    put(rec, "chip", {
      surname: mrz.surname, given: mrz.given, number: mrz.number, issuer: mrz.issuer, nationality: mrz.nationality,
      birth: mrz.birth, expiry: mrz.expiry, sex: mrz.sex, optional: mrz.optional,
    });
    rec.raw.mrz = mrz.lines;
  }
  rec.verified.chip = { integrity: integrity?.ok ?? null, algorithm: integrity?.algorithm || null, groups: integrity?.groups || {}, access: chip.access || null, readAt: nowIso() };
  rec.raw.chip = Object.fromEntries(["dg1", "dg2", "dg15", "sod", "com"].filter((k) => chip[k]).map((k) => [k, b64(chip[k])]));
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
export function status(rec, now = new Date()) {
  const e = rec.fields?.expiry || rec.expiry;
  if (!e) return { state: "unknown", days: null };
  const end = Date.parse(`${e}T23:59:59Z`);
  const days = Math.floor((end - now.getTime()) / 86400e3);
  return { state: days < 0 ? "expired" : days <= 90 ? "expiring" : "valid", days };
}

/** What the encrypted vault index carries, so the list can show expiry without opening the document. */
export const summary = (rec) => ({ kind: rec.kind, issuer: rec.fields.issuer || "", region: rec.fields.region || "", expiry: rec.fields.expiry || "" });

/** How sure HumID is of the details, in words, strongest source first. */
export function provenance(rec) {
  const v = rec.verified || {};
  if (v.chip?.integrity) return { level: "chip", text: "Read from the chip; matches the issuing country's signed hashes" };
  if (v.chip) return { level: "chip-unchecked", text: "Read from the chip" };
  if (v.barcode) return { level: "barcode", text: `Read from the barcode (AAMVA v${v.barcode.version})` };
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
