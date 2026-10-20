// Mobile IDs (ISO/IEC 18013-5) into the record's fields: a US state mobile
// driver's license or ID (mDL doctype, plus AAMVA's US extensions), an EU
// digital identity PID, or an ISO 23220 photo ID. The values arrive already
// verified by @humid/mdoc; this only maps names. Dates arrive as tagged values
// ({ tag: 1004, value: "YYYY-MM-DD" }) or strings.

import { ALPHA2 } from "./places.js";

export const MDOC_TYPES = {
  mdl: "org.iso.18013.5.1.mDL",
  pid: "eu.europa.ec.eudi.pid.1",
  photoid: "org.iso.23220.photoid.1",
};
const MDL_NS = "org.iso.18013.5.1", AAMVA_NS = "org.iso.18013.5.1.aamva", PHOTOID_NS = "org.iso.23220.1";

const txt = (v) => (v == null ? "" : typeof v === "object" && "tag" in v && "value" in v ? String(v.value) : typeof v === "string" || typeof v === "number" ? String(v) : "");
const date = (v) => { const s = txt(v); return /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : ""; };
/** ISO 3166-1 alpha-2 → the alpha-3 codes the rest of HumID uses. Unknown codes are kept as given. */
export const alpha3 = (c) => { const s = txt(c).toUpperCase(); return s.length === 2 ? ALPHA2[s] || s : s; };
const SEX = { 1: "M", 2: "F", 9: "X", 0: "" };
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "");
const list = (v) => (Array.isArray(v) ? v : []);
const get = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);

/** Is this document type one HumID knows how to show? */
export const isMdocType = (t) => Object.values(MDOC_TYPES).includes(t);

/** values: { namespace: { element: value } } from @humid/mdoc → { kind, fields, address, portrait }. */
export function mdocFields(docType, values) {
  const m = values[MDL_NS] || values[MDOC_TYPES.pid] || {};
  const a = values[AAMVA_NS] || {};
  const p = values[PHOTOID_NS] || {};
  const pick = (...keys) => { for (const k of keys) { const v = m[k] ?? p[k]; if (v instanceof Uint8Array ? v.length : v != null && txt(v) !== "") return v; } return null; };

  const country = alpha3(pick("issuing_country"));
  const us = country === "USA";
  const juris = txt(m.issuing_jurisdiction).toUpperCase();
  const region = /^[A-Z]{2}-([A-Z0-9]{1,3})$/.test(juris) ? juris.slice(3) : "";

  // Driving privileges: AAMVA's US detail when present, else the international categories.
  const dom = list(a.domestic_driving_privileges);
  const codes = (key, inner) => [...new Set(dom.flatMap((d) => list(get(d, key)).map((x) => txt(get(x, inner)))).filter(Boolean))].join(",");
  const domClasses = [...new Set(dom.map((d) => txt(get(get(d, "domestic_vehicle_class"), "domestic_vehicle_class_code"))).filter(Boolean))].join(",");
  const intl = [...new Set(list(m.driving_privileges).map((d) => txt(get(d, "vehicle_category_code"))).filter(Boolean))].join(",");
  const drives = !!(domClasses || intl);
  const kind = docType === MDOC_TYPES.mdl && drives ? "driver_license" : "id_card";

  const cm = Number(txt(pick("height")));
  const kg = Number(txt(pick("weight")));
  const inches = cm ? Math.round(cm / 2.54) : 0;
  const height = cm ? (us ? `${Math.floor(inches / 12)}′${inches % 12}″ (${cm} cm)` : `${cm} cm`) : "";
  const weight = kg ? (us ? `${Math.round(kg * 2.20462)} lb` : `${kg} kg`) : "";
  const realId = a.DHS_compliance == null ? null : txt(a.DHS_compliance).toUpperCase() === "F";

  const street = txt(pick("resident_address", "resident_address_unicode", "resident_street"));
  const city = txt(pick("resident_city", "resident_city_unicode"));
  const address = street || city ? {
    street, street2: "", city, region: txt(pick("resident_state")).toUpperCase(),
    postalCode: txt(pick("resident_postal_code")), country: alpha3(pick("resident_country")) || country,
  } : null;

  const portrait = pick("portrait");
  return {
    kind,
    address,
    portrait: portrait instanceof Uint8Array ? portrait : null,
    fields: {
      surname: txt(pick("family_name", "family_name_unicode")),
      given: txt(pick("given_name", "given_name_unicode")),
      suffix: txt(a.name_suffix),
      birth: date(pick("birth_date")),
      sex: SEX[txt(pick("sex"))] ?? "",
      nationality: alpha3(pick("nationality")),
      placeOfBirth: txt(pick("birth_place", "place_of_birth", "birthplace")),
      number: txt(pick("document_number")),
      issuer: country,
      region,
      issued: date(pick("issue_date", "issuance_date")),
      expiry: date(pick("expiry_date")),
      vehicleClass: domClasses || intl,
      restrictions: codes("domestic_vehicle_restrictions", "domestic_vehicle_restriction_code"),
      endorsements: codes("domestic_vehicle_endorsements", "domestic_vehicle_endorsement_code"),
      realId,
      height,
      weight,
      eyes: cap(txt(pick("eye_colour")).replace(/_/g, " ")),
      hair: cap(txt(pick("hair_colour")).replace(/_/g, " ")),
      organDonor: txt(a.organ_donor) === "1" ? true : null,
      veteran: txt(a.veteran) === "1" ? true : null,
    },
  };
}

/** The picture type from its first bytes: JPEG or JPEG 2000. */
export const imageType = (b) => (b?.[0] === 0xff && b[1] === 0xd8 ? "image/jpeg" : b?.[4] === 0x6a && b[5] === 0x50 ? "image/jp2" : b?.[0] === 0xff && b[1] === 0x4f ? "image/jp2" : "application/octet-stream");
