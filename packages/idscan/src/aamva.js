// North American driver's licenses and state ID cards: the PDF417 barcode on
// the back holds the card's details as AAMVA DL/ID text (versions 1 to 10).
// Real cards bend the standard (wrong offsets, CR LF line ends, missing
// header pieces), so this reads by element id rather than trusting the
// header's offsets.
import { IIN, regionCountry } from "./places.js";

/** Does this barcode text look like an AAMVA card? */
export const isAamva = (text) => /(ANSI|AAMVA) ?\d{8}/.test(String(text || ""));

const SEX = { 1: "M", 2: "F", 9: "X", M: "M", F: "F", X: "X" };
const EYES = { BLK: "Black", BLU: "Blue", BRO: "Brown", GRY: "Gray", GRN: "Green", HAZ: "Hazel", MAR: "Maroon", PNK: "Pink", DIC: "Dichromatic", UNK: "Unknown" };
const HAIR = { BAL: "Bald", BLK: "Black", BLN: "Blond", BRO: "Brown", GRY: "Gray", RED: "Red/Auburn", SDY: "Sandy", WHI: "White", UNK: "Unknown" };

function validDate(y, m, d) {
  if (y < 1900 || y > 2099 || m < 1 || m > 12 || d < 1 || d > 31) return null;
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCDate() === d ? `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}` : null;
}

/** AAMVA dates: MMDDCCYY in the US, CCYYMMDD in Canada. Whichever reads as a real date wins. */
export function aamvaDate(s, country = "USA") {
  const t = String(s || "").replace(/\D/g, "");
  if (t.length !== 8) return null;
  const us = validDate(+t.slice(4, 8), +t.slice(0, 2), +t.slice(2, 4));
  const ca = validDate(+t.slice(0, 4), +t.slice(4, 6), +t.slice(6, 8));
  if (us && ca) return country === "CAN" ? ca : us;
  return us || ca;
}

function height(v) {
  const s = String(v || "").trim().toUpperCase();
  let m;
  if ((m = /^(\d{2,3})\s*IN$/.exec(s))) { const n = +m[1]; return { inches: n, text: `${Math.floor(n / 12)}′${n % 12}″` }; }
  if ((m = /^(\d{2,3})\s*CM$/.exec(s))) return { cm: +m[1], text: `${+m[1]} cm` };
  if ((m = /^(\d)['\- ]?(\d{2})$/.exec(s))) { const n = +m[1] * 12 + +m[2]; return { inches: n, text: `${m[1]}′${+m[2]}″` }; }
  return s ? { text: s } : null;
}

function postal(v, country) {
  const s = String(v || "").replace(/\s+/g, "").toUpperCase();
  if (!s) return "";
  if (/^[A-Z]\d[A-Z]\d[A-Z]\d$/.test(s)) return `${s.slice(0, 3)} ${s.slice(3)}`;
  const d = s.replace(/[^0-9]/g, "");
  if (country !== "CAN" && d.length >= 9) return d.slice(5, 9) === "0000" ? d.slice(0, 5) : `${d.slice(0, 5)}-${d.slice(5, 9)}`;
  if (country !== "CAN" && d.length >= 5) return d.slice(0, 5);
  return s;
}

/** Split "LAST,FIRST,MIDDLE" (version 1) or "FIRST MIDDLE" / "FIRST,MIDDLE" (versions 2-3). */
const parts = (v, sep) => String(v || "").split(sep).map((x) => x.trim()).filter(Boolean);

/**
 * Parse the text of a license or ID card barcode. Returns
 * { kind, issuer: { country, region, iin }, version, jurisdictionVersion, elements, fields } or null.
 * `fields` uses the same names as an MRZ parse where they overlap.
 */
export function parseAamva(text) {
  const raw = String(text || "");
  const head = /(ANSI|AAMVA) ?(\d{6})(\d{2})/.exec(raw);
  if (!head) return null;
  const iin = head[2];
  const version = +head[3];
  let pos = head.index + head[0].length;
  let jurisdictionVersion = null;
  if (version >= 2 && /^\d{2}/.test(raw.slice(pos))) { jurisdictionVersion = +raw.slice(pos, pos + 2); pos += 2; }
  const entries = /^\d{2}/.test(raw.slice(pos)) ? +raw.slice(pos, pos + 2) : 1;
  pos += 2;
  const designators = [];
  const re = /(DL|ID|Z[A-Z0-9])(\d{4})(\d{4})/y;
  re.lastIndex = pos;
  for (let i = 0; i < Math.max(entries, 1); i++) {
    const m = re.exec(raw);
    if (!m) break;
    designators.push({ type: m[1], offset: +m[2], length: +m[3] });
  }
  const body = raw.slice(re.lastIndex || pos);

  // Elements: three capital letters, then the value up to the next line break. The first
  // element of each subfile follows its two-letter type directly ("DLDAQ…").
  const elements = {};
  const lines = body.split(/[\r\n]+/);
  let subfile = null;
  for (let line of lines) {
    const st = /^(DL|ID|Z[A-Z0-9])(?=[A-Z]{3})/.exec(line);
    if (st && (designators.some((d) => d.type === st[1]) || ["DL", "ID"].includes(st[1]))) { subfile = st[1]; line = line.slice(2); }
    const m = /^([A-Z]{3})(.*)$/.exec(line.replace(/\x1e|\x1c|\x1d/g, ""));
    if (!m) continue;
    // Jurisdiction-specific Z subfiles are kept apart so they can't overwrite standard fields.
    const key = subfile && subfile.startsWith("Z") ? `${subfile}.${m[1]}` : m[1];
    if (!(key in elements)) elements[key] = m[2].trim();
  }
  const kind = designators.some((d) => d.type === "DL") || /^DL/.test(body) ? "driver_license" : designators.some((d) => d.type === "ID") ? "id_card" : "driver_license";
  const e = elements;
  const region = (e.DAJ || IIN[iin] || "").toUpperCase();
  const country = (e.DCG || regionCountry(region) || "USA").toUpperCase();

  // Names moved around between versions.
  let surname = e.DCS || e.DAB || "", given = e.DAC || "", middle = e.DAD || "";
  if (!surname && e.DAA) { const p = parts(e.DAA, /,|\$/); surname = p[0] || ""; given = given || p[1] || ""; middle = middle || p.slice(2).join(" "); }
  if (!given && e.DCT) { const p = parts(e.DCT, /,|\s+/); given = p[0] || ""; middle = middle || p.slice(1).join(" "); }
  const none = (s) => (/^(NONE|UNAVL|UNAVAILABLE|N\/A)$/i.test(s || "") ? "" : s || "");

  const date = (k) => aamvaDate(e[k], country);
  const fields = {
    kind,
    issuer: country,
    region,
    surname: none(surname),
    given: [none(given), none(middle)].filter(Boolean).join(" "),
    firstName: none(given),
    middleName: none(middle),
    suffix: none(e.DCU || e.DAE || ""),
    number: (e.DAQ || "").replace(/\s+/g, ""),
    birth: date("DBB"),
    issued: date("DBD"),
    expiry: date("DBA"),
    sex: SEX[(e.DBC || "").trim()] || "",
    address: (e.DAG || e.DAI) ? {
      street: e.DAG || "", street2: e.DAH || "", city: e.DAI || "", region: (e.DAJ || "").toUpperCase(),
      postalCode: postal(e.DAK, country), country,
    } : null,
    vehicleClass: none(e.DCA || ""),
    restrictions: none(e.DCB || ""),
    endorsements: none(e.DCD || ""),
    discriminator: e.DCF || "",
    inventory: e.DCK || "",
    height: height(e.DAU),
    weight: e.DAW ? `${+e.DAW} lb` : e.DAX ? `${+e.DAX} kg` : "",
    eyes: EYES[(e.DAY || "").toUpperCase()] || e.DAY || "",
    hair: HAIR[(e.DAZ || "").toUpperCase()] || e.DAZ || "",
    placeOfBirth: e.DCI || "",
    realId: e.DDA ? e.DDA.toUpperCase() === "F" : null,
    organDonor: e.DDK === "1" ? true : null,
    veteran: e.DDL === "1" ? true : null,
    under18Until: date("DDH"), under19Until: date("DDI"), under21Until: date("DDJ"),
    truncated: ["DDE", "DDF", "DDG"].some((k) => (e[k] || "").toUpperCase() === "T"),
  };
  return { kind, issuer: { country, region, iin }, version, jurisdictionVersion, designators, elements, fields };
}
