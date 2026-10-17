// Machine-readable zone (ICAO 9303 part 3–5): the identity lines printed on
// the data page and stored in the chip as DG1. TD3 = passports (2 × 44),
// TD2 = some ID cards (2 × 36), TD1 = ID cards (3 × 30).

const WEIGHTS = [7, 3, 1];
const value = (c) => (c === "<" ? 0 : /[0-9]/.test(c) ? c.charCodeAt(0) - 48 : /[A-Z]/.test(c) ? c.charCodeAt(0) - 55 : NaN);

export function checkDigit(s) {
  let sum = 0;
  for (let i = 0; i < s.length; i++) {
    const v = value(s[i]);
    if (Number.isNaN(v)) return -1;
    sum += v * WEIGHTS[i % 3];
  }
  return sum % 10;
}

export class MrzError extends Error {
  constructor(message) { super(message); this.code = "bad_mrz"; }
}

const digitOk = (field, digit) => digit === "<" ? /^<*$/.test(field) : checkDigit(field) === Number(digit);
const clean = (s) => s.replace(/<+$/g, "").replace(/</g, " ").trim();

function names(field) {
  const [surname, given = ""] = field.split("<<");
  return { surname: clean(surname), given: clean(given.replace(/<+/g, "<")) };
}

/** Parse an MRZ (lines joined or not). Throws MrzError on a bad check digit. */
export function parseMrz(text) {
  const raw = String(text).toUpperCase().replace(/[\r\n\s]/g, "");
  let f;
  if (raw.length === 88) {
    const [a, b] = [raw.slice(0, 44), raw.slice(44)];
    f = {
      format: "TD3", documentCode: clean(a.slice(0, 2)), issuer: a.slice(2, 5), ...names(a.slice(5, 44)),
      number: b.slice(0, 9), numberCheck: b[9], nationality: b.slice(10, 13), birth: b.slice(13, 19), birthCheck: b[19],
      sex: b[20], expiry: b.slice(21, 27), expiryCheck: b[27],
      personal: b.slice(28, 42), personalCheck: b[42],
      composite: b.slice(0, 10) + b.slice(13, 20) + b.slice(21, 43), compositeCheck: b[43],
    };
  } else if (raw.length === 72) {
    const [a, b] = [raw.slice(0, 36), raw.slice(36)];
    f = {
      format: "TD2", documentCode: clean(a.slice(0, 2)), issuer: a.slice(2, 5), ...names(a.slice(5, 36)),
      number: b.slice(0, 9), numberCheck: b[9], nationality: b.slice(10, 13), birth: b.slice(13, 19), birthCheck: b[19],
      sex: b[20], expiry: b.slice(21, 27), expiryCheck: b[27],
      composite: b.slice(0, 10) + b.slice(13, 20) + b.slice(21, 35), compositeCheck: b[35],
    };
  } else if (raw.length === 90) {
    const [a, b, c] = [raw.slice(0, 30), raw.slice(30, 60), raw.slice(60)];
    f = {
      format: "TD1", documentCode: clean(a.slice(0, 2)), issuer: a.slice(2, 5), number: a.slice(5, 14), numberCheck: a[14],
      birth: b.slice(0, 6), birthCheck: b[6], sex: b[7], expiry: b.slice(8, 14), expiryCheck: b[14], nationality: b.slice(15, 18),
      composite: a.slice(5, 30) + b.slice(0, 7) + b.slice(8, 15) + b.slice(18, 29), compositeCheck: b[29],
      ...names(c),
    };
  } else {
    throw new MrzError("The chip's identity data isn't a passport or ID card MRZ.");
  }
  // Long document numbers (TD1) continue in the optional field; the check digit is then "<". Accept either form.
  if (!digitOk(f.number, f.numberCheck) && f.numberCheck !== "<") throw new MrzError("The document number fails its check digit.");
  if (!digitOk(f.birth, f.birthCheck)) throw new MrzError("The date of birth fails its check digit.");
  if (!digitOk(f.expiry, f.expiryCheck)) throw new MrzError("The expiry date fails its check digit.");
  if (f.personal != null && !digitOk(f.personal, f.personalCheck)) throw new MrzError("The personal number fails its check digit.");
  if (!/^[0-9]$/.test(f.compositeCheck) || checkDigit(f.composite) !== Number(f.compositeCheck)) throw new MrzError("The MRZ fails its overall check digit.");
  delete f.composite; delete f.compositeCheck; delete f.personalCheck;
  if (!/^[MFX<]$/.test(f.sex)) throw new MrzError("The sex field is not M, F or X.");
  f.number = clean(f.number);
  f.issuer = clean(f.issuer);
  f.nationality = clean(f.nationality);
  return f;
}

/** YYMMDD expiry → Date at the end of that day (UTC). Two-digit years are 20xx. */
export function expiryDate(yymmdd) {
  const y = 2000 + Number(yymmdd.slice(0, 2)), m = Number(yymmdd.slice(2, 4)) - 1, d = Number(yymmdd.slice(4, 6));
  return new Date(Date.UTC(y, m, d, 23, 59, 59));
}

/**
 * The fields that survive a renewal: issuer, nationality, names, birth date, sex.
 * The document number and expiry change with every new passport, so they're left out.
 */
export function stableIdentity(f) {
  return ["HUMID-ANCHOR-v1", f.issuer, f.nationality, f.surname, f.given, f.birth, f.sex].join("|");
}
