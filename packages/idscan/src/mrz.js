// Machine-readable zones (ICAO 9303 parts 4-7): the two or three lines of
// OCR-B text at the bottom of a passport's photo page, or on the back of an ID
// card. Built to read what a phone camera and OCR actually return: lines with
// a character too many or too few, O for 0, K for <. The check digits decide
// what each character really is, so a field is only trusted when its check
// digit agrees.
//
//   TD3  passports                      2 × 44
//   TD2  some ID cards, older visas     2 × 36
//   TD1  ID cards, residence permits    3 × 30
//   MRV  visas (A: 2 × 44, B: 2 × 36), no composite check digit

const WEIGHTS = [7, 3, 1];
const charValue = (c) => (c === "<" ? 0 : c >= "0" && c <= "9" ? c.charCodeAt(0) - 48 : c >= "A" && c <= "Z" ? c.charCodeAt(0) - 55 : NaN);

/** ICAO check digit of a field, or -1 if it holds a character the MRZ can't. */
export function checkDigit(s) {
  let sum = 0;
  for (let i = 0; i < s.length; i++) {
    const v = charValue(s[i]);
    if (Number.isNaN(v)) return -1;
    sum += v * WEIGHTS[i % 3];
  }
  return sum % 10;
}

// What OCR mixes up in OCR-B. A field that must be digits maps letters to the
// digit they look like; a field that must be letters does the reverse.
const TO_DIGIT = { O: "0", Q: "0", D: "0", U: "0", C: "0", I: "1", L: "1", J: "1", Z: "2", S: "5", G: "6", T: "7", B: "8", A: "4", "<": "0" };
const TO_ALPHA = { 0: "O", 1: "I", 2: "Z", 4: "A", 5: "S", 6: "G", 7: "T", 8: "B" };
// Pairs a document number can legitimately contain either way: the check digit picks.
const AMBIGUOUS = { O: "0", 0: "O", I: "1", 1: "I", B: "8", 8: "B", S: "5", 5: "S", Z: "2", 2: "Z", G: "6", 6: "G", D: "0", Q: "0" };

const digits = (s) => [...s].map((c) => TO_DIGIT[c] ?? c).join("");
const alpha = (s) => [...s].map((c) => TO_ALPHA[c] ?? c).join("");
const alphaFiller = (s) => [...s].map((c) => (c === "<" ? c : TO_ALPHA[c] ?? c)).join("");

// An MRZ line is 30, 36 or 44 characters. OCR output and typed text are
// attacker-influenced, so nothing below does more than linear work, and
// anything far longer than a line is refused before it is looked at.
const MAX_RAW_LINE = 256; // an OCR line longer than this is not an MRZ line
const MAX_RAW_TEXT = 4096; // typed or chip MRZ: 90 characters plus whitespace
const MAX_OCR_LINES = 500;

const isLetter = (c) => c >= "A" && c <= "Z";
const FILLER_LOOKALIKES = "KCELXZ";

/**
 * Names field: letters and fillers; anything after the last real name is filler.
 * Linear time. Equivalent to the former /^(.*?[A-Z]{2,})(?:<+[KCELXZ]?)*<*$/:
 * the names end at the first point where two letters are followed by nothing
 * but fillers, where a filler look-alike (K C E L X Z) may sit after a "<" but
 * never next to another letter.
 */
export function nameField(s) {
  const t = alphaFiller(s).replace(/[^A-Z<]/g, "<");
  const n = t.length;
  // e0: start of the longest suffix made only of "<" and look-alike letters, no two letters adjacent.
  let e0 = n;
  while (e0 > 0) {
    const c = t[e0 - 1];
    if (c === "<") e0--;
    else if (FILLER_LOOKALIKES.includes(c) && !(e0 < n && isLetter(t[e0]))) e0--;
    else break;
  }
  // Shortest names part that ends in two letters and is followed by "<" (or nothing).
  for (let e = Math.max(e0, 2); e < n; e++) {
    if (t[e] === "<" && isLetter(t[e - 1]) && isLetter(t[e - 2])) return t.slice(0, e) + "<".repeat(n - e);
  }
  return t;
}

/** Try the ambiguous characters both ways until the check digit agrees (fewest changes first). */
// At most one character per field, and only when exactly one such change makes
// the check digit agree: if two different guesses both pass, HumID can't know
// which is right, so the field stays unconfirmed (another frame, or the person,
// settles it).
const MAX_REPAIRS = 1;
function repair(field, check) {
  const want = Number(digits(check));
  if (checkDigit(field) === want) return { value: field, ok: true, changes: 0 };
  const spots = [...field].map((c, i) => (AMBIGUOUS[c] ? i : -1)).filter((i) => i >= 0);
  const found = [];
  for (const combo of choose(spots, MAX_REPAIRS)) {
    const chars = [...field];
    for (const p of combo) chars[p] = AMBIGUOUS[chars[p]];
    const v = chars.join("");
    if (checkDigit(v) === want) found.push(v);
  }
  return found.length === 1 ? { value: found[0], ok: true, changes: MAX_REPAIRS } : { value: field, ok: false, changes: 0 };
}
function* choose(arr, k, start = 0, acc = []) {
  if (acc.length === k) { yield acc; return; }
  for (let i = start; i < arr.length; i++) yield* choose(arr, k, i + 1, [...acc, arr[i]]);
}

const stripTrailing = (s, ch) => { let e = s.length; while (e > 0 && s[e - 1] === ch) e--; return s.slice(0, e); };
const clean = (s) => stripTrailing(s, "<").replace(/</g, " ").replace(/\s+/g, " ").trim();
function splitNames(field) {
  const i = field.indexOf("<<");
  const [sur, giv] = i < 0 ? [field, ""] : [field.slice(0, i), field.slice(i + 2)];
  return { surname: clean(sur), given: clean(giv) };
}

/** YYMMDD → YYYY-MM-DD. Birth dates are never in the future; expiry dates are 20xx unless that's absurdly far. */
export function mrzDate(yymmdd, kind, now = new Date()) {
  if (!/^\d{6}$/.test(yymmdd || "")) return null;
  const yy = Number(yymmdd.slice(0, 2)), mm = Number(yymmdd.slice(2, 4)), dd = Number(yymmdd.slice(4, 6));
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
  const cur = now.getUTCFullYear();
  let y = 2000 + yy;
  if (kind === "birth" && y > cur) y -= 100;
  if (kind === "expiry" && y > cur + 50) y -= 100;
  const d = new Date(Date.UTC(y, mm - 1, dd));
  if (d.getUTCDate() !== dd) return null;
  return `${y}-${String(mm).padStart(2, "0")}-${String(dd).padStart(2, "0")}`;
}

export function kindOfCode(code) {
  const c = (code || "").replace(/</g, "");
  if (c.startsWith("P")) return "passport";
  if (c.startsWith("V")) return "visa";
  if (/^[IAC]R/.test(c) || c === "RP") return "residence_permit";
  if (/^[IAC]/.test(c)) return "id_card";
  return "other";
}

const LAYOUTS = { TD3: [44, 2], TD2: [36, 2], TD1: [30, 3] };

/**
 * Parse MRZ lines that are already the right length. Repairs OCR confusions
 * field by field and reports which check digits agree.
 */
export function parseMrzLines(lines, { now = new Date() } = {}) {
  const L = lines.map((l) => String(l).toUpperCase());
  const len = L[0]?.length;
  const format = L.length === 3 && len === 30 ? "TD1" : L.length === 2 && len === 44 ? "TD3" : L.length === 2 && len === 36 ? "TD2" : null;
  if (!format || L.some((l) => l.length !== len)) return null;
  const code = alphaFiller(L[0].slice(0, 2));
  const visa = code[0] === "V";
  const f = { format: visa ? (format === "TD3" ? "MRV-A" : "MRV-B") : format, documentCode: stripTrailing(code, "<"), checks: {}, lines: L };
  const cd = (c) => (c === "<" ? "<" : digits(c));
  let compositeInput = null, composite = null;

  if (format === "TD1") {
    const [a, b, c] = L;
    f.issuer = alphaFiller(a.slice(2, 5));
    const chars = [...a];
    // Where the document number sits: 6-14, or (long numbers) 6-14 and on into the optional
    // data, with its check digit at the end of that run and < in the usual check slot.
    let pos = [5, 6, 7, 8, 9, 10, 11, 12, 13], checkAt = 14;
    if (a[14] === "<" && /[0-9A-Z]/.test(a[15] || "")) {
      let end = 15;
      while (end < 30 && a[end] !== "<") end++;
      pos = [...pos, ...Array.from({ length: end - 16 }, (_, i) => 15 + i)];
      checkAt = end - 1;
    }
    const num = repair(pos.map((i) => a[i]).join(""), a[checkAt]);
    pos.forEach((p, i) => { chars[p] = num.value[i]; });
    chars[checkAt] = cd(a[checkAt]);
    f.number = num.value.replace(/</g, "");
    f.checks.number = num.ok;
    f.repairs = num.changes;
    const birth = digits(b.slice(0, 6)), expiry = digits(b.slice(8, 14));
    f.checks.birth = checkDigit(birth) === Number(cd(b[6]));
    f.checks.expiry = checkDigit(expiry) === Number(cd(b[14]));
    f.sex = alphaFiller(b[7]);
    f.nationality = alphaFiller(b.slice(15, 18));
    const optional1 = checkAt === 14 ? a.slice(15, 30) : a.slice(checkAt + 1, 30);
    f.optional = clean([optional1, b.slice(18, 29)].join("<"));
    Object.assign(f, splitNames(nameField(c)));
    f.birthRaw = birth; f.expiryRaw = expiry;
    compositeInput = chars.slice(5, 30).join("") + birth + cd(b[6]) + expiry + cd(b[14]) + b.slice(18, 29);
    composite = b[29];
  } else {
    const [a, b] = L;
    const n = format === "TD3" ? 44 : 36;
    f.issuer = alphaFiller(a.slice(2, 5));
    Object.assign(f, splitNames(nameField(a.slice(5, n))));
    const num = repair(b.slice(0, 9), b[9]);
    f.number = num.value.replace(/</g, "");
    f.checks.number = num.ok;
    f.repairs = num.changes;
    f.nationality = alphaFiller(b.slice(10, 13));
    const birth = digits(b.slice(13, 19)), expiry = digits(b.slice(21, 27));
    f.checks.birth = checkDigit(birth) === Number(cd(b[19]));
    f.checks.expiry = checkDigit(expiry) === Number(cd(b[27]));
    f.sex = alphaFiller(b[20]);
    f.birthRaw = birth; f.expiryRaw = expiry;
    const head = num.value + cd(b[9]) + birth + cd(b[19]) + expiry + cd(b[27]);
    if (visa) f.optional = clean(b.slice(28, n));
    else if (format === "TD3") {
      let optional = b.slice(28, 42);
      // An empty personal number may carry < or 0 as its check digit; OCR may make that a letter.
      const oc = /^<*$/.test(optional) && !/[0-9]/.test(b[42]) ? "<" : cd(b[42]);
      if (oc === "<") f.checks.optional = /^<*$/.test(optional);
      else { const r = repair(optional, oc); optional = r.value; f.checks.optional = r.ok; f.repairs += r.changes; }
      f.optional = clean(optional);
      compositeInput = head + optional + oc;
      composite = b[43];
    } else {
      f.optional = clean(b.slice(28, 35));
      compositeInput = head + b.slice(28, 35);
      composite = b[35];
    }
  }
  if (compositeInput != null) f.checks.composite = checkDigit(compositeInput) === Number(cd(composite));
  f.sex = f.sex === "M" || f.sex === "F" ? f.sex : "X";
  f.birth = mrzDate(f.birthRaw, "birth", now);
  f.expiry = mrzDate(f.expiryRaw, "expiry", now);
  f.issuer = f.issuer.replace(/</g, "");
  f.nationality = f.nationality.replace(/</g, "");
  f.kind = kindOfCode(f.documentCode);
  // Trusted only when every check digit agrees, and only a couple of characters had to be guessed.
  f.valid = Object.values(f.checks).every(Boolean) && !!f.birth && !!f.expiry && f.number.length > 0 && f.repairs <= 2 * MAX_REPAIRS;
  return f;
}

/** Strict parse of an MRZ as stored on a chip (DG1) or typed: one string, lines joined or not. */
export function parseMrz(text, opts) {
  if (text == null || String(text).length > MAX_RAW_TEXT) return null;
  const raw = String(text).toUpperCase().replace(/[\r\n\s]/g, "");
  const shape = raw.length === 88 ? [44, 2] : raw.length === 72 ? [36, 2] : raw.length === 90 ? [30, 3] : null;
  if (!shape) return null;
  const lines = Array.from({ length: shape[1] }, (_, i) => raw.slice(i * shape[0], (i + 1) * shape[0]));
  return parseMrzLines(lines, opts);
}

/* ---------------- finding an MRZ in OCR output ---------------- */

// OCR often adds a stray character or two, set apart by a space, at either end of a line.
const normalizeOcrLine = (l) => {
  const parts = String(l).trim().split(/\s+/);
  while (parts.length > 1 && parts.at(-1).length <= 2) parts.pop();
  while (parts.length > 1 && parts[0].length <= 2) parts.shift();
  return parts.join("").toUpperCase().replace(/[«‹(\[{]/g, "<").replace(/[^A-Z0-9<]/g, "");
};

/**
 * Variants of an OCR'd line at exactly n characters, each with a cost: trim junk
 * off the ends, or add or drop fillers inside a run of <. Fewer edits win ties,
 * so a lucky check digit on a heavily edited line never beats a plain reading.
 */
function fits(line, n) {
  const out = new Map();
  const add = (s, cost) => { if (s.length === n && !(out.get(s) <= cost)) out.set(s, cost); };
  if (line.length === n) add(line, 0);
  if (line.length > n) {
    add(line.slice(0, n), 1);
    add(line.slice(line.length - n), 2);
    const extra = line.length - n;
    const runs = [...line.matchAll(/<{2,}/g)].sort((a, b) => b[0].length - a[0].length);
    for (const r of runs.slice(0, 2)) {
      if (r[0].length > extra) add(line.slice(0, r.index) + r[0].slice(extra) + line.slice(r.index + r[0].length), 3);
    }
  } else if (line.length < n && line.length >= n - 4) {
    const missing = n - line.length;
    add(line + "<".repeat(missing), 1);
    const runs = [...line.matchAll(/<+/g)].sort((a, b) => b[0].length - a[0].length);
    for (const r of runs.slice(0, 2)) add(line.slice(0, r.index) + "<".repeat(missing) + line.slice(r.index), 3);
  }
  return [...out].sort((a, b) => a[1] - b[1]);
}

const score = (f, cost = 0) => (f ? Object.values(f.checks).filter(Boolean).length * 10 + (f.birth ? 3 : 0) + (f.expiry ? 3 : 0) + (f.valid ? 100 : 0) - cost - 2 * (f.repairs || 0) : -1);

/**
 * Find the MRZ in OCR text (any number of lines, noise allowed). Returns the
 * best parse, with `valid` true only when every check digit agrees, or null.
 */
export function findMrz(text, opts) {
  const lines = String(text).split(/\r?\n/, MAX_OCR_LINES).filter((l) => l.length <= MAX_RAW_LINE).map(normalizeOcrLine).filter((l) => l.length >= 26);
  let best = null, bestScore = -1;
  for (const [format, [n, count]] of Object.entries(LAYOUTS)) {
    for (let i = 0; i + count <= lines.length; i++) {
      const group = lines.slice(i, i + count);
      if (group.some((l) => Math.abs(l.length - n) > 6)) continue;
      // The data line has to carry the dates; the names line has to look like names.
      const options = group.map((l) => fits(l, n).slice(0, 6));
      if (options.some((o) => !o.length)) continue;
      const combos = options.reduce((acc, o) => acc.flatMap((a) => o.map((x) => [...a, x])), [[]]).slice(0, 64);
      for (const c of combos) {
        const cost = c.reduce((sum, [, k]) => sum + k, 0);
        const f = parseMrzLines(c.map(([l]) => l), opts);
        if (f && score(f, cost) > bestScore) { best = f; bestScore = score(f, cost); }
      }
    }
  }
  return best;
}

/** The three fields that open a chip with BAC/PACE (YYMMDD dates), from a parse. */
export const accessFromMrz = (f) => (f?.number && f.birthRaw && f.expiryRaw ? { number: f.number, birth: f.birthRaw, expiry: f.expiryRaw } : null);

/* ---------------- several camera frames agreeing ---------------- */

/**
 * Live scanning: OCR many frames, vote character by character across the
 * recent readings of the same layout, and accept only when the voted MRZ passes
 * every check digit and comes out the same twice in a row. One frame's misread
 * is outvoted by the others; a lucky check digit has to repeat to count.
 */
export class MrzConsensus {
  constructor({ window = 5, now } = {}) { this.window = window; this.now = now; this.reads = []; this.lastKey = null; this.streak = 0; }
  reset() { this.reads = []; this.lastKey = null; this.streak = 0; }
  /** Add one frame's OCR text. Returns { best, voted, stable } (any may be null/false). */
  add(text) {
    const best = findMrz(text, { now: this.now });
    if (!best) return { best: null, voted: null, stable: false };
    this.reads = [...this.reads.filter((r) => r.format === best.format && r.lines[0].length === best.lines[0].length), best].slice(-this.window);
    const voted = this.reads.length >= 2 ? vote(this.reads.map((r) => r.lines), { now: this.now }) : null;
    const pick = voted?.valid ? voted : best.valid ? best : null;
    const key = pick ? [pick.lines.join("/")].join() : null;
    this.streak = key && key === this.lastKey ? this.streak + 1 : key ? 1 : 0;
    this.lastKey = key;
    return { best, voted, result: pick, stable: !!pick && this.streak >= 2 };
  }
}

/**
 * Per-position majority vote over several readings of the same MRZ (same layout).
 * Where the vote is tied, each tied character is tried; the reading that needs
 * the fewest guesses to pass every check digit wins.
 */
export function vote(readings, opts) {
  if (!readings.length) return null;
  const ties = [];
  const lines = readings[0].map((first, li) => {
    let out = "";
    for (let i = 0; i < first.length; i++) {
      const tally = new Map();
      for (const r of readings) { const c = r[li][i]; tally.set(c, (tally.get(c) || 0) + 1); }
      const ranked = [...tally].sort((a, b) => b[1] - a[1]);
      const top = ranked.filter(([, n]) => n === ranked[0][1]).map(([c]) => c);
      if (top.length > 1) ties.push({ li, i, top });
      out += top[0];
    }
    return out;
  });
  let best = parseMrzLines(lines, opts);
  const tried = ties.slice(0, 4);
  for (let mask = 1; mask < 1 << tried.length; mask++) {
    const variant = lines.map((l) => [...l]);
    tried.forEach((t, b) => { if (mask & (1 << b)) variant[t.li][t.i] = t.top[1]; });
    const f = parseMrzLines(variant.map((v) => v.join("")), opts);
    if (f && (f.valid && !best?.valid || f.valid === best?.valid && f.repairs < best.repairs)) best = f;
  }
  return best;
}
