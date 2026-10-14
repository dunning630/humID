// Reading a card's front from OCR text (the app's camera engine gives lines
// of text; this decides what they mean). Embossed and flat-printed numbers
// both arrive as digit groups; OCR confuses a few letters with digits, which
// are repaired only inside digit groups, and a number is accepted only when
// it passes the Luhn check and fits its network's length. Like the MRZ
// reader, live scanning accepts a number once two frames agree.

import { digits, checkPan, parseExpiry } from "./pan.js";

const FIX = { O: "0", o: "0", D: "0", Q: "0", I: "1", l: "1", "|": "1", "!": "1", Z: "2", S: "5", s: "5", B: "8", G: "6", b: "6", T: "7" };
const fixDigits = (s) => s.replace(/[OoDQIl|!ZSsBGbT]/g, (c) => FIX[c]);

/** Candidate card numbers in a block of text: runs of 12-19 digits in groups. */
function panCandidates(text) {
  const out = new Set();
  // Digit groups (with OCR look-alikes) separated by single spaces.
  const re = /(?:[0-9OoDQIl|!ZSsBGbT]{3,6}[ \t]?){3,6}[0-9OoDQIl|!ZSsBGbT]{0,6}/g;
  for (const line of String(text).split(/\r?\n/)) {
    for (const m of line.matchAll(re)) {
      const raw = m[0].trim();
      if ((raw.match(/[0-9]/g) || []).length < raw.replace(/\s/g, "").length * 0.6) continue; // mostly letters: a word, not a number
      const d = digits(fixDigits(raw));
      if (d.length >= 12 && d.length <= 19) out.add(d);
      // A trailing stray digit group (e.g. "4111 1111 1111 1111 12/28" without the slash) — try trimming.
      for (let cut = 1; cut <= 4 && d.length - cut >= 13; cut++) out.add(d.slice(0, d.length - cut));
    }
  }
  return [...out];
}

const NOT_NAME = /\b(VISA|MASTERCARD|MASTER|CARD|DEBIT|CREDIT|BANK|VALID|THRU|THROUGH|FROM|MEMBER|SINCE|GOOD|EXPIRES|EXP|PLATINUM|GOLD|SIGNATURE|REWARDS|WORLD|ELITE|BUSINESS|CORPORATE|PREPAID|ELECTRON|CONTACTLESS|AMERICAN|EXPRESS|DISCOVER|INTERNATIONAL|CHASE|CITI|CAPITAL|ONE|WELLS|FARGO|BARCLAYS|HSBC|INFINITE|PREFERRED|CASH|BACK|MONTH|YEAR)\b/;

/**
 * Read a card front from OCR text. Returns { pan, brand, expiry, name, issues }
 * with null for anything not found. Expiry: the latest plausible MM/YY (a
 * "member since" date is earlier). Name: an all-capitals line of 2-4 words.
 */
export function readCardText(text, { now = new Date() } = {}) {
  const issues = [];
  const valid = panCandidates(text).map(checkPan).filter((c) => c.ok);
  // Prefer known networks and longer numbers.
  valid.sort((a, b) => (a.brand === "unknown") - (b.brand === "unknown") || b.pan.length - a.pan.length);
  const pan = valid[0] || null;
  if (valid.length > 1 && valid[1].pan !== pan.pan) issues.push("several_numbers");

  const dates = [...String(text).matchAll(/(?<![\d/])(0[1-9]|1[0-2]|[1-9])\s?[/\-]\s?(\d{2}|20\d{2})(?![\d/])/g)]
    .map((m) => parseExpiry(`${m[1]}/${m[2]}`)).filter(Boolean)
    .filter((e) => +e.slice(0, 4) <= now.getUTCFullYear() + 20);
  dates.sort();
  const expiry = dates.length ? dates[dates.length - 1] : null;

  let name = null;
  for (const line of String(text).split(/\r?\n/)) {
    const s = line.trim().replace(/\s+/g, " ");
    if (!/^[A-Z][A-Z.'\-]*(?: [A-Z][A-Z.'\-]*){1,3}$/.test(s) || s.length > 26 || NOT_NAME.test(s)) continue;
    name = s; break;
  }
  return { pan: pan?.pan || null, brand: pan?.brand || null, expiry, name, issues };
}

/**
 * Live scanning: feed each frame's OCR text; `result` is set once the same
 * number has been read in `need` frames. Expiry and name take the most common reading.
 */
export class CardConsensus {
  constructor({ need = 2 } = {}) { this.need = need; this.pans = new Map(); this.expiries = new Map(); this.names = new Map(); this.result = null; }
  add(text, opts) {
    const r = readCardText(text, opts);
    const bump = (m, k) => k && m.set(k, (m.get(k) || 0) + 1);
    bump(this.pans, r.pan); bump(this.expiries, r.expiry); bump(this.names, r.name);
    const top = (m) => [...m].sort((a, b) => b[1] - a[1])[0] || [null, 0];
    const [pan, n] = top(this.pans);
    if (pan && n >= this.need) {
      const c = checkPan(pan);
      this.result = { pan, brand: c.brand, expiry: top(this.expiries)[0], name: top(this.names)[0], frames: n };
    }
    return this.result;
  }
}
