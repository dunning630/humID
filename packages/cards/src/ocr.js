// Reading a card's front from OCR text (the app's camera engine gives lines
// of text; this decides what they mean). Embossed and flat-printed numbers
// both arrive as digit groups; OCR confuses a few letters with digits, which
// are repaired only inside digit groups, and a number is accepted only when
// it passes the Luhn check and fits its network's length. Like the MRZ
// reader, live scanning accepts a number once two frames agree.

import { digits, checkPan, parseExpiry } from "./pan.js";

// OCR text is attacker-influenced (a card or a screen in front of the camera):
// look at a bounded amount of it, and only short lines (a card line is far under 100 characters).
const MAX_TEXT = 16384;
const MAX_LINE = 256;
const MAX_LINES = 200;
const ocrLines = (text) => String(text ?? "").slice(0, MAX_TEXT).split(/\r?\n/, MAX_LINES).map((l) => (l.length > MAX_LINE ? "" : l));

const FIX = { O: "0", o: "0", D: "0", Q: "0", I: "1", l: "1", "|": "1", "!": "1", Z: "2", S: "5", s: "5", B: "8", G: "6", b: "6", T: "7" };
const fixDigits = (s) => s.replace(/[OoDQIl|!ZSsBGbT]/g, (c) => FIX[c]);

/** Candidate card numbers in a block of text: runs of 12-19 digits in groups. */
function panCandidates(text) {
  const out = new Set();
  // Digit groups (with OCR look-alikes) separated by single spaces.
  const re = /(?:[0-9OoDQIl|!ZSsBGbT]{3,6}[ \t]?){3,6}[0-9OoDQIl|!ZSsBGbT]{0,6}/g;
  for (const line of ocrLines(text)) {
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

  const dates = [...String(text ?? "").slice(0, MAX_TEXT).matchAll(/(?<![\d/])(0[1-9]|1[0-2]|[1-9])\s?[/\-]\s?(\d{2}|20\d{2})(?![\d/])/g)]
    .map((m) => parseExpiry(`${m[1]}/${m[2]}`)).filter(Boolean)
    .filter((e) => +e.slice(0, 4) <= now.getUTCFullYear() + 20);
  dates.sort();
  const expiry = dates.length ? dates[dates.length - 1] : null;

  let name = null;
  for (const line of ocrLines(text)) {
    const s = line.trim().replace(/\s+/g, " ");
    if (s.length > 26 || !/^[A-Z][A-Z.'\-]*(?: [A-Z][A-Z.'\-]*){1,3}$/.test(s) || NOT_NAME.test(s)) continue;
    name = s; break;
  }
  // American Express prints its 4-digit security code (CID) on the front, above the number.
  let cvv = null;
  if (pan?.brand === "amex") {
    const groups = new Set();
    for (const line of ocrLines(text)) {
      if (digits(fixDigits(line)).includes(pan.pan.slice(0, 8))) continue; // the number's own line
      if (/SINCE|MEMBER|VALID|THRU|EXP|GOOD|FROM|YEAR/i.test(line)) continue; // a "member since" year, a date
      for (const m of line.matchAll(/(?<![\d/])(\d{4})(?![\d/])/g)) if (m[1] !== pan.pan.slice(0, 4)) groups.add(m[1]);
    }
    if (groups.size === 1) cvv = [...groups][0];
  }
  return { pan: pan?.pan || null, brand: pan?.brand || null, expiry, name, cvv, issues };
}

/* ---------------- the back of the card ---------------- */

// Phone numbers as printed on cards: North American (1-800-555-0100, (800) 555-0100)
// and international (+44 20 7946 0000).
const PHONE = /(?:\+?1[\s.\-]?)?\(?([2-9]\d{2})\)?[\s.\-]?(\d{3})[\s.\-]?(\d{4})(?!\d)|\+(?!1\b)(\d{1,3})[\s.\-]?((?:\d[\s.\-]?){6,12}\d)/g;
const SERVICE = /(CALL|CUSTOMER|SERVICE|LOST|STOLEN|TOLL|PHONE|TEL|COLLECT|ASSISTANCE|QUESTIONS)/i;

function phones(text) {
  const out = [];
  for (const line of ocrLines(text)) {
    for (const m of line.matchAll(PHONE)) {
      const shown = m[1] ? `1-${m[1]}-${m[2]}-${m[3]}` : `+${m[4]} ${m[5].replace(/[\s.\-]+/g, " ").trim()}`;
      out.push({ shown, service: SERVICE.test(line), start: m.index, end: m.index + m[0].length, line });
    }
  }
  return out;
}

/**
 * Read the back of a card from OCR text: the security code (CVV / CVC) and the bank's
 * phone number. pan, when known, helps: many cards print the last four digits next to
 * the code ("1111 123"). Returns { cvv, phone, issues }, null for what wasn't found.
 * A code is taken only when there's exactly one clear candidate; otherwise the holder types it.
 */
export function readCardBack(text, { pan = null } = {}) {
  const t = String(text ?? "").slice(0, MAX_TEXT);
  const issues = [];
  const want = pan ? checkPan(pan).brand === "amex" ? 4 : 3 : 3;
  const ph = phones(t);
  const phone = (ph.find((p) => p.service) || ph[0])?.shown || null;

  let cvv = null;
  const fixed = ocrLines(t).map((line) => line.replace(/[0-9OoDQIl|!ZSsBGbT]{2,}/g, (g) => (/[0-9]/.test(g) ? fixDigits(g) : g)));
  const last4 = pan ? digits(pan).slice(-4) : null;
  // 1. next to the last four digits of the number, or after a "CVV / CVC / security code" label
  const near = [];
  for (const line of fixed) {
    if (last4) for (const m of line.matchAll(new RegExp(`${last4}\\s*(\\d{${want}})(?!\\d)`, "g"))) near.push(m[1]);
    for (const m of line.matchAll(new RegExp(`(?:CVV2?|CVC2?|CID|SECURITY\\s*CODE|CSC)\\W{0,3}(\\d{${want}})(?!\\d)`, "gi"))) near.push(m[1]);
  }
  if (new Set(near).size === 1) cvv = near[0];
  else if (near.length) issues.push("several_codes");
  // 2. otherwise: the only standalone group of that many digits that isn't part of a phone number or a date
  if (!cvv && !near.length) {
    const lone = [];
    fixed.forEach((line) => {
      const taken = phones(line).map((p) => [p.start, p.end]);
      for (const m of line.matchAll(new RegExp(`(?<![\\d/\\-.])(\\d{${want}})(?![\\d/\\-.])`, "g"))) {
        if (taken.some(([a, b]) => m.index >= a && m.index < b)) continue;
        lone.push(m[1]);
      }
    });
    if (new Set(lone).size === 1) cvv = lone[0];
    else if (lone.length > 1) issues.push("several_codes");
  }
  if (!cvv) issues.push("no_code");
  return { cvv, phone, issues };
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
