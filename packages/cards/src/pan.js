// Card numbers (PANs): the Luhn check, the card network from the number's
// leading digits (IIN), formatting and masking, and expiry dates.

export const digits = (s) => String(s ?? "").replace(/\D+/g, "");

/** ISO/IEC 7812 Luhn check. */
export function luhn(pan) {
  const d = digits(pan);
  if (d.length < 12) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

const r = (lo, hi) => (p) => { const n = +p.slice(0, String(lo).length); return n >= lo && n <= hi; };
const pre = (...xs) => (p) => xs.some((x) => p.startsWith(String(x)));

/**
 * Networks, most specific first. lengths: valid PAN lengths. groups: how the
 * number is printed. cvv: security code length.
 */
export const BRANDS = [
  { id: "mir", name: "Mir", test: r(2200, 2204), lengths: [16, 17, 18, 19], cvv: 3 },
  { id: "mastercard", name: "Mastercard", test: (p) => r(51, 55)(p) || r(2221, 2720)(p), lengths: [16], cvv: 3 },
  { id: "amex", name: "American Express", test: pre(34, 37), lengths: [15], groups: [4, 6, 5], cvv: 4 },
  { id: "diners", name: "Diners Club", test: (p) => r(300, 305)(p) || pre(3095, 36, 38, 39)(p), lengths: [14, 15, 16, 17, 18, 19], groups: [4, 6, 4], cvv: 3 },
  { id: "jcb", name: "JCB", test: r(3528, 3589), lengths: [16, 17, 18, 19], cvv: 3 },
  { id: "discover", name: "Discover", test: (p) => pre(6011, 65)(p) || r(644, 649)(p) || r(622126, 622925)(p), lengths: [16, 17, 18, 19], cvv: 3 },
  { id: "unionpay", name: "UnionPay", test: pre(62, 81), lengths: [16, 17, 18, 19], cvv: 3 },
  { id: "rupay", name: "RuPay", test: pre(508, 60, 652), lengths: [16], cvv: 3 },
  { id: "visa", name: "Visa", test: pre(4), lengths: [13, 16, 19], cvv: 3 },
  { id: "maestro", name: "Maestro", test: (p) => pre(50)(p) || r(56, 69)(p), lengths: [12, 13, 14, 15, 16, 17, 18, 19], cvv: 3 },
];
const UNKNOWN = { id: "unknown", name: "Card", lengths: [12, 13, 14, 15, 16, 17, 18, 19], cvv: 3 };

/** The network for a number (by its leading digits), or { id: "unknown" }. */
export function brandOf(pan) {
  const p = digits(pan);
  if (!p) return UNKNOWN;
  return BRANDS.find((b) => b.test(p)) || UNKNOWN;
}

/** { ok, pan, brand, problems[] } — problems: "length", "luhn". */
export function checkPan(pan) {
  const p = digits(pan);
  const brand = brandOf(p);
  const problems = [];
  if (!brand.lengths.includes(p.length)) problems.push("length");
  if (!luhn(p)) problems.push("luhn");
  return { ok: problems.length === 0, pan: p, brand: brand.id, brandName: brand.name, problems };
}

/** "4111 1111 1111 1111", "3782 822463 10005". */
export function formatPan(pan) {
  const p = digits(pan);
  const groups = brandOf(p).groups || (p.length === 19 ? [4, 4, 4, 4, 3] : null);
  if (groups && groups.reduce((a, b) => a + b, 0) === p.length) {
    const out = []; let i = 0;
    for (const g of groups) { out.push(p.slice(i, i + g)); i += g; }
    return out.join(" ");
  }
  return p.replace(/(.{4})(?=.)/g, "$1 ");
}

export const last4 = (pan) => digits(pan).slice(-4);
/** "•••• 1111". Only ever the last four. */
export const maskPan = (pan) => (digits(pan).length >= 4 ? `•••• ${last4(pan)}` : "••••");

/**
 * Expiry "MM/YY", "MM/YYYY", "MMYY", "YYMM" (chip / track 2 order, pass
 * order: "yymm") → "YYYY-MM", or "" if it can't be a card expiry.
 */
export function parseExpiry(s, { order = "mmyy" } = {}) {
  const t = String(s ?? "").trim();
  let m, y, mo;
  if ((m = /^(\d{1,2})\s*[/\-.]\s*(\d{2}|\d{4})$/.exec(t))) { mo = +m[1]; y = +m[2]; }
  else if ((m = /^(\d{2})(\d{2})$/.exec(t))) { [mo, y] = order === "yymm" ? [+m[2], +m[1]] : [+m[1], +m[2]]; }
  else if ((m = /^(\d{4})-(\d{2})$/.exec(t))) { y = +m[1]; mo = +m[2]; }
  else return "";
  if (y < 100) y += 2000;
  if (mo < 1 || mo > 12 || y < 1990 || y > 2099) return "";
  return `${y}-${String(mo).padStart(2, "0")}`;
}

/** Cards are valid through the last day of the expiry month. { state, months } with state valid | expiring (≤ 2 months) | expired. */
export function expiryStatus(expiry, now = new Date()) {
  const m = /^(\d{4})-(\d{2})$/.exec(expiry || "");
  if (!m) return { state: "unknown", months: null };
  const months = (+m[1] - now.getUTCFullYear()) * 12 + (+m[2] - 1 - now.getUTCMonth());
  return { state: months < 0 ? "expired" : months <= 2 ? "expiring" : "valid", months };
}

/** "12/28" for display. */
export const showExpiry = (e) => (/^\d{4}-\d{2}$/.test(e || "") ? `${e.slice(5)}/${e.slice(2, 4)}` : "");
