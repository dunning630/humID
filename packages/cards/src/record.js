// One record per payment card, sealed into the vault like any document
// (media type application/vnd.humid.card+json). What it will and won't hold:
//
//   holds       number, expiry, name on card, network, the holder's nickname,
//               the bank's name and phone number, notes, a photo of the FRONT
//   never       the PIN; track or chip data; a photo of the back (it shows
//               the security code)
//   opt-in      the security code (CVV / CVC / CID), only after the holder
//               turns it on for this card; turning it off deletes it
//
// The vault index (encrypted, shown in the list without opening) carries only
// network, last four digits and expiry. Opening the record (the full number)
// is a vault open: a fresh live biometric check, recorded in the ledger.

import { checkPan, brandOf, digits, last4, maskPan, formatPan, parseExpiry, expiryStatus, showExpiry } from "./pan.js";

export const SCHEMA = "humid.card/1";
export const MEDIA_TYPE = "application/vnd.humid.card+json";

/** How apps must handle a revealed card. Same on every platform. */
export const HANDLING = {
  revealMs: 30_000,          // re-mask the number and code after this long
  clipboard: false,          // never copied: other apps and keyboards can read the clipboard
  blockScreenshots: true,    // FLAG_SECURE on Android, a privacy cover elsewhere
  maskInAppSwitcher: true,
};

export const FIELDS = [
  { key: "pan", label: "Card number", mono: true, secret: true },
  { key: "expiry", label: "Expires", type: "month" },
  { key: "name", label: "Name on card" },
  { key: "cvv", label: "Security code", mono: true, secret: true, optIn: true },
  { key: "nickname", label: "Nickname", optional: true },
  { key: "bank", label: "Bank", optional: true },
  { key: "phone", label: "Bank phone", optional: true },
  { key: "notes", label: "Notes", optional: true, multiline: true },
];
const KEYS = new Set(FIELDS.map((f) => f.key));
/** Never stored, whoever asks: PINs and the data that lets a card be cloned. */
export const FORBIDDEN = ["pin", "track1", "track2", "track", "magstripe", "pinBlock", "iccData"];

export class CardRecordError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new CardRecordError(code, m); };

const nowIso = () => new Date().toISOString();
const RANK = { typed: 3, nfc: 2, camera: 1 };
const SOURCES = ["camera", "nfc"];

export function newCard() {
  return { schema: SCHEMA, kind: "payment_card", fields: {}, source: {}, policy: { storeCvv: false }, images: {}, edited: [], createdAt: nowIso(), updatedAt: nowIso() };
}

function put(rec, from, values) {
  for (const [k, v] of Object.entries(values)) {
    if (v == null || v === "") continue;
    const had = rec.source[k];
    if (had && had !== from && (RANK[had] ?? 0) > (RANK[from] ?? 0)) continue;
    rec.fields[k] = v; rec.source[k] = from;
  }
  rec.updatedAt = nowIso();
  return rec;
}

/**
 * What a reader found. camera: the front (readCardText / CardConsensus) or the back
 * (readCardBack: security code and bank phone); nfc: readContactless (never a code:
 * the chip doesn't carry it). The security code is kept only if the holder turned
 * that on for this card (setStoreCvv), and only if it has the network's length.
 */
export function applyRead(rec, read, from) {
  if (!read) return rec;
  if (!SOURCES.includes(from)) fail("bad_source", "Unknown card source.");
  const pan = read.pan ? digits(read.pan) : null;
  if (pan && !checkPan(pan).ok) fail("bad_number", "That card number doesn't check out. Try again or type it.");
  const want = brandOf(pan || rec.fields.pan).cvv;
  const cvv = from === "camera" && rec.policy.storeCvv && read.cvv && new RegExp(`^\\d{${want}}$`).test(String(read.cvv)) ? String(read.cvv) : null;
  const phone = from === "camera" && read.phone ? String(read.phone).slice(0, 30) : null;
  put(rec, from, { pan, expiry: read.expiry || null, name: read.name || null, cvv, phone });
  if (from === "nfc") rec.read = { network: read.network || null, aid: read.aid || null, issuerCountry: read.issuerCountry || null, at: nowIso() };
  return rec;
}

/** The holder turns storing this card's security code on or off. Off deletes it. */
export function setStoreCvv(rec, on) {
  rec.policy.storeCvv = !!on;
  if (!on) { delete rec.fields.cvv; delete rec.source.cvv; }
  rec.updatedAt = nowIso();
  return rec;
}

/** The holder typed or corrected fields. Validated; forbidden and unknown fields are refused. */
export function applyTyped(rec, values) {
  for (const k of Object.keys(values)) {
    if (FORBIDDEN.includes(k)) fail("forbidden", "HumID never stores a card's PIN or magnetic-stripe / chip data.");
    if (!KEYS.has(k)) fail("unknown_field", `Unknown card field: ${k}`);
  }
  const v = { ...values };
  if ("pan" in v && v.pan) {
    const c = checkPan(v.pan);
    if (!c.ok) fail("bad_number", c.problems.includes("luhn") ? "That card number has a typo (its check digit doesn't match)." : "That card number is the wrong length for its network.");
    v.pan = c.pan;
  }
  if ("expiry" in v && v.expiry) {
    const e = parseExpiry(v.expiry);
    if (!e) fail("bad_expiry", "Enter the expiry as MM/YY.");
    v.expiry = e;
  }
  if ("cvv" in v && v.cvv) {
    if (!rec.policy.storeCvv) fail("cvv_off", "Turn on 'Keep the security code' for this card first.");
    const want = brandOf(v.pan || rec.fields.pan).cvv;
    if (!new RegExp(`^\\d{${want}}$`).test(String(v.cvv))) fail("bad_cvv", `The security code is ${want} digits.`);
  }
  for (const [k, x] of Object.entries(v)) {
    const val = typeof x === "string" ? x.trim() : x;
    if (val === "" || val == null) { delete rec.fields[k]; delete rec.source[k]; }
    else { rec.fields[k] = val; rec.source[k] = "typed"; }
    if (!rec.edited.includes(k)) rec.edited.push(k);
  }
  rec.updatedAt = nowIso();
  return rec;
}

/** A photo of the card's front. The back is refused: it shows the security code. */
export function setImage(rec, side, image) {
  if (side !== "front") fail("no_back_photo", "HumID keeps a photo of the front only; the back shows the security code.");
  rec.images.front = image; rec.updatedAt = nowIso();
  return rec;
}

/** Anything still wrong before sealing: [{ field, code }]. */
export function problems(rec) {
  const out = [];
  const f = rec.fields;
  if (!f.pan) out.push({ field: "pan", code: "missing" });
  else if (!checkPan(f.pan).ok) out.push({ field: "pan", code: "invalid" });
  if (f.expiry && !/^\d{4}-\d{2}$/.test(f.expiry)) out.push({ field: "expiry", code: "invalid" });
  if (f.cvv && !rec.policy.storeCvv) out.push({ field: "cvv", code: "not_allowed" });
  return out;
}

export const brand = (rec) => brandOf(rec.fields.pan);
export const status = (rec, now) => expiryStatus(rec.fields.expiry, now);

/** "Visa •••• 1111", or the holder's nickname. */
export function title(rec) {
  return rec.fields.nickname || `${brand(rec).name} ${maskPan(rec.fields.pan)}`;
}

/** What the encrypted vault index carries: never the number. */
export const summary = (rec) => ({ kind: "payment_card", brand: brand(rec).id, last4: last4(rec.fields.pan), expiry: rec.fields.expiry || "", nickname: rec.fields.nickname || "" });

/** Display values. Number and code stay masked unless `revealed` (which the app sets after its biometric check and clears after HANDLING.revealMs). */
export function view(rec, { revealed = false } = {}) {
  const f = rec.fields;
  return {
    title: title(rec), brand: brand(rec).id, brandName: brand(rec).name,
    number: f.pan ? (revealed ? formatPan(f.pan) : maskPan(f.pan)) : "",
    expiry: showExpiry(f.expiry), name: f.name || "",
    cvv: f.cvv ? (revealed ? f.cvv : "•".repeat(String(f.cvv).length)) : null,
    bank: f.bank || "", phone: f.phone || "", notes: f.notes || "",
    status: status(rec),
  };
}

function scrub(rec) {
  for (const k of FORBIDDEN) { delete rec[k]; delete rec.fields?.[k]; }
  if (!rec.policy?.storeCvv) { delete rec.fields?.cvv; delete rec.source?.cvv; }
  if (rec.images) for (const side of Object.keys(rec.images)) if (side !== "front") delete rec.images[side];
  return rec;
}

export function encodeCard(rec) {
  const bad = problems(rec).filter((p) => p.code !== "missing" || p.field !== "pan");
  if (!rec.fields.pan) fail("bad_number", "A card needs its number.");
  if (bad.length) fail("bad_card", "Fix the card's details before saving.");
  return new TextEncoder().encode(JSON.stringify(scrub({ ...rec, fields: { ...rec.fields }, source: { ...rec.source }, images: { ...rec.images }, schema: SCHEMA })));
}

export function decodeCard(bytes) {
  const j = JSON.parse(typeof bytes === "string" ? bytes : new TextDecoder().decode(bytes));
  if (j?.schema !== SCHEMA) throw new CardRecordError("not_card", "not a HumID card record");
  return scrub({ fields: {}, source: {}, policy: { storeCvv: false }, images: {}, edited: [], ...j });
}
