// Reading a contactless payment card's number and expiry (EMV Book 3 /
// EMV Contactless), over the same APDU transport HumID uses for passport
// chips: transport.transceive(bytes) → response bytes with status word.
// Android (IsoDep) and desktop USB readers (PC/SC) can do this; iPhone apps
// can't read payment cards over NFC, so iPhones use the camera.
//
//   SELECT PPSE ("2PAY.SYS.DDF01") → the card's payment applications
//   SELECT the application → its PDOL (what it wants to know first)
//   GET PROCESSING OPTIONS  → where its records are (AFL), or track 2 directly
//   READ RECORD …           → PAN (5A), expiry (5F24), track 2 equivalent (57)
//
// Only the number, expiry, name (rarely present), network and issuing country
// are returned. Never the security code, service code or track discretionary
// data, and no payment is made: no GENERATE AC, amount zero.

export class CardReadError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (code, m) => { throw new CardReadError(code, m); };

/* ---------------- BER-TLV ---------------- */

/** Parse BER-TLV into [{ tag (hex string), value, children? }]. */
export function tlv(bytes) {
  const out = [];
  let i = 0;
  while (i < bytes.length) {
    if (bytes[i] === 0x00 || bytes[i] === 0xff) { i++; continue; } // padding
    const t0 = i;
    let tagEnd = i + 1;
    if ((bytes[i] & 0x1f) === 0x1f) { while (tagEnd < bytes.length && bytes[tagEnd] & 0x80) tagEnd++; tagEnd++; }
    if (tagEnd > bytes.length) break;
    const tag = hex(bytes.subarray(t0, tagEnd)).toUpperCase();
    const constructed = !!(bytes[t0] & 0x20);
    let len = bytes[tagEnd], p = tagEnd + 1;
    if (len === undefined) break;
    if (len & 0x80) { const k = len & 0x7f; if (k > 3) break; len = 0; for (let j = 0; j < k; j++) len = len * 256 + bytes[p++]; }
    if (p + len > bytes.length) break;
    const value = bytes.subarray(p, p + len);
    out.push(constructed ? { tag, value, children: tlv(value) } : { tag, value });
    i = p + len;
  }
  return out;
}
/** Every value with this tag, anywhere in the tree. */
export function find(nodes, tag, acc = []) {
  for (const n of nodes) { if (n.tag === tag) acc.push(n.value); if (n.children) find(n.children, tag, acc); }
  return acc;
}
const first = (nodes, tag) => find(nodes, tag)[0] || null;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
const ascii = (b) => Array.from(b, (x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : "")).join("").trim();

/* ---------------- APDUs ---------------- */

const apdu = (cla, ins, p1, p2, data, le = 0) => {
  const d = data || new Uint8Array(0);
  return Uint8Array.from([cla, ins, p1, p2, ...(d.length ? [d.length, ...d] : []), le]);
};
const sw = (r) => (r.length >= 2 ? (r[r.length - 2] << 8) | r[r.length - 1] : 0);
const body = (r) => r.subarray(0, r.length - 2);

async function send(transport, cmd) {
  let r = await transport.transceive(cmd);
  if (!(r instanceof Uint8Array)) r = new Uint8Array(r);
  if ((sw(r) & 0xff00) === 0x6c00) { const c = cmd.slice(); c[c.length - 1] = sw(r) & 0xff; r = new Uint8Array(await transport.transceive(c)); }
  let data = body(r);
  for (let guard = 0; (sw(r) & 0xff00) === 0x6100 && guard < 16; guard++) {
    r = new Uint8Array(await transport.transceive(apdu(0x00, 0xc0, 0, 0, null, sw(r) & 0xff)));
    data = Uint8Array.from([...data, ...body(r)]);
  }
  return { sw: sw(r), data };
}

/** Well-known payment application ids, tried when a card has no PPSE directory. */
export const AIDS = {
  A0000000031010: "Visa", A0000000032010: "Visa Electron", A0000000041010: "Mastercard", A0000000043060: "Maestro",
  A00000002501: "American Express", A0000001523010: "Discover", A0000000651010: "JCB", A000000333010101: "UnionPay Debit",
  A000000333010102: "UnionPay Credit", A0000002771010: "Interac", A0000005241010: "RuPay", A0000006581010: "Mir",
};

const PPSE = new TextEncoder().encode("2PAY.SYS.DDF01");

/** The values HumID gives for a PDOL: a zero-amount, read-only request. */
function pdolData(pdol, { now = new Date(), random } = {}) {
  const yymmdd = Uint8Array.from([now.getUTCFullYear() % 100, now.getUTCMonth() + 1, now.getUTCDate()].map((n) => ((n / 10) | 0) * 16 + (n % 10)));
  const known = {
    "9F66": Uint8Array.of(0x36, 0x00, 0x40, 0x00),      // TTQ: contactless EMV, online-capable, no CVM, read only
    "9F02": new Uint8Array(6),                          // amount: 0
    "9F03": new Uint8Array(6),                          // other amount: 0
    "9F1A": Uint8Array.of(0x08, 0x40),                  // terminal country
    "5F2A": Uint8Array.of(0x08, 0x40),                  // currency
    "95": new Uint8Array(5),                            // TVR
    "9A": yymmdd,                                       // date
    "9C": Uint8Array.of(0x00),                          // transaction type: purchase (amount 0)
    "9F37": random || crypto.getRandomValues(new Uint8Array(4)), // unpredictable number
    "9F35": Uint8Array.of(0x22),                        // terminal type
    "9F40": new Uint8Array(5),
    "9F33": Uint8Array.of(0xe0, 0x08, 0x08),            // terminal capabilities: no CVM performed
  };
  const out = [];
  let i = 0;
  while (i < pdol.length) {
    let e = i + 1;
    if ((pdol[i] & 0x1f) === 0x1f) { while (pdol[e] & 0x80) e++; e++; }
    const tag = hex(pdol.subarray(i, e)).toUpperCase();
    const len = pdol[e];
    i = e + 1;
    const v = known[tag] || new Uint8Array(len);
    const fixed = new Uint8Array(len);
    if (v.length >= len) fixed.set(v.subarray(0, len)); else fixed.set(v, len - v.length); // numbers right-aligned
    out.push(...fixed);
  }
  return Uint8Array.from(out);
}

/** Track 2 equivalent → { pan, expiry "YYMM" }. Service code and discretionary data are dropped. */
export function parseTrack2(bytes) {
  const s = hex(bytes).toUpperCase();
  const m = /^(\d{12,19})D(\d{4})/.exec(s);
  return m ? { pan: m[1], yymm: m[2] } : null;
}

const pan5A = (b) => hex(b).toUpperCase().replace(/F+$/, "");
const yymmdd = (b) => hex(b);
function holderName(b) {
  if (!b) return null;
  const s = ascii(b).replace(/\s+/g, " ").trim();
  if (!s || /^[\s/]*$/.test(s) || /CARDHOLDER|CUSTOMER|VALUED|\bCARD\b/i.test(s)) return null;
  const [sur, given] = s.split("/").map((x) => x.trim());
  return given ? `${given} ${sur}`.replace(/\s+/g, " ").trim() : sur;
}

async function selectApp(transport, aid) {
  const r = await send(transport, apdu(0x00, 0xa4, 0x04, 0x00, aid));
  return r.sw === 0x9000 ? tlv(r.data) : null;
}

/**
 * Read a contactless card. Returns { pan, expiry: "YYYY-MM", name, network,
 * aid, issuerCountry (ISO 3166 numeric) }. Throws CardReadError.
 */
export async function readContactless(transport, { now = new Date(), random } = {}) {
  // 1. Which payment applications?
  let apps = [];
  const ppse = await send(transport, apdu(0x00, 0xa4, 0x04, 0x00, PPSE));
  if (ppse.sw === 0x9000) {
    for (const entry of find(tlv(ppse.data), "61")) {
      const e = tlv(entry);
      const aid = first(e, "4F");
      if (aid) apps.push({ aid, label: first(e, "50") ? ascii(first(e, "50")) : null, priority: first(e, "87")?.[0] & 0x0f || 99 });
    }
    apps.sort((a, b) => a.priority - b.priority);
  }
  if (!apps.length) apps = Object.entries(AIDS).map(([a, label]) => ({ aid: fromHex(a), label, priority: 99, guess: true }));

  for (const app of apps) {
    const fci = await selectApp(transport, app.aid);
    if (!fci) continue;
    const aidHex = hex(app.aid).toUpperCase();
    const label = (first(fci, "9F12") && ascii(first(fci, "9F12"))) || (first(fci, "50") && ascii(first(fci, "50"))) || app.label || AIDS[aidHex] || null;

    // 2. Processing options.
    const pdol = first(fci, "9F38");
    const pd = pdol ? pdolData(pdol, { now, random }) : new Uint8Array(0);
    const gpo = await send(transport, apdu(0x80, 0xa8, 0x00, 0x00, Uint8Array.from([0x83, pd.length, ...pd])));
    if (gpo.sw !== 0x9000) continue;
    const g = tlv(gpo.data);
    let afl = null;
    const fmt1 = first(g, "80");
    if (fmt1) afl = fmt1.subarray(2);
    else afl = first(g, "94");
    const found = [g];

    // 3. Records.
    if (afl) {
      for (let i = 0; i + 3 < afl.length; i += 4) {
        const sfi = afl[i] >> 3, from = afl[i + 1], to = afl[i + 2];
        for (let rec = from; rec <= to && rec - from < 16; rec++) {
          const r = await send(transport, apdu(0x00, 0xb2, rec, (sfi << 3) | 4));
          if (r.sw === 0x9000) found.push(tlv(r.data));
        }
      }
    }
    const all = found.flat();
    const t2 = parseTrack2(first(all, "57") || first(all, "9F6B") || new Uint8Array(0));
    const pan = first(all, "5A") ? pan5A(first(all, "5A")) : t2?.pan || null;
    const exp = first(all, "5F24") ? yymmdd(first(all, "5F24")).slice(0, 4) : t2?.yymm || null;
    if (!pan) continue;
    const yy = exp ? +exp.slice(0, 2) : null, mm = exp ? exp.slice(2, 4) : null;
    const country = first(all, "5F28");
    return {
      pan, expiry: exp && +mm >= 1 && +mm <= 12 ? `${2000 + yy}-${mm}` : null, name: holderName(first(all, "5F20")),
      network: label, aid: aidHex, issuerCountry: country ? hex(country).replace(/^0/, "") : null,
    };
  }
  fail(apps.some((a) => !a.guess) ? "no_number" : "no_payment_app", "This card didn't share its number. Scan the front with the camera instead.");
}
