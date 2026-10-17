// Simulated contactless payment cards: they answer the APDUs a reader sends
// (SELECT, GET PROCESSING OPTIONS, READ RECORD) with BER-TLV built here.
// Test card numbers only (network test ranges). Used by the tests and by
// development builds' "Use a demo card"; release builds never import it.

const fromHex = (s) => Uint8Array.from(s.replace(/\s+/g, "").match(/../g) || [], (h) => parseInt(h, 16));
const ascii = (s) => new TextEncoder().encode(s);
const lenBytes = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]);
/** t("5A", bytes) or t("70", [child, child]). */
export function t(tag, v) {
  const value = Array.isArray(v) ? Uint8Array.from(v.flatMap((x) => [...x])) : typeof v === "string" ? fromHex(v) : v;
  return Uint8Array.from([...fromHex(tag), ...lenBytes(value.length), ...value]);
}
const ok = (data = new Uint8Array(0)) => Uint8Array.from([...data, 0x90, 0x00]);
const SW = (a, b) => Uint8Array.of(a, b);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const bcdPan = (pan) => fromHex(pan.length % 2 ? pan + "F" : pan);
const track2 = (pan, yymm) => { const s = `${pan}D${yymm}2011000000000000`; return fromHex(s.length % 2 ? s + "F" : s); };

/**
 * A card. kind: "visa" (GPO format 2 with track 2, has PDOL), "mastercard"
 * (format 1, AFL, records), "amex-noppse" (no PPSE directory), "refuses"
 * (GPO always 6985), "visa-debit" (format 2 with an AFL, the issuer's own
 * preferred name, name, country and valid-from in the records: everything a
 * card can fill in). chain: answer SELECT with 61xx first.
 */
export function card(kind, { pan, yymm = "2908", name = "SPECIMEN/JANE Q", chain = false, preferredName = "FIRST HUMID DEBIT" } = {}) {
  const log = [];
  const aids = { visa: "A0000000031010", "visa-debit": "A0000000031010", mastercard: "A0000000041010", "amex-noppse": "A00000002501", refuses: "A0000000031010" };
  const aid = aids[kind];
  if (!aid) throw new Error(`no simulated card "${kind}"`);
  const panFor = pan || { visa: "4111111111111111", "visa-debit": "4012888888881881", mastercard: "5555555555554444", "amex-noppse": "378282246310005", refuses: "4111111111111111" }[kind];
  let pending = null;
  let gpoData = null;

  const records = {
    "1:1": t("70", [t("57", track2(panFor, yymm)), t("5F20", ascii(name))]),
    "2:1": t("70", [t("5A", bcdPan(panFor)), t("5F24", `${yymm}31`), t("5F28", "0840"), t("5F25", "240101")]),
    "2:2": t("70", [t("8C", "9F02069F03069F1A0295055F2A029A039C019F3704")]),
  };

  async function transceive(cmd) {
    log.push(hex(cmd));
    const [cla, ins, p1, p2] = cmd;
    const lc = cmd.length > 5 ? cmd[4] : 0;
    const data = cmd.subarray(5, 5 + lc);
    let r;
    if (ins === 0xc0 && pending) { r = ok(pending); pending = null; return r; }
    if (ins === 0xa4) {
      const name = hex(data);
      if (name === hex(ascii("2PAY.SYS.DDF01"))) {
        if (kind === "amex-noppse") return SW(0x6a, 0x82);
        const label = { visa: "VISA CREDIT", "visa-debit": "VISA DEBIT" }[kind] || "MASTERCARD";
        r = t("6F", [t("84", ascii("2PAY.SYS.DDF01")), t("A5", [t("BF0C", [t("61", [t("4F", aid), t("50", ascii(label)), t("87", "01")])])])]);
      } else if (name === aid) {
        const fci = [t("50", ascii({ "amex-noppse": "AMERICAN EXPRESS", "visa-debit": "VISA DEBIT" }[kind] || kind.toUpperCase()))];
        if (kind === "visa-debit") fci.push(t("9F12", ascii(preferredName)));
        if (kind === "visa" || kind === "visa-debit" || kind === "refuses") fci.push(t("9F38", "9F66049F02069F03069F1A0295055F2A029A039C019F3704"));
        r = t("6F", [t("84", aid), t("A5", fci)]);
      } else return SW(0x6a, 0x82);
      if (chain) { pending = r; return SW(0x61, r.length); }
      return ok(r);
    }
    if (cla === 0x80 && ins === 0xa8) {
      gpoData = data;
      if (kind === "refuses") return SW(0x69, 0x85);
      if (kind === "visa") return ok(t("77", [t("82", "0020"), t("57", track2(panFor, yymm)), t("5F20", ascii(" /")), t("9F10", "06011203A00000"), t("9F26", "1122334455667788")]));
      if (kind === "visa-debit") return ok(t("77", [t("82", "0020"), t("94", "08010100" + "10010100"), t("57", track2(panFor, yymm)), t("9F10", "06011203A00000"), t("9F26", "1122334455667788")]));
      return ok(t("80", fromHex("1980" + "08010100" + "10010200")));
    }
    if (ins === 0xb2) {
      const sfi = p2 >> 3;
      const rec = records[`${sfi}:${p1}`];
      return rec ? ok(rec) : SW(0x6a, 0x83);
    }
    return SW(0x6d, 0x00);
  }
  return { transceive, log, gpo: () => gpoData, pan: panFor };
}
