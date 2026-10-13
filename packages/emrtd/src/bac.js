// Basic Access Control (ICAO 9303 part 11, section 4.3). The access key comes
// from the MRZ (document number, birth date, expiry), which is why a chip
// can't be read through a closed passport. Older and many current passports.
import { sha1 } from "@noble/hashes/legacy.js";
import { tdesCbc, retailMac, withParity } from "./des.js";
import { concat, pad, utf8, u32be, random, equal, ChipError } from "./util.js";

const WEIGHTS = [7, 3, 1];
const value = (c) => (c === "<" ? 0 : /[0-9]/.test(c) ? c.charCodeAt(0) - 48 : c.charCodeAt(0) - 55);
export const checkDigit = (s) => [...s].reduce((sum, c, i) => sum + value(c) * WEIGHTS[i % 3], 0) % 10;

/** Clean what a person typed: upper case, look-alikes, YYMMDD dates. */
export function normalizeAccess({ number, birth, expiry }) {
  const num = String(number || "").toUpperCase().replace(/[^0-9A-Z<]/g, "");
  const d = (s) => String(s || "").replace(/\D/g, "");
  const b = d(birth), e = d(expiry);
  if (num.length < 1 || num.length > 22) throw new ChipError("bad_access", "Enter the document number as printed.");
  if (b.length !== 6 || e.length !== 6) throw new ChipError("bad_access", "Enter dates as YYMMDD (six digits).");
  return { number: num, birth: b, expiry: e };
}

/** The MRZ information the BAC and PACE keys are derived from. */
export function mrzInformation(access) {
  const { number, birth, expiry } = normalizeAccess(access);
  const n = number.padEnd(9, "<");
  return `${n}${checkDigit(n)}${birth}${checkDigit(birth)}${expiry}${checkDigit(expiry)}`;
}

/** KDF for 3DES keys: SHA-1(K ‖ counter), first 16 bytes, odd parity. */
export const kdf3des = (k, c) => withParity(sha1(concat(k, u32be(c))).subarray(0, 16));

export function bacKeys(access) {
  const seed = sha1(utf8(mrzInformation(access))).subarray(0, 16);
  return { seed, kEnc: kdf3des(seed, 1), kMac: kdf3des(seed, 2) };
}

/**
 * Run BAC over `send` (apdu object → { data, sw }). Returns session keys and SSC.
 * rndIfd / kIfd can be fixed for known-answer tests.
 */
export async function bac(send, access, { rndIfd = random(8), kIfd = random(16) } = {}) {
  const { kEnc, kMac } = bacKeys(access);
  const ch = await send({ cla: 0x00, ins: 0x84, p1: 0, p2: 0, le: 8 });
  if (ch.sw !== 0x9000 || ch.data.length !== 8) throw new ChipError("chip_refused", "The chip didn't start Basic Access Control.", ch.sw);
  const rndIc = ch.data;
  const eIfd = tdesCbc(kEnc, concat(rndIfd, rndIc, kIfd));
  const mIfd = retailMac(kMac, pad(eIfd, 8));
  const r = await send({ cla: 0x00, ins: 0x82, p1: 0, p2: 0, data: concat(eIfd, mIfd), le: 40 });
  if (r.sw !== 0x9000 || r.data.length !== 40) {
    throw new ChipError("access_denied", "These details don't open this chip. Check the document number, birth date and expiry date.", r.sw);
  }
  const eIc = r.data.subarray(0, 32), mIc = r.data.subarray(32);
  if (!equal(retailMac(kMac, pad(eIc, 8)), mIc)) throw new ChipError("bad_sm", "The chip's BAC answer failed its check.");
  const plain = tdesCbc(kEnc, eIc, true);
  if (!equal(plain.subarray(0, 8), rndIc) || !equal(plain.subarray(8, 16), rndIfd)) throw new ChipError("bad_sm", "The chip's BAC answer doesn't match this session.");
  const kIc = plain.subarray(16, 32);
  const seed = kIfd.map((v, i) => v ^ kIc[i]);
  return { cipher: "3des", ksEnc: kdf3des(seed, 1), ksMac: kdf3des(seed, 2), ssc: concat(rndIc.subarray(4), rndIfd.subarray(4)) };
}
