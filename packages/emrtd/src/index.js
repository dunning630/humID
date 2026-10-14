// @humid/emrtd — reads a passport or ID card chip (ICAO 9303 eMRTD) over any
// APDU transport. The phone (CoreNFC, Android IsoDep) or a desktop USB reader
// (PC/SC) only moves bytes; everything else happens here, the same on every
// platform:
//
//   1. access    PACE if the chip offers a variant we support (EF.CardAccess),
//                otherwise BAC. Keys come from the MRZ details or the CAN.
//   2. files     EF.COM, DG1 (MRZ), DG15 (Active Authentication key), EF.SOD,
//                over secure messaging. DG2 (the photo) is never read.
//   3. liveness  with a nonce from the server, INTERNAL AUTHENTICATE: the chip
//                signs it with its private key, proving it's the real chip.
//
// The server checks everything (passive and active authentication); this
// module never decides whether a document is genuine. Nothing read here is
// stored on the device.
import { SecureMessaging, chipMessage } from "./sm.js";
import { bac, normalizeAccess } from "./bac.js";
import { pace, parseCardAccess, choosePace } from "./pace.js";
import { encodeApdu, swOf, bodyOf, concat, tlvTotalLength, readTlvs, ChipError } from "./util.js";

export { ChipError } from "./util.js";
export { normalizeAccess, mrzInformation, checkDigit, bacKeys, bac } from "./bac.js";
export { pace, parseCardAccess, choosePace, PROTOCOLS, CURVES } from "./pace.js";
export { SecureMessaging } from "./sm.js";
export * as util from "./util.js";
export * as des from "./des.js";
export { cmac, aesCbc } from "./cmac.js";

export const AID = Uint8Array.of(0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01);
export const FILES = { com: 0x011e, dg1: 0x0101, dg2: 0x0102, dg14: 0x010e, dg15: 0x010f, sod: 0x011d, cardAccess: 0x011c };
const CHUNK = 0xa0; // conservative: fits every reader and secure-messaging overhead

/**
 * Raw APDU exchange with ISO 7816 response chaining (61XX → GET RESPONSE) and
 * wrong-length retry (6CXX). transport.transceive(bytes) → bytes incl. SW.
 */
async function exchange(transport, apdu) {
  let r = await transport.transceive(encodeApdu(apdu));
  if (r.length < 2) throw new ChipError("lost", "Lost contact with the chip. Hold the document still and try again.");
  if ((swOf(r) & 0xff00) === 0x6c00) r = await transport.transceive(encodeApdu({ ...apdu, le: swOf(r) & 0xff || 256 }));
  let body = bodyOf(r);
  while ((swOf(r) & 0xff00) === 0x6100) {
    r = await transport.transceive(encodeApdu({ cla: 0x00, ins: 0xc0, p1: 0, p2: 0, le: swOf(r) & 0xff || 256 }));
    body = concat(body, bodyOf(r));
  }
  return { data: body, sw: swOf(r) };
}

/** A session: plain until `secure()`, then every command goes through secure messaging. */
class Session {
  constructor(transport) { this.transport = transport; this.sm = null; }
  secure(keys) { this.sm = new SecureMessaging(keys); }
  async send(apdu) {
    if (!this.sm) return exchange(this.transport, apdu);
    const r = await exchange(this.transport, this.sm.wrap(apdu));
    return this.sm.unwrap(r.data, r.sw);
  }
  async ok(apdu, what) {
    const r = await this.send(apdu);
    if (r.sw !== 0x9000) throw new ChipError(r.sw === 0x6a82 ? "no_file" : "chip_refused", `${what}: ${chipMessage(r.sw)}`, r.sw);
    return r.data;
  }
  selectApplet() { return this.ok({ cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x0c, data: AID }, "Opening the passport application"); }
  selectFile(fid) { return this.ok({ cla: 0x00, ins: 0xa4, p1: 0x02, p2: 0x0c, data: Uint8Array.of(fid >> 8, fid & 255) }, "Selecting a file"); }

  /** Read a whole elementary file: its TLV header says how long it is. */
  async readFile(fid, onBytes) {
    await this.selectFile(fid);
    const head = await this.ok({ cla: 0x00, ins: 0xb0, p1: 0, p2: 0, le: 8 }, "Reading");
    const total = tlvTotalLength(head);
    if (!total || total > 64 * 1024) throw new ChipError("bad_tlv", "A file on the chip has an impossible length.");
    let out = head.subarray(0, Math.min(head.length, total));
    while (out.length < total) {
      const off = out.length;
      const part = await this.ok({ cla: 0x00, ins: 0xb0, p1: (off >> 8) & 0x7f, p2: off & 255, le: Math.min(CHUNK, total - off) }, "Reading");
      if (!part.length) throw new ChipError("bad_tlv", "The chip stopped sending a file early.");
      out = concat(out, part);
      onBytes?.(out.length, total);
    }
    return out;
  }
}

/** EF.CardAccess, readable without any key: which PACE options the chip offers (or null). */
async function readCardAccess(s) {
  const read = () => s.send({ cla: 0x00, ins: 0xb0, p1: 0x9c, p2: 0x00, le: 256 }); // READ BINARY via short file id 0x1C
  try {
    let r = await read();
    if (r.sw === 0x9000 && r.data.length) return r.data;
    // iPhones select the passport application before handing over the chip; EF.CardAccess
    // lives in the master file, so select that and try once more.
    await s.send({ cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x0c, data: Uint8Array.of(0x3f, 0x00) });
    r = await read();
    return r.sw === 0x9000 && r.data.length ? r.data : null;
  } catch { return null; }
}

/**
 * Read a document.
 *   transport  { transceive(Uint8Array): Promise<Uint8Array> }
 *   access     { number, birth, expiry } (YYMMDD) or { can }
 *   nonce      optional server challenge for Active Authentication (8 bytes)
 *   onProgress ({ step, fraction, message })
 * Returns { dg1, sod, dg15?, com, aaSignature?, access: "PACE …" | "BAC" }.
 */
export async function readDocument(transport, { access, nonce, onProgress = () => {}, preferBac = false } = {}) {
  const useCan = !!access?.can;
  if (!useCan) normalizeAccess(access || {});
  const s = new Session(transport);
  const step = (stepName, fraction, message) => onProgress({ step: stepName, fraction, message });

  step("access", 0.05, "Opening a secure connection to the chip…");
  let method = "BAC";
  const ca = preferBac ? null : await readCardAccess(s);
  const info = ca ? (() => { try { return choosePace(parseCardAccess(ca)); } catch { return null; } })() : null;
  if (info) {
    const keys = await pace((a) => s.send(a), access, info);
    s.secure(keys);
    method = `PACE ${keys.protocol}`;
    await s.selectApplet();
  } else {
    if (useCan) throw new ChipError("needs_mrz", "This document needs the details from its machine-readable zone, not the CAN.");
    await s.selectApplet();
    s.secure(await bac((a) => s.send(a), access));
  }

  step("files", 0.25, "Reading the identity page data…");
  const com = await s.readFile(FILES.com);
  const tags = (() => { try { return [...(readTlvs(readTlvs(com).get(0x60) || new Uint8Array(0)).get(0x5c) || [])]; } catch { return []; } })();
  const dg1 = await s.readFile(FILES.dg1);
  step("files", 0.4, "Reading the issuing country's signature…");
  const sod = await s.readFile(FILES.sod, (n, t) => step("files", 0.4 + 0.35 * (n / t), "Reading the issuing country's signature…"));
  let dg15 = null;
  if (!tags.length || tags.includes(0x6f)) {
    try { dg15 = await s.readFile(FILES.dg15); } catch (e) { if (e.code !== "no_file") throw e; }
  }

  let aaSignature = null;
  if (nonce) {
    if (!dg15) throw new ChipError("no_chip_proof", "This chip can't prove it's present. Verify at a HumID station instead.");
    step("liveness", 0.85, "Asking the chip to prove it's genuine…");
    aaSignature = await s.ok({ cla: 0x00, ins: 0x88, p1: 0, p2: 0, data: Uint8Array.from(nonce), le: 256 }, "Chip proof");
  }
  step("done", 1, "Done. You can move the document away.");
  return { com, dg1, sod, ...(dg15 ? { dg15 } : {}), ...(aaSignature ? { aaSignature } : {}), access: method };
}
