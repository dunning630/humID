// ICAO 9303 part 11 secure messaging: every command and answer after BAC or
// PACE is encrypted (DO87, or DO85 for odd instructions such as READ BINARY
// with a long offset) and MACed (DO8E) with session keys, and a send
// sequence counter (SSC) makes each one unique, so nothing can be replayed,
// reordered or altered between the phone and the chip.
//
//   3DES  (BAC, PACE-3DES)  two-key 3DES-CBC with IV 0, ISO 9797-1 MAC alg 3, 8-byte blocks
//   AES   (PACE-AES)        AES-CBC with IV = AES(KSenc, SSC), AES-CMAC truncated to 8 bytes
import { tdesCbc, retailMac } from "./des.js";
import { aesCbc, aesEcbBlock, cmac } from "./cmac.js";
import { concat, pad, unpad, increment, tlv, readTlvs, equal, wipe, ChipError } from "./util.js";

export class SecureMessaging {
  /** cipher: "3des" | "aes"; ssc: initial counter (8 bytes for 3DES, 16 for AES). */
  constructor({ cipher, ksEnc, ksMac, ssc }) {
    this.cipher = cipher;
    this.ksEnc = ksEnc; this.ksMac = ksMac;
    this.ssc = Uint8Array.from(ssc);
    this.block = cipher === "aes" ? 16 : 8;
  }

  mac(data) {
    const n = pad(concat(this.ssc, data), this.block);
    return this.cipher === "aes" ? cmac(this.ksMac, n).subarray(0, 8) : retailMac(this.ksMac, n);
  }
  #iv() { return this.cipher === "aes" ? aesEcbBlock(this.ksEnc, this.ssc) : new Uint8Array(8); }
  encrypt(data) { return this.cipher === "aes" ? aesCbc(this.ksEnc, data, false, this.#iv()) : tdesCbc(this.ksEnc, data); }
  decrypt(data) { return this.cipher === "aes" ? aesCbc(this.ksEnc, data, true, this.#iv()) : tdesCbc(this.ksEnc, data, true); }

  /** Protect a command. In: { cla, ins, p1, p2, data?, le? }. Out: the same shape, ready to encode. */
  wrap({ cla, ins, p1, p2, data, le }) {
    increment(this.ssc);
    const header = Uint8Array.of(cla | 0x0c, ins, p1, p2);
    // Odd instructions carry BER-TLV data: DO85, without the padding-indicator byte.
    const do87 = !(data && data.length) ? new Uint8Array(0)
      : ins & 1 ? tlv(0x85, this.encrypt(pad(data, this.block)))
      : tlv(0x87, concat(Uint8Array.of(1), this.encrypt(pad(data, this.block))));
    const do97 = le != null ? tlv(0x97, le > 256 ? Uint8Array.of((le >> 8) & 255, le & 255) : Uint8Array.of(le === 256 ? 0 : le)) : new Uint8Array(0);
    const m = concat(pad(header, this.block), do87, do97);
    const do8e = tlv(0x8e, this.mac(m));
    return { cla: cla | 0x0c, ins, p1, p2, data: concat(do87, do97, do8e), le: le > 256 ? 65536 : 256 };
  }

  /** Check and open a protected answer (body without SW). Returns { data, sw }. */
  unwrap(body, outerSw) {
    increment(this.ssc);
    if (!body.length) throw new ChipError("chip_refused", chipMessage(outerSw), outerSw);
    const t = readTlvs(body);
    const do87 = t.get(0x87), do85 = t.get(0x85), do99 = t.get(0x99), do8e = t.get(0x8e);
    if (!do99 || !do8e) throw new ChipError("bad_sm", "The chip's answer wasn't protected. Reading stopped.", outerSw);
    if (do99.length !== 2 || do8e.length !== 8 || (do87 && do85)) throw new ChipError("bad_sm", "The chip's answer was malformed. Reading stopped.", outerSw);
    const k = concat(do87 ? tlv(0x87, do87) : do85 ? tlv(0x85, do85) : new Uint8Array(0), tlv(0x99, do99));
    if (!equal(this.mac(k), do8e)) throw new ChipError("bad_sm", "The chip's answer failed its integrity check. Reading stopped.", outerSw);
    const sw = (do99[0] << 8) | do99[1];
    // DO87 is a padding-content indicator (01) then whole cipher blocks; DO85 is whole blocks.
    const ct = do87 ? do87.subarray(1) : do85;
    if (do87 && do87[0] !== 0x01) throw new ChipError("bad_sm", "The chip's answer was malformed. Reading stopped.", outerSw);
    if (ct && (ct.length === 0 || ct.length % this.block)) throw new ChipError("bad_sm", "The chip's answer was malformed. Reading stopped.", outerSw);
    const data = ct ? unpad(this.decrypt(ct)) : new Uint8Array(0);
    return { data, sw };
  }

  /** Forget the session keys (when reading is over, or failed). */
  wipe() { wipe(this.ksEnc, this.ksMac, this.ssc); }
}

/** What an ISO 7816 status word means to a person. */
export function chipMessage(sw) {
  switch (sw) {
    case 0x6300: return "The chip refused the access details. Check them and try again.";
    case 0x6982: return "The chip needs a secure session first.";
    case 0x6985: return "The chip refused that step.";
    case 0x6a82: return "The chip doesn't have that file.";
    case 0x6a86: case 0x6b00: return "The chip didn't accept that request.";
    case 0x6d00: case 0x6e00: return "This chip doesn't support that command.";
    case 0x6988: return "The chip found an error in the secure session.";
    default: return `The chip answered ${sw?.toString(16).toUpperCase().padStart(4, "0") || "nothing"}.`;
  }
}
