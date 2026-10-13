// A simulated passport chip: the card side of ICAO 9303 (BAC, PACE ECDH-GM
// with AES or 3DES, secure messaging, files, Active Authentication), built on
// a test passport from passport.js. It lets the reader in @humid/emrtd run
// end to end without hardware. Tests only.
import { util, des, cmac, SecureMessaging, bacKeys, CURVES, PROTOCOLS } from "@humid/emrtd";
import { paceKdf, pacePassword, blockCipher, authMac, publicKeyDo, randomScalar, bytesToBig, bigToBytes, curveSizes } from "../../packages/emrtd/src/pace.js";
import { kdf3des } from "../../packages/emrtd/src/bac.js";

const { concat, pad, unpad, increment, tlv, readTlv, readTlvs, decodeApdu, oidBytes, equal, random } = util;
const ok = (data = new Uint8Array(0)) => concat(data, Uint8Array.of(0x90, 0x00));
const sw = (n) => Uint8Array.of(n >> 8, n & 255);

/**
 * passport: from testPassport(). access: { number, birth, expiry } and/or { can }.
 * pace: null (BAC only) or { oid, parameterId } offered in EF.CardAccess.
 * bac: whether BAC also works (default true).
 */
export function simulatedChip({ passport, access, can, pace = null, bac = true, tamper = null }) {
  const files = new Map([[0x011e, tlv(0x60, concat(tlv(0x5f01, new TextEncoder().encode("0107")), tlv(0x5c, Uint8Array.of(0x61, 0x75, ...(passport.dg15 ? [0x6f] : []))))) ],
    [0x0101, Uint8Array.from(passport.dg1)], [0x011d, Uint8Array.from(passport.sod)]]);
  if (passport.dg15) files.set(0x010f, Uint8Array.from(passport.dg15));
  const cardAccess = pace ? tlv(0x31, tlv(0x30, concat(tlv(0x06, oidBytes(pace.oid)), tlv(0x02, Uint8Array.of(2)), tlv(0x02, Uint8Array.of(pace.parameterId))))) : null;

  let applet = false, ef = null, sm = null, rndIc = null, ps = null;
  let count = 0;

  function plain(a) {
    switch (a.ins) {
      case 0xa4: {
        if (a.p1 === 0x04) { if (!equal(a.data, Uint8Array.of(0xa0, 0, 0, 2, 0x47, 0x10, 1))) return sw(0x6a82); applet = true; ef = null; return ok(); }
        if (a.p1 === 0x02 || a.p1 === 0x00) {
          const fid = (a.data[0] << 8) | a.data[1];
          if (!applet || !files.has(fid)) return sw(0x6a82);
          if (!sm) return sw(0x6982);
          ef = fid; return ok();
        }
        return sw(0x6a86);
      }
      case 0xb0: {
        if (a.p1 & 0x80) { // short file id
          const sfi = a.p1 & 0x1f;
          if (sfi === 0x1c && cardAccess) return ok(cardAccess.subarray(a.p2, a.p2 + (a.le || 256)));
          return sw(0x6a82);
        }
        if (!sm) return sw(0x6982);
        if (ef == null) return sw(0x6986);
        const off = ((a.p1 & 0x7f) << 8) | a.p2;
        const f = files.get(ef);
        if (off > f.length) return sw(0x6b00);
        return ok(f.subarray(off, off + (a.le || 256)));
      }
      case 0x84: if (!bac) return sw(0x6d00); rndIc = random(8); return ok(rndIc);
      case 0x82: {
        if (!bac || !rndIc) return sw(0x6985);
        const { kEnc, kMac } = bacKeys(access);
        const e = a.data.subarray(0, 32), m = a.data.subarray(32, 40);
        if (!equal(des.retailMac(kMac, pad(e, 8)), m)) return sw(0x6300);
        const s = des.tdesCbc(kEnc, e, true);
        if (!equal(s.subarray(8, 16), rndIc)) return sw(0x6300);
        const rndIfd = s.subarray(0, 8), kIfd = s.subarray(16, 32), kIc = random(16);
        const r = des.tdesCbc(kEnc, concat(rndIc, rndIfd, kIc));
        const seed = kIfd.map((v, i) => v ^ kIc[i]);
        const keys = { cipher: "3des", ksEnc: kdf3des(seed, 1), ksMac: kdf3des(seed, 2), ssc: concat(rndIc.subarray(4), rndIfd.subarray(4)) };
        const answer = ok(concat(r, des.retailMac(kMac, pad(r, 8))));
        sm = new SecureMessaging(keys);
        return answer;
      }
      case 0x22: {
        if (!pace) return sw(0x6d00);
        const t = readTlvs(a.data);
        ps = { oid: pace.oid, paramId: pace.parameterId, pwd: t.get(0x83)?.[0] };
        return ok();
      }
      case 0x86: return paceStep(a);
      case 0x88: {
        if (!sm) return sw(0x6982);
        const sig = passport.answer(a.data);
        return sig ? ok(sig) : sw(0x6d00);
      }
      default: return sw(0x6d00);
    }
  }

  function paceStep(a) {
    if (!ps) return sw(0x6985);
    const proto = PROTOCOLS[ps.oid], curve = CURVES[ps.paramId], G = curve.Point.BASE;
    const inner = readTlvs(readTlv(a.data, 0).value);
    const ga = (t) => ok(tlv(0x7c, t));
    if (!ps.s) {
      const pwd = ps.pwd === 2 ? { can } : access;
      if (ps.pwd === 2 && !can) return sw(0x6a88);
      ps.s = random(proto.cipher === "aes" ? 16 : 8);
      return ga(tlv(0x80, blockCipher(proto, paceKdf(pacePassword(pwd), 3, proto), ps.s, false)));
    }
    if (inner.has(0x81)) {
      const skMap = randomScalar(curve);
      const H = curve.Point.fromBytes(inner.get(0x81)).multiply(skMap);
      ps.G = G.multiply(bytesToBig(ps.s) % curve.Point.Fn.ORDER).add(H);
      return ga(tlv(0x82, G.multiply(skMap).toBytes(false)));
    }
    if (inner.has(0x83)) {
      ps.pkIfd = inner.get(0x83);
      const sk = randomScalar(curve);
      ps.pkIc = ps.G.multiply(sk).toBytes(false);
      const K = bigToBytes(curve.Point.fromBytes(ps.pkIfd).multiply(sk).toAffine().x, curveSizes(curve));
      ps.ksEnc = paceKdf(K, 1, proto); ps.ksMac = paceKdf(K, 2, proto);
      return ga(tlv(0x84, ps.pkIc));
    }
    if (inner.has(0x85)) {
      if (!equal(inner.get(0x85), authMac(proto, ps.ksMac, publicKeyDo(ps.oid, ps.pkIc)))) { ps = null; return sw(0x6300); }
      const t = authMac(proto, ps.ksMac, publicKeyDo(ps.oid, ps.pkIfd));
      const answer = ga(tlv(0x86, t));
      sm = new SecureMessaging({ cipher: proto.cipher, ksEnc: ps.ksEnc, ksMac: ps.ksMac, ssc: new Uint8Array(proto.cipher === "aes" ? 16 : 8) });
      ps = null;
      return answer;
    }
    return sw(0x6a80);
  }

  /** Card-side secure messaging: check and open the command, protect the answer. */
  function protectedCommand(raw) {
    const a = decodeApdu(raw);
    if ((a.cla & 0x0c) !== 0x0c) { sm = null; return plain(a); } // a plain command ends the session
    increment(sm.ssc);
    const t = readTlvs(a.data);
    const do87 = t.get(0x87), do97 = t.get(0x97), do8e = t.get(0x8e);
    const m = concat(pad(Uint8Array.of(a.cla, a.ins, a.p1, a.p2), sm.block), do87 ? tlv(0x87, do87) : new Uint8Array(0), do97 ? tlv(0x97, do97) : new Uint8Array(0));
    if (!do8e || !equal(sm.mac(m), do8e)) { sm = null; return sw(0x6988); }
    const data = do87 ? unpad(sm.decrypt(do87.subarray(1))) : new Uint8Array(0);
    const le = do97 ? (do97.length === 1 ? do97[0] || 256 : (do97[0] << 8) | do97[1]) : null;
    const r = plain({ cla: a.cla & ~0x0c, ins: a.ins, p1: a.p1, p2: a.p2, data, le });
    const s = sm; // (plain() may have ended it)
    if (!s) return r;
    increment(s.ssc);
    const body = r.subarray(0, r.length - 2), status = r.subarray(r.length - 2);
    const r87 = body.length ? tlv(0x87, concat(Uint8Array.of(1), s.encrypt(pad(body, s.block)))) : new Uint8Array(0);
    const r99 = tlv(0x99, status);
    let mac = s.mac(concat(r87, r99));
    if (tamper === "mac" && ++count > 3) mac = mac.map((x) => x ^ 1);
    return concat(r87, r99, tlv(0x8e, mac), Uint8Array.of(0x90, 0x00));
  }

  return {
    transceive: async (raw) => (sm ? protectedCommand(raw) : plain(decodeApdu(raw))),
    get secured() { return !!sm; },
  };
}

/** Wrap a transport so long answers come back in pieces (61XX → GET RESPONSE), as some readers do. */
export function chained(transport, size = 64) {
  let rest = null;
  return {
    async transceive(raw) {
      if (raw[1] === 0xc0 && rest) {
        const part = rest.subarray(0, size); rest = rest.subarray(size);
        const done = !rest.length; const tail = done ? rest = null : null;
        return concat(part, done ? Uint8Array.of(0x90, 0) : Uint8Array.of(0x61, Math.min(255, rest.length)));
      }
      const r = await transport.transceive(raw);
      const body = r.subarray(0, r.length - 2);
      if (body.length <= size || r[r.length - 2] !== 0x90) return r;
      rest = body.subarray(size);
      return concat(body.subarray(0, size), Uint8Array.of(0x61, Math.min(255, rest.length)));
    },
  };
}
