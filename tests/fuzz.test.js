// Fuzzing the parsers that read untrusted bytes: QR codes from the camera, chip
// answers (BER-TLV, secure messaging, EF.CardAccess, EF.SOD) and, on the server,
// the SOD and DG1 a phone sends. Seeded, so a failure can be replayed:
//   FUZZ_SEED=1234 FUZZ_N=20000 node --test tests/fuzz.test.js
// Each parser must either return something well-formed or refuse with its own
// error type: never another exception (a TypeError on the server is a 500), never hang.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseQr, qrPayload, keyCode, LINK_LABEL, QR_MAX, QR_KINDS } from "@humid/recovery";
import { util, SecureMessaging, ChipError, parseCardAccess } from "@humid/emrtd";
import { parseSod, passiveAuth, readDg1, AnchorError } from "@humid/anchor";
import { sodHashes, checkIntegrity, tlvChildren } from "@humid/idscan";
import { testCsca, testPassport } from "./support/passport.js";

const SEED = Number(process.env.FUZZ_SEED || 0x5eed);
const N = Number(process.env.FUZZ_N || 3000);

/** mulberry32: small, fast, seedable. */
function rng(seed) {
  let a = seed >>> 0;
  const next = () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const int = (n) => Math.floor(next() * n);
  return {
    int,
    bytes: (n) => Uint8Array.from({ length: n }, () => int(256)),
    pick: (xs) => xs[int(xs.length)],
    /** A few random edits: flip, insert, delete, truncate, extend, or splice in a length byte. */
    mutate(src) {
      let b = Array.from(src);
      for (let k = 1 + int(4); k > 0; k--) {
        const i = int(Math.max(1, b.length));
        switch (int(7)) {
          case 0: if (b.length) b[i] ^= 1 << int(8); break;
          case 1: b.splice(i, 0, int(256)); break;
          case 2: b.splice(i, 1); break;
          case 3: b = b.slice(0, i); break;
          case 4: b.push(...Array.from({ length: int(8) }, () => int(256))); break;
          case 5: if (b.length) b[i] = this.pick([0x00, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0xff]); break;
          default: if (b.length) b[i] = int(256);
        }
      }
      return Uint8Array.from(b);
    },
  };
}

/** Run fn on every input; anything thrown must pass `allowed`. Returns how many were refused. */
function fuzz(name, inputs, fn, allowed) {
  let refused = 0;
  for (const [i, x] of inputs.entries()) {
    try { fn(x); }
    catch (e) {
      if (!allowed(e)) assert.fail(`${name}: input ${i} (seed ${SEED}) threw ${e?.constructor?.name}: ${e?.message}\n${Buffer.from(x?.buffer ? x : Buffer.from(String(x))).toString("hex").slice(0, 400)}`);
      refused++;
    }
  }
  return refused;
}

test("fuzz: QR parser returns null or a well-formed code, nothing else", () => {
  const r = rng(SEED);
  const good = qrPayload("link", keyCode(LINK_LABEL, r.bytes(32)), Date.now() + 600_000);
  const alphabet = "HUMID:0123456789ABCDEFGHJKMNPQRSTVWXYZ-<>/?&=%._ \n‮\u0000é";
  const inputs = [];
  for (let i = 0; i < N; i++) {
    if (i % 3 === 0) inputs.push(Array.from({ length: r.int(80) }, () => r.pick([...alphabet])).join(""));
    else inputs.push(new TextDecoder().decode(r.mutate(new TextEncoder().encode(good))));
  }
  let parsed = 0;
  fuzz("parseQr", inputs, (t) => {
    const q = parseQr(t);
    if (q === null) return;
    parsed++;
    assert.ok(t.length <= QR_MAX);
    assert.ok(Object.keys(QR_KINDS).includes(q.kind));
    assert.match(q.code, /^[0-9A-HJKMNP-TV-Z]{12}$/);
    assert.ok(Number.isSafeInteger(q.expiresAt) && q.expiresAt > 0);
    assert.equal(qrPayload(q.kind, q.code, q.expiresAt), t, "only the canonical form parses");
  }, () => false);
  assert.ok(parsed < N, "most mutations are refused");
});

test("fuzz: BER-TLV reading stays inside the bytes and refuses with ChipError only", () => {
  const r = rng(SEED + 1);
  const seeds = [
    util.tlv(0x61, util.tlv(0x5f1f, new Uint8Array(88).fill(0x3c))),
    util.tlv(0x7f49, util.concat(util.tlv(0x06, Uint8Array.of(4, 0, 127, 0, 7)), util.tlv(0x86, r.bytes(65)))),
    util.concat(util.tlv(0x87, r.bytes(17)), util.tlv(0x99, Uint8Array.of(0x90, 0)), util.tlv(0x8e, r.bytes(8))),
    util.tlv(0x77, r.bytes(300)),
  ];
  const inputs = Array.from({ length: N }, (_, i) => (i % 4 === 0 ? r.bytes(r.int(64)) : r.mutate(r.pick(seeds))));
  fuzz("readTlv/readTlvs/tlvTotalLength", inputs, (b) => {
    const total = util.tlvTotalLength(b);
    if (total !== null) assert.ok(Number.isInteger(total) && total >= 2 && total < 2 ** 25);
    let p = 0;
    while (p < b.length) {
      const t = util.readTlv(b, p);
      assert.ok(t.end > p && t.end <= b.length && t.value.length === t.end - p - t.headerLength);
      assert.ok(t.tag >= 0 && t.tag < 2 ** 24);
      p = t.end;
    }
    util.readTlvs(b);
  }, (e) => e instanceof ChipError);
});

test("fuzz: a secure-messaging answer from a hostile chip is refused, never mis-read", () => {
  const r = rng(SEED + 2);
  const keys = { cipher: "aes", ksEnc: r.bytes(16), ksMac: r.bytes(16), ssc: new Uint8Array(16) };
  const valid = util.concat(util.tlv(0x87, util.concat(Uint8Array.of(1), r.bytes(32))), util.tlv(0x99, Uint8Array.of(0x90, 0)), util.tlv(0x8e, r.bytes(8)));
  const inputs = Array.from({ length: N }, (_, i) => (i % 3 === 0 ? r.bytes(r.int(80)) : r.mutate(valid)));
  let accepted = 0;
  fuzz("SecureMessaging.unwrap", inputs, (b) => { new SecureMessaging(keys).unwrap(b, 0x9000); accepted++; }, (e) => e instanceof ChipError);
  assert.equal(accepted, 0, "without the MAC key nothing gets through");
});

test("fuzz: EF.CardAccess from a chip (read before any key exists)", () => {
  const r = rng(SEED + 3);
  const info = util.tlv(0x31, util.tlv(0x30, util.concat(util.tlv(0x06, util.oidBytes("0.4.0.127.0.7.2.2.4.2.2")), util.tlv(0x02, Uint8Array.of(2)), util.tlv(0x02, Uint8Array.of(13)))));
  const inputs = Array.from({ length: N }, (_, i) => (i % 4 === 0 ? r.bytes(r.int(48)) : r.mutate(info)));
  fuzz("parseCardAccess", inputs, (b) => parseCardAccess(b), (e) => e instanceof ChipError);
});

test("fuzz: the server's SOD, DG1 and passive authentication refuse with AnchorError only", () => {
  const r = rng(SEED + 4);
  const csca = testCsca("Fuzz Country");
  const p = testPassport({ csca, aaKind: "ec" });
  const n = Math.max(300, Math.floor(N / 5)); // each passive authentication is a few signature checks
  const sods = Array.from({ length: n }, () => r.mutate(p.sod));
  fuzz("parseSod", sods, (b) => parseSod(b), (e) => e instanceof AnchorError);
  fuzz("passiveAuth(sod)", sods, (b) => passiveAuth({ dg1: p.dg1, sod: b, dg15: p.dg15 }, { cscas: [csca.pem] }), (e) => e instanceof AnchorError);
  const dg1s = Array.from({ length: n }, () => r.mutate(p.dg1));
  fuzz("readDg1", dg1s, (b) => readDg1(b), (e) => e instanceof AnchorError);
  fuzz("passiveAuth(dg1)", dg1s.slice(0, 100), (b) => passiveAuth({ dg1: b, sod: p.sod }, { cscas: [csca.pem] }), (e) => e instanceof AnchorError);
  // the genuine chip still passes
  assert.ok(passiveAuth(p, { cscas: [csca.pem] }));
});

test("fuzz: the phone's own SOD reading (for the vault copy) never crashes on a bad chip", () => {
  const r = rng(SEED + 5);
  const csca = testCsca("Fuzz Country 2");
  const p = testPassport({ csca });
  const inputs = Array.from({ length: Math.max(300, Math.floor(N / 3)) }, () => r.mutate(p.sod));
  fuzz("sodHashes/checkIntegrity", inputs, (b) => {
    const res = checkIntegrity(b, { 1: p.dg1 });
    assert.equal(typeof res.ok, "boolean");
    sodHashes(b);
    tlvChildren(b);
  }, (e) => e instanceof Error && !(e instanceof RangeError && /call stack/i.test(e.message)));
});
