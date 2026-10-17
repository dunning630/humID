// Reading passport chips: ICAO 9303 known-answer tests for BAC and secure
// messaging, then BAC and every supported PACE variant end to end against a
// simulated chip, checked by the server's own passive and active authentication.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readDocument, bacKeys, mrzInformation, bac, SecureMessaging, util, ChipError } from "@humid/emrtd";
import { passiveAuth, activeAuth } from "@humid/anchor";
import { testCsca, testPassport } from "./support/passport.js";
import { simulatedChip, chained } from "./support/chip.js";

const { fromHex, hex, encodeApdu } = util;
const csca = testCsca("HumID Chip Country");
const ACCESS = { number: "X4K90T2R1", birth: "880214", expiry: "330630" };
const MRZ = { number: ACCESS.number, birth: ACCESS.birth, expiry: ACCESS.expiry, surname: "OKAFOR", given: "ADA" };

/* ---------------- ICAO 9303 part 11, worked example (appendix D) ---------------- */

test("BAC keys, mutual authentication and secure messaging match the ICAO worked example", async () => {
  const acc = { number: "L898902C", birth: "690806", expiry: "940623" };
  assert.equal(mrzInformation(acc), "L898902C<369080619406236");
  const k = bacKeys(acc);
  assert.equal(hex(k.seed), "239ab9cb282daf66231dc5a4df6bfbae");
  assert.equal(hex(k.kEnc), "ab94fdecf2674fdfb9b391f85d7f76f2");
  assert.equal(hex(k.kMac), "7962d9ece03d1acd4c76089dce131543");
  const send = async (a) => {
    if (a.ins === 0x84) return { data: fromHex("4608F91988702212"), sw: 0x9000 };
    assert.equal(hex(a.data), "72c29c2371cc9bdb65b779b8e8d37b29ecc154aa56a8799fae2f498f76ed92f25f1448eea8ad90a7");
    return { data: fromHex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449"), sw: 0x9000 };
  };
  const s = await bac(send, acc, { rndIfd: fromHex("781723860C06C226"), kIfd: fromHex("0B795240CB7049B01C19B33E32804F0B") });
  assert.equal(hex(s.ksEnc), "979ec13b1cbfe9dcd01ab0fed307eae5");
  assert.equal(hex(s.ksMac), "f1cb1f1fb5adf208806b89dc579dc1f8");
  assert.equal(hex(s.ssc), "887022120c06c226");
  const sm = new SecureMessaging(s);
  assert.equal(hex(encodeApdu(sm.wrap({ cla: 0, ins: 0xa4, p1: 2, p2: 0x0c, data: fromHex("011E") }))), "0ca4020c158709016375432908c044f68e08bf8b92d635ff24f800");
  assert.deepEqual(sm.unwrap(fromHex("990290008E08FA855A5D4C50A8ED"), 0x9000).sw, 0x9000);
  assert.throws(() => sm.unwrap(fromHex("990290008E08FA855A5D4C50A8EE"), 0x9000), (e) => e.code === "bad_sm");
});

/* ---------------- end to end against a simulated chip ---------------- */

const PACE = "0.4.0.127.0.7.2.2.4.2";
const VARIANTS = [
  { name: "BAC", pace: null },
  { name: "PACE ECDH-GM AES-128 · Brainpool P-256", pace: { oid: `${PACE}.2`, parameterId: 13 } },
  { name: "PACE ECDH-GM AES-128 · NIST P-256", pace: { oid: `${PACE}.2`, parameterId: 12 } },
  { name: "PACE ECDH-GM AES-256 · Brainpool P-384", pace: { oid: `${PACE}.4`, parameterId: 16 } },
  { name: "PACE ECDH-GM AES-192 · NIST P-384", pace: { oid: `${PACE}.3`, parameterId: 15 } },
  { name: "PACE ECDH-GM 3DES · Brainpool P-256", pace: { oid: `${PACE}.1`, parameterId: 13 } },
];

for (const v of VARIANTS) {
  test(`read a chip with ${v.name}; the server verifies it and the chip's live answer`, async () => {
    const passport = testPassport({ csca, mrz: MRZ, aaKind: v.name.includes("3DES") ? "ec" : "rsa" });
    const chip = simulatedChip({ passport, access: ACCESS, pace: v.pace });
    const nonce = randomBytes(8);
    const steps = [];
    const r = await readDocument(chip, { access: { ...ACCESS, number: ACCESS.number.toLowerCase() }, nonce, onProgress: (p) => steps.push(p.step) });
    assert.match(r.access, v.pace ? /^PACE / : /^BAC$/);
    assert.deepEqual(Buffer.from(r.dg1), Buffer.from(passport.dg1));
    assert.deepEqual(Buffer.from(r.sod), Buffer.from(passport.sod));
    const ok = passiveAuth({ dg1: r.dg1, sod: r.sod, dg15: r.dg15 }, { cscas: [csca.pem] });
    assert.equal(ok.mrz.surname, "OKAFOR");
    assert.equal(activeAuth({ dg15: r.dg15, nonce, signature: r.aaSignature }), true);
    assert.deepEqual([...new Set(steps)], ["access", "files", "liveness", "done"]);
  });
}

test("PACE with the CAN printed on an ID card", async () => {
  const passport = testPassport({ csca, mrz: MRZ });
  const chip = simulatedChip({ passport, access: ACCESS, can: "123456", pace: { oid: `${PACE}.2`, parameterId: 13 } });
  const r = await readDocument(chip, { access: { can: "123 456" } });
  assert.match(r.access, /^PACE/);
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS, can: "123456", pace: { oid: `${PACE}.2`, parameterId: 13 } }), { access: { can: "654321" } }), (e) => e.code === "access_denied");
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS }), { access: { can: "123456" } }), (e) => e.code === "needs_mrz");
});

test("wrong details are refused, with BAC and with PACE", async () => {
  const passport = testPassport({ csca, mrz: MRZ });
  const wrong = { ...ACCESS, birth: "880215" };
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS }), { access: wrong }), (e) => e instanceof ChipError && e.code === "access_denied");
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS, pace: { oid: `${PACE}.2`, parameterId: 12 } }), { access: wrong }), (e) => e.code === "access_denied");
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS }), { access: { number: "", birth: "1", expiry: "x" } }), (e) => e.code === "bad_access");
});

test("a tampered answer stops the read; long answers arrive in pieces; no AA key means no live proof", async () => {
  const passport = testPassport({ csca, mrz: MRZ });
  await assert.rejects(readDocument(simulatedChip({ passport, access: ACCESS, tamper: "mac" }), { access: ACCESS }), (e) => e.code === "bad_sm");
  const r = await readDocument(chained(simulatedChip({ passport, access: ACCESS, pace: { oid: `${PACE}.2`, parameterId: 13 } }), 40), { access: ACCESS, nonce: randomBytes(8) });
  assert.deepEqual(Buffer.from(r.sod), Buffer.from(passport.sod));
  const noAa = testPassport({ csca, mrz: MRZ, aaKind: null });
  const plain = await readDocument(simulatedChip({ passport: noAa, access: ACCESS }), { access: ACCESS });
  assert.equal(plain.dg15, undefined);
  await assert.rejects(readDocument(simulatedChip({ passport: noAa, access: ACCESS }), { access: ACCESS, nonce: randomBytes(8) }), (e) => e.code === "no_chip_proof");
});

/* ---------------- a hostile chip ---------------- */

test("secure messaging refuses malformed answers even with a valid MAC", () => {
  const keys = { cipher: "3des", ksEnc: randomBytes(16), ksMac: randomBytes(16), ssc: new Uint8Array(8) };
  const chip = new SecureMessaging(keys), reader = new SecureMessaging(keys);
  // The chip side builds an answer with the right MAC around whatever DO87 it likes.
  const answer = (do87, do99 = Uint8Array.of(0x90, 0)) => {
    util.increment(chip.ssc);
    const k = util.concat(do87 ? util.tlv(0x87, do87) : new Uint8Array(0), util.tlv(0x99, do99));
    return util.concat(k, util.tlv(0x8e, chip.mac(k)));
  };
  const ct = chip.encrypt(util.pad(Uint8Array.of(1, 2, 3), 8));
  assert.deepEqual(reader.unwrap(answer(util.concat(Uint8Array.of(1), ct)), 0x9000).data, Uint8Array.of(1, 2, 3));
  for (const [what, do87, do99] of [
    ["no padding indicator", util.concat(Uint8Array.of(2), ct)],
    ["not whole blocks", util.concat(Uint8Array.of(1), ct.subarray(0, 7))],
    ["no ciphertext", Uint8Array.of(1)],
    ["a 3-byte status", util.concat(Uint8Array.of(1), ct), Uint8Array.of(0x90, 0, 0)],
  ]) assert.throws(() => reader.unwrap(answer(do87, do99), 0x9000), (e) => e instanceof ChipError && e.code === "bad_sm", what);
});

test("a chip that keeps answering 61XX (\"there's more\") is cut off", async () => {
  let calls = 0;
  const endless = { transceive: async () => { calls++; return Uint8Array.of(1, 2, 3, 0x61, 0x10); } };
  await assert.rejects(readDocument(endless, { access: ACCESS, preferBac: true }), (e) => e instanceof ChipError);
  assert.ok(calls <= 40, `stopped after ${calls} exchanges`);
});

test("session keys are wiped once reading is over", async () => {
  const passport = testPassport({ csca, mrz: MRZ });
  const chip = simulatedChip({ passport, access: ACCESS });
  const seen = [];
  const orig = SecureMessaging.prototype.wipe;
  SecureMessaging.prototype.wipe = function () { orig.call(this); seen.push([this.ksEnc, this.ksMac, this.ssc]); };
  try { await readDocument(chip, { access: ACCESS, preferBac: true }); }
  finally { SecureMessaging.prototype.wipe = orig; }
  assert.equal(seen.length, 1);
  for (const k of seen[0]) assert.ok(k.every((b) => b === 0), "zeroed");
});
