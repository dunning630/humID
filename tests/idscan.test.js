// Reading identity documents into one record: MRZ (ICAO specimens, OCR noise,
// several frames voting), US and Canadian license barcodes (AAMVA), and chip
// data with the photo, checked against the issuing country's signed hashes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import {
  parseMrz, findMrz, MrzConsensus, mrzDate, accessFromMrz, parseAamva, isAamva, aamvaDate,
  readDg1, readDg2, checkIntegrity, safeCheckIntegrity, chipIntegrityOk, sodHashes, newRecord, applyMrz, applyAamva, applyChip, applyTyped,
  title, status, summary, provenance, recheckChip, encodeRecord, decodeRecord, fullName, fieldsFor, MEDIA_TYPE,
} from "@humid/idscan";
import { readDocument } from "@humid/emrtd";
import { testCsca, testPassport, td3 } from "./support/passport.js";
import { simulatedChip } from "./support/chip.js";

const NOW = new Date("2026-10-13T12:00:00Z");
const TD3 = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"];
const TD1 = ["I<UTOD231458907<<<<<<<<<<<<<<<", "7408122F1204159UTO<<<<<<<<<<<6", "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"];
const TD2 = ["I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<", "D231458907UTO7408122F1204159<<<<<<<6"];

/* ---------------- MRZ ---------------- */

test("MRZ: the ICAO specimens (TD3, TD2, TD1) parse with every check digit agreeing", () => {
  for (const [lines, format, number] of [[TD3, "TD3", "L898902C3"], [TD2, "TD2", "D23145890"], [TD1, "TD1", "D23145890"]]) {
    const f = parseMrz(lines.join("\n"), { now: NOW });
    assert.equal(f.format, format);
    assert.equal(f.valid, true, JSON.stringify(f.checks));
    assert.equal(f.number, number);
    assert.equal(f.surname, "ERIKSSON");
    assert.equal(f.given, "ANNA MARIA");
    assert.equal(f.birth, "1974-08-12");
    assert.equal(f.expiry, "2012-04-15");
    assert.equal(f.sex, "F");
    assert.equal(f.issuer, "UTO");
    assert.equal(f.nationality, "UTO");
  }
  assert.equal(parseMrz(TD3.join("")).kind, "passport");
  assert.equal(parseMrz(TD1.join("")).kind, "id_card");
  assert.deepEqual(accessFromMrz(parseMrz(TD3.join(""))), { number: "L898902C3", birth: "740812", expiry: "120415" });
});

test("MRZ: a wrong check digit is reported, never silently accepted", () => {
  const bad = parseMrz([TD3[0], TD3[1].replace("7408122", "7408132")].join(""));
  assert.equal(bad.valid, false);
  assert.equal(bad.checks.birth, false);
  assert.equal(bad.checks.composite, false);
});

test("MRZ: long TD1 document numbers continue into the optional data", () => {
  // ICAO 9303-5 long number: 12 characters, check digit after them, < in the usual slot.
  const num = "D23145890123";
  const cd = (s) => [...s].reduce((sum, c, i) => sum + (c === "<" ? 0 : /\d/.test(c) ? +c : c.charCodeAt(0) - 55) * [7, 3, 1][i % 3], 0) % 10;
  const l1 = `I<UTO${num.slice(0, 9)}<${num.slice(9)}${cd(num)}`.padEnd(30, "<");
  const l2body = "7408122F1204159UTO<<<<<<<<<<<";
  const comp = cd(l1.slice(5, 30) + l2body.slice(0, 7) + l2body.slice(8, 15) + l2body.slice(18, 29));
  const f = parseMrz([l1, l2body.slice(0, 29) + comp, TD1[2]].join(""));
  assert.equal(f.number, num);
  assert.equal(f.valid, true, JSON.stringify(f.checks));
});

test("MRZ: century rules — birth dates are never in the future, expiry dates are 20xx", () => {
  assert.equal(mrzDate("740812", "birth", NOW), "1974-08-12");
  assert.equal(mrzDate("200101", "birth", NOW), "2020-01-01");
  assert.equal(mrzDate("341231", "expiry", NOW), "2034-12-31");
  assert.equal(mrzDate("990101", "expiry", NOW), "1999-01-01");
  assert.equal(mrzDate("740231", "birth", NOW), null);
});

test("MRZ from OCR: stray characters, O for 0, 8 for B, and a misread the check digits catch", () => {
  const noisy = findMrz("PASSPORT  UTOPIA\nP<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<< 0\nL898902C36UT07408122F1204159ZE184226B<<<<<10 8", { now: NOW });
  assert.equal(noisy.valid, true, JSON.stringify(noisy.checks));
  assert.equal(noisy.nationality, "UTO");
  assert.equal(noisy.number, "L898902C3");
  // One O-for-0 in the document number: exactly one fix makes its check digit agree.
  const fixed = findMrz(`${TD3[0]}\n${TD3[1].replace("L898902", "L8989O2")}`, { now: NOW });
  assert.equal(fixed.valid, true);
  assert.equal(fixed.number, "L898902C3");
  // 8 or B? Two different single fixes both pass the check digit, so neither is trusted.
  const unsure = findMrz(`${TD3[0]}\n${TD3[1].replace("ZE184226B", "ZE1842268")}`, { now: NOW });
  assert.equal(unsure.valid, false);
  assert.equal(unsure.checks.optional, false);
  // A real misread (0 read as 9) plus another error: not trusted.
  const wrong = findMrz(`${TD3[0]}\n${TD3[1].replace("L898902", "L898992").replace("ZE184226B", "2E1842268")}`, { now: NOW });
  assert.equal(wrong?.valid ?? false, false);
  // Short line (a filler dropped) and a long one (an extra filler).
  assert.equal(findMrz(`${TD3[0].slice(0, -1)}\n${TD3[1]}`, { now: NOW }).valid, true);
  assert.equal(findMrz(`${TD3[0]}<\n${TD3[1]}`, { now: NOW }).valid, true);
});

test("MRZ live: frames vote, and a result counts only once it repeats", () => {
  const c = new MrzConsensus({ now: NOW });
  const frames = [
    `${TD3[0]}\n${TD3[1].replace("ZE184226B", "2E1842268")}`,
    `${TD3[0].replace("ERIKSSON", "ERTKSSON")}\n${TD3[1].replace("L898902", "L898992")}`,
    `${TD3[0]}\n${TD3[1]}`,
    `${TD3[0]}\n${TD3[1].replace("ZE184226B", "ZE1842268")}`,
  ];
  const results = frames.map((f) => c.add(f));
  assert.equal(results[0].stable, false);
  assert.equal(results[1].stable, false);
  const last = results.at(-1);
  assert.equal(last.stable, true);
  assert.equal(last.result.number, "L898902C3");
  assert.equal(last.result.given, "ANNA MARIA");
  assert.equal(last.result.optional, "ZE184226B");
});

/* ---------------- AAMVA license barcodes ---------------- */

const VA = "@\n\x1e\rANSI 636000090002DL00410278ZV03190008DLDAQT64235789\nDCSSAMPLE\nDDEN\nDACMICHAEL\nDDFN\nDADJOHN\nDDGN\nDCAD\nDCBK\nDCDPH\nDBD06062016\nDBB06061986\nDBA12102024\nDBC1\nDAU068 in\nDAYBRO\nDAG2300 WEST BROAD STREET\nDAIRICHMOND\nDAJVA\nDAK232690000  \nDCF2424244747474786102204\nDCGUSA\nDCK123456789\nDDAF\nDDB06062008\nDDC06062009\nDDD1\rZVZVA01\r";

test("AAMVA: a version 9 Virginia license reads into the record's fields", () => {
  assert.equal(isAamva(VA), true);
  assert.equal(isAamva("P<UTOERIKSSON"), false);
  const a = parseAamva(VA);
  assert.equal(a.version, 9);
  assert.equal(a.kind, "driver_license");
  const f = a.fields;
  assert.equal(f.surname, "SAMPLE");
  assert.equal(f.given, "MICHAEL JOHN");
  assert.equal(f.number, "T64235789");
  assert.equal(f.birth, "1986-06-06");
  assert.equal(f.issued, "2016-06-06");
  assert.equal(f.expiry, "2024-12-10");
  assert.equal(f.sex, "M");
  assert.equal(f.height.text, "5′8″");
  assert.equal(f.eyes, "Brown");
  assert.equal(f.region, "VA");
  assert.equal(f.issuer, "USA");
  assert.equal(f.address.street, "2300 WEST BROAD STREET");
  assert.equal(f.address.city, "RICHMOND");
  assert.equal(f.address.postalCode, "23269");
  assert.equal(f.vehicleClass, "D");
  assert.equal(f.realId, true);
  assert.equal(a.elements["ZV.ZVA"], "01", "jurisdiction fields stay in their own subfile");
});

test("AAMVA: Illinois with a 9-digit ZIP, CR LF line ends and an ID card", () => {
  const il = "@\r\n\x1e\r\nANSI 636035100102ID00410250ZI02910045IDDAQD12345678901\r\nDCSDUNNING\r\nDDEN\r\nDACPARKER\r\nDDFN\r\nDADQ\r\nDDGN\r\nDBD03152024\r\nDBB07041980\r\nDBA07042028\r\nDBC1\r\nDAU071 IN\r\nDAYBLU\r\nDAG1 MAIN ST\r\nDAIST CHARLES\r\nDAJIL\r\nDAK601741234\r\nDCF123\r\nDCGUSA\r\nDDAN\r\n";
  const a = parseAamva(il);
  assert.equal(a.kind, "id_card");
  assert.equal(a.jurisdictionVersion, 1);
  assert.equal(a.fields.number, "D12345678901");
  assert.equal(a.fields.given, "PARKER Q");
  assert.equal(a.fields.address.postalCode, "60174-1234");
  assert.equal(a.fields.address.city, "ST CHARLES");
  assert.equal(a.fields.region, "IL");
  assert.equal(a.fields.realId, false);
  assert.equal(a.fields.height.text, "5′11″");
});

test("AAMVA: Canada uses CCYYMMDD and postal codes; version 1 puts the whole name in DAA", () => {
  const on = "@\n\x1e\rANSI 636012030001DL00290200DLDAQS1234-56789-01234\nDAAMARTIN,ELODIE,ANNE\nDBA20290415\nDBB19920102\nDBD20240415\nDBC2\nDAG10 KING ST W\nDAITORONTO\nDAJON\nDAKM5H1A1\nDCGCAN\n";
  const a = parseAamva(on);
  assert.equal(a.fields.surname, "MARTIN");
  assert.equal(a.fields.given, "ELODIE ANNE");
  assert.equal(a.fields.birth, "1992-01-02");
  assert.equal(a.fields.expiry, "2029-04-15");
  assert.equal(a.fields.sex, "F");
  assert.equal(a.fields.address.postalCode, "M5H 1A1");
  assert.equal(a.fields.issuer, "CAN");
  assert.equal(aamvaDate("07041980", "USA"), "1980-07-04");
  assert.equal(aamvaDate("19800704", "CAN"), "1980-07-04");
  assert.equal(aamvaDate("13131980"), null);
});

/* ---------------- chip: DG1, the DG2 photo, SOD hashes ---------------- */

const csca = testCsca("HumID ID Country");
const ACCESS = { number: "X4K90T2R1", birth: "880214", expiry: "330630" };
const MRZ = { number: ACCESS.number, birth: ACCESS.birth, expiry: ACCESS.expiry, surname: "OKAFOR", given: "ADA", issuer: "NGA", nationality: "NGA" };
const JPEG = readFileSync(new URL("./fixtures/id/portrait.jpg", import.meta.url));

test("chip: the photo is read only when asked, and matches the country's signed hash", async () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG });
  const plain = await readDocument(simulatedChip({ passport, access: ACCESS }), { access: ACCESS });
  assert.equal(plain.dg2, undefined, "proving identity never reads the photo");
  for (const pace of [null, { oid: "0.4.0.127.0.7.2.2.4.2.4", parameterId: 13 }]) {
    const r = await readDocument(simulatedChip({ passport, access: ACCESS, pace }), { access: ACCESS, photo: true });
    assert.ok(r.dg2, "photo read");
    const face = readDg2(r.dg2);
    assert.equal(face.type, "image/jpeg");
    assert.deepEqual(Buffer.from(face.bytes), JPEG);
    const { mrz } = readDg1(r.dg1);
    assert.equal(mrz.surname, "OKAFOR");
    assert.equal(mrz.valid, true);
    const integrity = checkIntegrity(r.sod, { 1: r.dg1, 2: r.dg2, 15: r.dg15 });
    assert.equal(integrity.ok, true);
    assert.equal(integrity.algorithm, "SHA-256");
    assert.deepEqual(Object.keys(sodHashes(r.sod).hashes).sort(), ["1", "15", "2"]);
  }
});

test("chip: a photo over 32 KB is read with long offsets; JPEG 2000 photos are found too", async () => {
  const big = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(34 * 1024)]);
  const passport = testPassport({ csca, mrz: MRZ, photo: big });
  const r = await readDocument(simulatedChip({ passport, access: ACCESS }), { access: ACCESS, photo: true });
  assert.deepEqual(Buffer.from(readDg2(r.dg2).bytes), big);
  assert.equal(checkIntegrity(r.sod, { 2: r.dg2 }).ok, true);
  const jp2 = readFileSync(new URL("./fixtures/id/portrait.jp2", import.meta.url));
  const p2 = testPassport({ csca, mrz: MRZ, photo: jp2 });
  assert.equal(readDg2(p2.dg2).type, "image/jp2");
});

test("chip: an altered photo or MRZ fails the integrity check", () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG, tamper: "dg2" });
  const bad = checkIntegrity(passport.sod, { 1: passport.dg1, 2: passport.dg2 });
  assert.equal(bad.ok, false);
  assert.equal(bad.groups[1], true);
  assert.equal(bad.groups[2], false);
});

/* ---------------- fail closed: only integrity.ok === true counts ---------------- */

test("chip integrity decision: null, thrown, ok:false are rejected; only ok:true passes", () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG });
  const good = safeCheckIntegrity(passport.sod, { 1: passport.dg1, 2: passport.dg2 });
  const tampered = safeCheckIntegrity(testPassport({ csca, mrz: MRZ, photo: JPEG, tamper: "dg2" }).sod, { 1: passport.dg1, 2: passport.dg2 });
  const thrown = safeCheckIntegrity(Uint8Array.of(1, 2, 3), { 1: passport.dg1 });
  assert.throws(() => checkIntegrity(Uint8Array.of(1, 2, 3), { 1: passport.dg1 }), "the raw check does throw on a malformed SOD");
  assert.equal(chipIntegrityOk(good), true);
  assert.equal(good.ok, true);
  assert.equal(chipIntegrityOk(tampered), false, "hash mismatch");
  assert.equal(chipIntegrityOk(thrown), false, "malformed SOD");
  assert.equal(thrown.reason, "malformed");
  assert.equal(chipIntegrityOk(null), false, "null (the old code treated this as fine)");
  assert.equal(chipIntegrityOk(undefined), false);
  assert.equal(chipIntegrityOk({}), false);
  assert.equal(chipIntegrityOk({ ok: false }), false);
  assert.equal(chipIntegrityOk({ ok: "yes" }), false, "truthy but not true");
  assert.equal(chipIntegrityOk({ ok: true }), true);
});

test("record: chip data from an unchecked chip is not applied and is labelled not verified", () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG });
  const { mrz } = readDg1(passport.dg1);
  const chip = { dg1: passport.dg1, dg2: passport.dg2, sod: passport.sod, access: "BAC" };
  const b64 = (b) => Buffer.from(b).toString("base64");
  const printed = parseMrz(td3(MRZ), { now: NOW });
  const bad = [
    null,
    undefined,
    { ok: false, groups: { 1: true, 2: false } },
    safeCheckIntegrity(Uint8Array.of(1, 2, 3), { 1: passport.dg1 }),
  ];
  for (const integrity of bad) {
    const rec = applyMrz(newRecord("passport"), { ...printed, given: "PRINTED" }, { consensus: true });
    applyChip(rec, chip, { mrz, integrity, b64 });
    assert.equal(rec.fields.given, "PRINTED", "the chip's name is not applied");
    assert.equal(rec.source.given, "mrz", "nothing is ranked as chip");
    assert.equal(rec.raw.chip, undefined, "the chip's files are not kept");
    assert.equal(rec.verified.chip, undefined);
    assert.ok(rec.verified.chipFailed, "the failure is recorded");
    assert.equal(provenance(rec).level, "mrz-unverified");
    assert.match(provenance(rec).text, /^Not verified/);
    assert.doesNotMatch(provenance(rec).text, /verified by|genuine/i);
  }
  // With nothing else read, the record says the chip failed rather than "from the chip".
  const empty = applyChip(newRecord("passport"), chip, { mrz, integrity: null, b64 });
  assert.deepEqual(empty.fields, {});
  assert.equal(provenance(empty).level, "chip-failed");
  // A hash-consistent chip is applied, and described as integrity-checked, never as verified.
  const ok = applyChip(newRecord("passport"), chip, { mrz, integrity: checkIntegrity(passport.sod, { 1: passport.dg1, 2: passport.dg2 }), b64 });
  assert.equal(ok.source.given, "chip");
  assert.equal(ok.verified.chip.integrity, true);
  assert.equal(provenance(ok).level, "chip");
  assert.match(provenance(ok).text, /^Chip data integrity-checked/);
  assert.match(provenance(ok).text, /signature isn't checked on this phone/);
  assert.doesNotMatch(provenance(ok).text, /\bverified\b/i);
});

test("APP-05: the chip label is re-checked from the chip's files, never taken from a stored flag", () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG });
  const { mrz } = readDg1(passport.dg1);
  const b64 = (b) => Buffer.from(b).toString("base64");
  const chip = { dg1: passport.dg1, dg2: passport.dg2, sod: passport.sod, access: "BAC" };
  const make = () => applyChip(newRecord("passport"), chip, { mrz, integrity: checkIntegrity(passport.sod, { 1: passport.dg1, 2: passport.dg2 }), b64 });
  assert.equal(recheckChip(make()).ok, true);

  // A forged record: the flag says integrity-checked, but no chip files are kept.
  const noFiles = make(); delete noFiles.raw.chip;
  assert.equal(provenance(noFiles).level, "chip-mismatch");
  // The flag is set, but the files don't match the hash list.
  const flipped = Buffer.from(passport.dg2); flipped[flipped.length - 1] ^= 1;
  const swapped = make(); swapped.raw.chip.dg2 = b64(flipped);
  assert.equal(provenance(swapped).level, "chip-mismatch");
  // The files are genuine, but a "chip" field was rewritten while keeping its chip source.
  const relabelled = make(); relabelled.fields.surname = "MALLORY";
  assert.equal(provenance(relabelled).level, "chip-mismatch");
  assert.match(provenance(relabelled).text, /^Not verified: details on this card don't match the chip/);
  // ... or rewritten and relabelled as if it came from the printed lines (review finding).
  const relabelledSource = make(); relabelledSource.fields.surname = "MALLORY"; relabelledSource.source.surname = "mrz";
  relabelledSource.fields.birth = "1999-01-01"; relabelledSource.source.birth = "barcode";
  assert.equal(provenance(relabelledSource).level, "chip-mismatch");
  // The chip photo (JPEG) must be the chip's own bytes.
  const photo = make(); photo.images.portrait = { type: "image/jpeg", data: b64(Buffer.from([0xff, 0xd8, 0xff, 1, 2, 3])), size: 6 };
  assert.equal(provenance(photo).level, "chip-mismatch");
  const realPhoto = make(); realPhoto.images.portrait = { type: "image/jpeg", data: b64(readDg2(passport.dg2).bytes), size: 1 };
  assert.equal(provenance(realPhoto).level, "chip");
  assert.equal(recheckChip(realPhoto).portrait, "matches");
  // A flag set on a record with no chip read at all is caught too.
  const flagOnly = applyMrz(newRecord("passport"), parseMrz(td3(MRZ), { now: NOW }));
  flagOnly.verified.chip = { integrity: true };
  assert.equal(provenance(flagOnly).level, "chip-mismatch");
  // An honest correction by hand is still "chip, edited".
  const edited = applyTyped(make(), { surname: "ERIKSSON-LUND" });
  assert.equal(provenance(edited).level, "chip-edited");
  // Garbage in the stored files is "not verified", never a crash.
  const junk = make(); junk.raw.chip.dg1 = "%%%";
  assert.equal(provenance(junk).level, "chip-mismatch");
});

test("APP-05: a mobile ID's labels need a fresh check passed in; stored flags alone don't earn them", () => {
  const rec = newRecord("driver_license");
  rec.verified.mdoc = { docType: "org.iso.18013.5.1.mDL", chain: "trusted", deviceOk: true };
  assert.equal(provenance(rec).level, "mdoc-unchecked");
  assert.equal(provenance(rec, { mdoc: { ok: false, reason: "the issuer's signature doesn't verify" } }).level, "mdoc-mismatch");
  assert.equal(provenance(rec, { mdoc: { ok: true, chain: "unchecked" } }).level, "mdoc-unchecked");
  assert.equal(provenance(rec, { mdoc: { ok: true, chain: "trusted" } }).level, "mdoc");
});

/* ---------------- the record ---------------- */

test("record: chip beats barcode beats OCR, typed corrections win and are marked", () => {
  const passport = testPassport({ csca, mrz: MRZ, photo: JPEG });
  const rec = newRecord("passport");
  // OCR got the given name wrong; the chip has it right.
  applyMrz(rec, { ...parseMrz(td3(MRZ), { now: NOW }), given: "ADD" }, { consensus: true });
  assert.equal(rec.fields.given, "ADD");
  const { mrz } = readDg1(passport.dg1);
  const b64 = (b) => Buffer.from(b).toString("base64");
  applyChip(rec, { dg1: passport.dg1, dg2: passport.dg2, sod: passport.sod, access: "BAC" }, { mrz, integrity: checkIntegrity(passport.sod, { 1: passport.dg1, 2: passport.dg2 }), b64 });
  assert.equal(rec.fields.given, "ADA");
  assert.equal(rec.source.given, "chip");
  applyMrz(rec, { ...mrz, given: "XXX" });
  assert.equal(rec.fields.given, "ADA", "a later OCR read can't overwrite chip data");
  applyTyped(rec, { given: "Ada Ngozi" });
  assert.equal(rec.fields.given, "Ada Ngozi");
  assert.deepEqual(rec.edited, ["given"]);
  assert.equal(title(rec), "Passport · Nigeria");
  assert.equal(fullName(rec), "Ada Ngozi Okafor");
  assert.equal(provenance(rec).level, "chip-edited", "a typed change means the record no longer says it's all from the chip");
  assert.match(provenance(rec).text, /changed by hand/);
  assert.deepEqual(summary(rec), { kind: "passport", issuer: "NGA", region: "", expiry: "2033-06-30" });
  const back = decodeRecord(encodeRecord(rec));
  assert.equal(back.fields.number, "X4K90T2R1");
  assert.equal(back.raw.chip.dg2, b64(passport.dg2));
  assert.equal(MEDIA_TYPE, "application/vnd.humid.id+json");
});

test("record: license fields, expiry status and which fields show", () => {
  const rec = applyAamva(newRecord("driver_license"), parseAamva(VA));
  assert.equal(title(rec), "Driver's license · Virginia");
  assert.equal(rec.address.city, "RICHMOND");
  assert.equal(status(rec, NOW).state, "expired");
  assert.equal(status({ fields: { expiry: "2026-12-01" } }, NOW).state, "expiring");
  assert.equal(status({ fields: { expiry: "2030-01-01" } }, NOW).state, "valid");
  assert.equal(status({ fields: {} }, NOW).state, "unknown");
  assert.ok(fieldsFor("driver_license").some((f) => f.key === "vehicleClass"));
  assert.ok(!fieldsFor("passport").some((f) => f.key === "vehicleClass"));
  assert.equal(provenance(rec).level, "barcode");
  assert.throws(() => decodeRecord(new TextEncoder().encode("{}")));
});
