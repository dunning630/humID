// Payment cards: number checks, networks, camera text, contactless reads
// against simulated cards (tests/support/emvcard.js), and the sealed record's rules.
import test from "node:test";
import assert from "node:assert/strict";
import {
  luhn, checkPan, brandOf, formatPan, maskPan, parseExpiry, expiryStatus, readCardText, CardConsensus, readContactless, parseTrack2,
  newCard, applyRead, applyTyped, setStoreCvv, setImage, summary, view, title, copyValue, encodeCard, decodeCard, problems, HANDLING, MEDIA_TYPE,
} from "@humid/cards";
import { card } from "./support/emvcard.js";

const code = (c) => (e) => { assert.equal(e.code, c, e.message); return true; };

test("numbers: Luhn, lengths and networks (published test numbers)", () => {
  const cases = {
    "4111111111111111": "visa", "4012888888881881": "visa", "5555555555554444": "mastercard", "2223003122003222": "mastercard",
    "378282246310005": "amex", "371449635398431": "amex", "6011111111111117": "discover", "6011000990139424": "discover",
    "3530111333300000": "jcb", "36259600000004": "diners", "6200000000000005": "unionpay", "2200000000000004": "mir",
  };
  for (const [pan, brand] of Object.entries(cases)) {
    const c = checkPan(pan);
    assert.equal(c.ok, true, `${pan} valid`);
    assert.equal(c.brand, brand, `${pan} → ${brand}`);
  }
  assert.equal(luhn("4111111111111112"), false);
  assert.deepEqual(checkPan("4111 1111 1111 1112").problems, ["luhn"]);
  assert.deepEqual(checkPan("37828224631000").problems, ["length", "luhn"]);
  assert.equal(formatPan("4111111111111111"), "4111 1111 1111 1111");
  assert.equal(formatPan("378282246310005"), "3782 822463 10005");
  assert.equal(maskPan("4111111111111111"), "•••• 1111");
  assert.equal(brandOf("9999999999999995").id, "unknown");
});

test("expiry: formats, and a card is good through the end of its month", () => {
  assert.equal(parseExpiry("12/28"), "2028-12");
  assert.equal(parseExpiry("1/2030"), "2030-01");
  assert.equal(parseExpiry("1228"), "2028-12");
  assert.equal(parseExpiry("2812", { order: "yymm" }), "2028-12");
  assert.equal(parseExpiry("13/28"), "");
  const now = new Date("2026-10-14T12:00:00Z");
  assert.equal(expiryStatus("2026-10", now).state, "expiring");
  assert.equal(expiryStatus("2026-09", now).state, "expired");
  assert.equal(expiryStatus("2028-12", now).state, "valid");
});

test("camera: the card front from noisy OCR text; member-since and brand words aren't mistaken", () => {
  const text = [
    "FIRST HUMID BANK", "PLATINUM REWARDS",
    "4111 1lll 1111 1111", // OCR read 1 as l
    "MEMBER SINCE 03/19   VALID THRU 08/29",
    "JANE Q SPECIMEN", "VISA",
  ].join("\n");
  const r = readCardText(text, { now: new Date("2026-10-14T00:00:00Z") });
  assert.equal(r.pan, "4111111111111111");
  assert.equal(r.brand, "visa");
  assert.equal(r.expiry, "2029-08");
  assert.equal(r.name, "JANE Q SPECIMEN");
  // A number that fails its check digit is never accepted.
  assert.equal(readCardText("4111 1111 1111 1112\n08/29").pan, null);
  // Amex grouping.
  assert.equal(readCardText("3782 822463 10005\n12/27 JOHN DOE").pan, "378282246310005");
});

test("camera live: a number counts once two frames agree", () => {
  const c = new CardConsensus();
  assert.equal(c.add("5555 5555 5555 4444\n09/28"), null);
  assert.equal(c.add("5555 5555 5555 4444\n09/28\nALEX ROE").pan, "5555555555554444");
  assert.equal(c.result.expiry, "2028-09");
});

test("contactless: Visa (track 2 in the processing options), Mastercard (records), Amex without a directory", async () => {
  const visa = card("visa");
  const v = await readContactless(visa, { random: Uint8Array.of(1, 2, 3, 4), now: new Date("2026-10-14T00:00:00Z") });
  assert.deepEqual({ pan: v.pan, expiry: v.expiry, name: v.name, aid: v.aid }, { pan: "4111111111111111", expiry: "2029-08", name: null, aid: "A0000000031010" });
  // Amount zero, today's date, our unpredictable number: a read, not a payment.
  const pd = visa.gpo();
  assert.equal(pd[0], 0x83);
  const body = pd.subarray(2);
  assert.deepEqual([...body.subarray(4, 10)], [0, 0, 0, 0, 0, 0], "amount is zero");
  assert.deepEqual([...body.subarray(body.length - 4)], [1, 2, 3, 4]);
  assert.deepEqual([...body.subarray(body.length - 8, body.length - 5)], [0x26, 0x10, 0x14], "date 261014");

  const mc = card("mastercard", { chain: true });
  const m = await readContactless(mc);
  assert.deepEqual({ pan: m.pan, expiry: m.expiry, name: m.name, issuerCountry: m.issuerCountry }, { pan: "5555555555554444", expiry: "2029-08", name: "JANE Q SPECIMEN", issuerCountry: "840" });

  const amex = card("amex-noppse");
  const a = await readContactless(amex);
  assert.equal(a.pan, "378282246310005");
  assert.equal(a.network, "AMERICAN EXPRESS");

  // The reader only ever selects, asks for processing options, reads records or fetches chained replies.
  for (const l of [...visa.log, ...mc.log, ...amex.log]) assert.ok(["A4", "A8", "B2", "C0"].includes(l.slice(2, 4)), `unexpected command ${l}`);
  for (const r of [v, m, a]) assert.deepEqual(Object.keys(r).sort(), ["aid", "expiry", "issuerCountry", "name", "network", "pan"], "nothing else leaves the reader");
});

test("contactless: a card that won't answer is reported, and track 2's extra data is dropped", async () => {
  await assert.rejects(readContactless(card("refuses")), code("no_number"));
  assert.deepEqual(parseTrack2(Uint8Array.from([0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0xd2, 0x90, 0x82, 0x01, 0x10, 0x00, 0x0f])), { pan: "4111111111111111", yymm: "2908" });
});

test("record: holds the card, never a PIN, a back photo or an unrequested security code", async () => {
  const rec = newCard();
  applyRead(rec, await readContactless(card("mastercard")), "nfc");
  applyTyped(rec, { nickname: "Travel card", bank: "First HumID Bank", phone: "800-555-0100" });
  assert.equal(title(rec), "Travel card");
  assert.throws(() => applyTyped(rec, { pin: "1234" }), code("forbidden"));
  assert.throws(() => applyTyped(rec, { track2: "..." }), code("forbidden"));
  assert.throws(() => applyTyped(rec, { cvv: "123" }), code("cvv_off"));
  assert.throws(() => setImage(rec, "back", { type: "image/jpeg", data: "" }), code("no_back_photo"));
  assert.throws(() => applyTyped(rec, { pan: "4111111111111112" }), code("bad_number"));
  assert.throws(() => applyTyped(rec, { expiry: "14/29" }), code("bad_expiry"));

  // Opt in to the code: right length per network; opting out deletes it.
  setStoreCvv(rec, true);
  assert.throws(() => applyTyped(rec, { cvv: "12" }), code("bad_cvv"));
  applyTyped(rec, { cvv: "123" });
  assert.equal(view(rec).cvv, "•••");
  assert.equal(view(rec, { revealed: true }).cvv, "123");
  setStoreCvv(rec, false);
  assert.equal(rec.fields.cvv, undefined);

  // Display masks until revealed; copies are digits only.
  assert.equal(view(rec).number, "•••• 4444");
  assert.equal(view(rec, { revealed: true }).number, "5555 5555 5555 4444");
  assert.equal(copyValue(rec, "pan"), "5555555555554444");
  assert.ok(HANDLING.clipboardClearMs > 0 && HANDLING.blockScreenshots);

  // A typed correction beats a later read; the index never carries the number.
  applyTyped(rec, { name: "JANE SPECIMEN" });
  applyRead(rec, { pan: "5555555555554444", name: "OTHER" }, "camera");
  assert.equal(rec.fields.name, "JANE SPECIMEN");
  assert.deepEqual(summary(rec), { kind: "payment_card", brand: "mastercard", last4: "4444", expiry: "2029-08", nickname: "Travel card" });
  assert.ok(!JSON.stringify(summary(rec)).includes("5555555555"));
  assert.equal(MEDIA_TYPE, "application/vnd.humid.card+json");
});

test("record: sealing's encoding round-trips, and decoding strips anything that shouldn't be there", () => {
  const rec = newCard();
  applyTyped(rec, { pan: "4111 1111 1111 1111", expiry: "08/29", name: "JANE SPECIMEN" });
  const back = decodeCard(encodeCard(rec));
  assert.equal(back.fields.pan, "4111111111111111");
  assert.equal(back.fields.expiry, "2029-08");
  assert.deepEqual(problems(back), []);
  // A record tampered with (or written by a buggy client) loses forbidden data on read.
  const raw = JSON.parse(new TextDecoder().decode(encodeCard(rec)));
  raw.fields.pin = "1234"; raw.fields.cvv = "999"; raw.images.back = { data: "x" }; raw.track2 = "x";
  const clean = decodeCard(JSON.stringify(raw));
  assert.equal(clean.fields.pin, undefined);
  assert.equal(clean.fields.cvv, undefined, "no opt-in, so no security code");
  assert.equal(clean.images.back, undefined);
  assert.equal(clean.track2, undefined);
  assert.throws(() => encodeCard(newCard()), code("bad_number"));
});
