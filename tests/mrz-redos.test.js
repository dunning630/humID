// Regression: nameField() used a backtracking regex (ReDoS: ~27 s at 30 fillers).
// It is now linear. The old function lives here as an oracle for short inputs only.
import test from "node:test";
import assert from "node:assert/strict";
import { nameField } from "../packages/idscan/src/mrz.js";
import { parseMrzLines, parseMrz, findMrz } from "../packages/idscan/src/index.js";
import { readCardText, readCardBack } from "../packages/cards/src/index.js";

const TO_ALPHA = { 0: "O", 1: "I", 2: "Z", 4: "A", 5: "S", 6: "G", 7: "T", 8: "B" };
const alphaFiller = (s) => [...s].map((c) => (c === "<" ? c : TO_ALPHA[c] ?? c)).join("");
function oldNameField(s) {
  let t = alphaFiller(s).replace(/[^A-Z<]/g, "<");
  const m = /^(.*?[A-Z]{2,})(?:<+[KCELXZ]?)*<*$/.exec(t);
  if (m && t.length > m[1].length) t = m[1] + "<".repeat(t.length - m[1].length);
  return t;
}
const ms = (fn) => { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; };

test("nameField: the original reproducers are linear, up to 10,000 fillers", () => {
  for (const k of [20, 30, 100, 1000, 10000]) {
    for (const s of ["AA" + "<".repeat(k) + "Y", "WU<<LI" + "<".repeat(k) + "S", "<".repeat(k) + "AAK", "AB" + "<K".repeat(k)]) {
      const t = ms(() => nameField(s));
      assert.ok(t < 50, `k=${k}: ${t} ms`);
    }
  }
});

test("nameField: same results as the old regex on valid names and 100k random strings", () => {
  const valid = [
    "ERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "WU<<LI<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "MUELLER<<HANS<PETER<<<<<<<<<<<<<<<<",
    "DE<LA<CRUZ<<JOSE<<<<<<<<<<<<<<<<<<<<<<", "O<BRIEN<<MARY<<<<<<<<<<<<<<<<<<<<<<<<", "WU<<LI<<<<<<<<<<<<<<<<<<<<<<<<<<<<S",
    "WU<<LI<<<K<<<E<<<<<<<<<<<<<<<<<<<", "LI<<WEI<<<<<<<<<<<<<<<<<<<<<<<<<<<<<B", "AA", "A", "", "<<<", "AB<K", "AB<KK", "AB<K<C", "AB<<CD", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "SMITH<<J0HN<<<<<<<<<<<<<<<<<<<<<<<<", "ERIKSS0N<<ANNA", "A<B<C<D", "AB<ZZ", "AB<Z<Z<Z", "ABK", "ABKK<",
  ];
  for (const v of valid) assert.equal(nameField(v), oldNameField(v), JSON.stringify(v));
  let seed = 12345;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const alphabets = ["<<<<<AKCELXZYB", "<<<<ABCKEZ0158", "<AKZ", "<<<<<<<<ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -'"];
  for (let i = 0; i < 100000; i++) {
    const a = alphabets[i % alphabets.length], len = Math.floor(rnd() * 15);
    let s = "";
    for (let j = 0; j < len; j++) s += a[Math.floor(rnd() * a.length)];
    assert.equal(nameField(s), oldNameField(s), JSON.stringify(s));
  }
});

test("MRZ: a short name with an OCR-misread filler parses fast, end to end", () => {
  const L2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
  for (const [name, miss] of [["WU<<LI", "S"], ["LI<<WEI", "B"], ["ERIKSSON<<ANNA", "S"], ["WU<<LI", "<"]]) {
    const line1 = ("P<UTO" + name).padEnd(43, "<") + miss;
    assert.ok(ms(() => parseMrzLines([line1, L2])) < 50);
    assert.ok(ms(() => findMrz("noise\n" + line1 + "\n" + L2)) < 50);
  }
  const f = parseMrzLines([("P<UTOWU<<LI").padEnd(43, "<") + "K", L2]);
  assert.equal(f.surname, "WU");
  assert.equal(f.given, "LI");
});

test("MRZ: oversized input is refused or bounded, not chewed on", () => {
  const big = "<".repeat(200000);
  assert.equal(parseMrz(big), null);
  assert.ok(ms(() => parseMrz("A".repeat(88) + big)) < 50);
  assert.ok(ms(() => findMrz(big + "\n" + ("AA" + big + "Y\n").repeat(50))) < 100);
  assert.ok(ms(() => parseMrzLines([big, big])) < 50);
  assert.ok(ms(() => nameField("AA" + big + "Y")) < 50);
});

test("cards: OCR text of any size is bounded and fast", () => {
  const junk = "O1".repeat(500000), spaces = "SECURITY" + " ".repeat(500000), digits = "1 ".repeat(100000);
  for (const text of [junk, spaces, digits, "1111" + " ".repeat(300000), ("A ".repeat(300) + "\n").repeat(2000)]) {
    assert.ok(ms(() => readCardText(text)) < 200);
    assert.ok(ms(() => readCardBack(text)) < 200);
  }
});
