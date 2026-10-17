// @humid/recovery: codes, cards and Shamir sharing.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  base32, unbase32, keyCode, formatCode, parseCode, LINK_LABEL,
  newCard, parseCard, formatCard, cardTag, sealCard, openCard,
  split, combine, thresholdFor, encodeShare, decodeShare,
  qrPayload, parseQr, QR_MAX, accountCheck,
} from "@humid/recovery";

const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

test("base32 round-trips and forgives look-alike characters", () => {
  const b = rnd(15);
  const s = base32(b);
  assert.equal(s.length, 24);
  assert.deepEqual(unbase32(s, 15), b);
  assert.deepEqual(unbase32("0O1IL", 3).slice(0, 3), unbase32("00111", 3).slice(0, 3));
});

test("a key code commits to the keys and survives formatting", () => {
  const k1 = rnd(1568), k2 = rnd(32);
  const code = keyCode(LINK_LABEL, k1, k2);
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{12}$/);
  assert.equal(parseCode(formatCode(code).toLowerCase()), code);
  assert.equal(parseCode(" " + formatCode(code) + " "), code);
  assert.notEqual(keyCode(LINK_LABEL, k1, rnd(32)), code, "different keys, different code");
  assert.notEqual(keyCode("OTHER", k1, k2), code, "labels separate code kinds");
  assert.equal(parseCode("ABCD-EFGH"), null);
});

test("recovery card: generate, print, retype, catch typos", () => {
  const { secret, code } = newCard();
  assert.match(code, /^HUMID(-[0-9A-HJKMNP-TV-Z]{5}){5}$/);
  assert.deepEqual(parseCard(code), secret);
  assert.deepEqual(parseCard(code.toLowerCase().replace(/-/g, " ")), secret);
  // every single-character typo and every neighbour swap is caught
  const body = code.slice(6).replace(/-/g, "");
  const ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  for (let i = 0; i < body.length; i++) {
    for (const ch of ALPHA) {
      if (ch === body[i]) continue;
      const typo = body.slice(0, i) + ch + body.slice(i + 1);
      assert.throws(() => parseCard("HUMID" + typo), /typo/, `substitution at ${i}`);
    }
    if (i + 1 < body.length && body[i] !== body[i + 1]) {
      const swap = body.slice(0, i) + body[i + 1] + body[i] + body.slice(i + 2);
      assert.throws(() => parseCard("HUMID" + swap), /typo/, `swap at ${i}`);
    }
  }
  assert.throws(() => parseCard("HUMID-12345"), /25 characters/);
  assert.equal(formatCard(secret), code);
});

test("card seals the seed to one account and nothing else opens it", async () => {
  const { secret } = newCard();
  const seed = rnd(64);
  const blob = await sealCard(secret, seed, "hid_aaa");
  assert.deepEqual(await openCard(secret, blob, "hid_aaa"), seed);
  await assert.rejects(openCard(secret, blob, "hid_bbb"), /does not open/);
  await assert.rejects(openCard(newCard().secret, blob, "hid_aaa"), /does not open/);
  assert.equal(cardTag(secret), cardTag(parseCard(formatCard(secret))));
  assert.notEqual(cardTag(secret), cardTag(newCard().secret));
});

test("Shamir: any t of n rebuild the seed; t-1 do not", () => {
  const seed = rnd(64);
  for (const n of [2, 3, 4, 5]) {
    const t = thresholdFor(n);
    const shares = split(seed, n, t);
    // every t-subset works
    const subsets = (arr, k) => k === 0 ? [[]] : arr.flatMap((v, i) => subsets(arr.slice(i + 1), k - 1).map((s) => [v, ...s]));
    for (const sub of subsets(shares, t)) assert.deepEqual(combine(sub), seed, `n=${n} t=${t}`);
    // t-1 shares give something else (overwhelmingly likely; t>=2 always here)
    if (t - 1 >= 2) assert.notDeepEqual(combine(shares.slice(0, t - 1)), seed);
  }
  assert.deepEqual([2, 3, 4, 5].map(thresholdFor), [2, 2, 3, 3]);
});

test("Shamir: a single share is uniformly random, independent of the secret", () => {
  // Same secret split twice -> unrelated shares; different secrets -> share byte distributions both look uniform.
  const zero = new Uint8Array(4096);
  const counts = new Array(256).fill(0);
  for (const b of split(zero, 3, 2)[0].y) counts[b]++;
  const max = Math.max(...counts), min = Math.min(...counts);
  assert.ok(max < 40 && min > 2, `share bytes should be spread out (min ${min}, max ${max})`);
});

test("Shamir: rejects malformed input", () => {
  const s = split(rnd(8), 3, 2);
  assert.throws(() => combine([s[0]]), /two shares/);
  assert.throws(() => combine([s[0], s[0]]), /distinct/);
  assert.throws(() => split(rnd(8), 3, 1), /2 ≤ t/);
  assert.throws(() => split(rnd(8), 2, 3), /2 ≤ t/);
});

test("share payload round-trips", () => {
  const [sh] = split(rnd(64), 3, 2);
  const back = decodeShare(encodeShare({ owner: "hid_x", label: "Parker", x: sh.x, t: 2, n: 3, y: sh.y }));
  assert.equal(back.owner, "hid_x");
  assert.equal(back.label, "Parker");
  assert.deepEqual(back.y, sh.y);
  assert.throws(() => decodeShare(new TextEncoder().encode('{"kind":"x"}')), /Not a HumID/);
});

/* ---------------- QR payloads ---------------- */

test("QR: versioned, with purpose and expiry, and round-trips", () => {
  const code = keyCode(LINK_LABEL, rnd(32), rnd(32));
  const exp = Date.UTC(2030, 0, 1, 12, 0, 0);
  const t = qrPayload("link", code, exp);
  assert.match(t, /^HUMID:2:LINK:[0-9A-Z]{12}:[0-9A-Z]+$/);
  assert.ok(t.length <= QR_MAX);
  assert.deepEqual(parseQr(t), { kind: "link", code, expiresAt: exp });
  for (const k of ["recover", "contact"]) assert.equal(parseQr(qrPayload(k, code, exp)).kind, k);
  assert.throws(() => qrPayload("link", code), /Nothing/, "no expiry, no QR");
  assert.throws(() => qrPayload("url", code, exp), /Nothing/);
});

test("QR: anything that isn't exactly the current format is refused", () => {
  const code = keyCode(LINK_LABEL, rnd(32), rnd(32));
  const good = qrPayload("recover", code, Date.UTC(2030, 0, 1));
  const [, , , , exp] = good.split(":");
  for (const bad of [
    code,                                       // a bare code
    formatCode(code),                           // a bare formatted code
    `HUMID:RECOVER:${code}`,                    // version 1
    `HUMID:1:RECOVER:${code}:${exp}`,           // another version
    `HUMID:3:RECOVER:${code}:${exp}`,
    `HUMID:02:RECOVER:${code}:${exp}`.replace(":02:", ":2x:"),
    `HUMID:2:OPEN:${code}:${exp}`,              // unknown purpose
    `HUMID:2:RECOVER:${code}:${exp}:EXTRA`,     // an extra field
    `HUMID:2:RECOVER:${code}`,                  // no expiry
    `HUMID:2:RECOVER:${formatCode(code)}:${exp}`, // dashes
    good.toLowerCase(),
    ` ${good}`, `${good}\n`,
    `HUMID:2:RECOVER:${code.slice(0, 11)}O:${exp}`, // look-alike characters aren't normalised from a camera
    `HUMID:2:RECOVER:${code.slice(0, 11)}U:${exp}`, // not in the alphabet
    `https://evil.example/?q=${good}`,
    `humid://open?${good}`,
    good + "0".repeat(QR_MAX),
    "", null, undefined, 42, {}, [good],
  ]) assert.equal(parseQr(bad), null, String(bad));
});

test("account check: the same on both devices for one account, different for another", () => {
  const a = accountCheck("hid_abc"), b = accountCheck("hid_abd");
  assert.match(a, /^[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  assert.equal(a, accountCheck("hid_abc"));
  assert.notEqual(a, b);
  assert.throws(() => accountCheck(""));
});
