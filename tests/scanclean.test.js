// "Clean scan" (apps/mobile/src/core/scanclean.js): a straightened photo of a page made
// to look like it came off a flatbed scanner. A real text page (tests/fixtures/docs)
// is lit the way a phone sees it: light falling off across the page, a soft shadow
// from the phone over one side, warm room light. Afterwards the paper should be white
// and even, the ink still dark, and colours still themselves.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { cleanScan, lightField, paperShare } from "../apps/mobile/src/core/scanclean.js";

const fixture = (n) => {
  const b = gunzipSync(readFileSync(new URL(`./fixtures/docs/${n}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
};
const PAGE = fixture("page-letter"), FRONT = fixture("card-front");

/** RGBA from a grey page, lit by light(x, y) (0–1) and tinted [r, g, b] (0–1 each). */
function lit(page, light = () => 1, tint = [1, 1, 1], seed = 3) {
  let s = seed;
  const rnd = () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const data = new Uint8ClampedArray(page.w * page.h * 4);
  for (let y = 0; y < page.h; y++) for (let x = 0; x < page.w; x++) {
    const i = y * page.w + x, v = page.g[i] * light(x / page.w, y / page.h), n = (rnd() - 0.5) * 6;
    data[i * 4] = v * tint[0] + n; data[i * 4 + 1] = v * tint[1] + n; data[i * 4 + 2] = v * tint[2] + n; data[i * 4 + 3] = 255;
  }
  return { width: page.w, height: page.h, data };
}

/** Paper and ink levels: the page's own grey says which pixels are which. */
function measure(img, page) {
  const paper = [], ink = [];
  let cast = 0, nc = 0;
  for (let i = 0; i < page.g.length; i += 3) {
    const d = img.data, l = (d[i * 4] + d[i * 4 + 1] + d[i * 4 + 2]) / 3;
    if (page.g[i] > 235) { paper.push(l); cast += d[i * 4] - d[i * 4 + 2]; nc++; }
    else if (page.g[i] < 60) ink.push(l);
  }
  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const sorted = [...paper].sort((a, b) => a - b);
  return { paper: mean(paper), paperLow: sorted[Math.floor(sorted.length * 0.05)], ink: mean(ink), cast: cast / nc };
}

// light from the upper left, a soft shadow from the phone over the lower right, warm bulb
const SHADOWED = (x, y) => {
  const fall = 0.95 - 0.35 * x * y;
  const shadow = 1 - 0.4 / (1 + Math.exp(-(x - 0.62) * 25)) / (1 + Math.exp(-(y - 0.45) * 25));
  return fall * shadow;
};
const WARM = [1, 0.93, 0.82]; // what's left of a warm bulb after the phone's own white balance

test("a shadowed, warm-lit page comes out white and even, with dark ink", () => {
  const img = lit(PAGE, SHADOWED, WARM);
  const before = measure(img, PAGE);
  const out = cleanScan(img);
  const after = measure(out, PAGE);
  assert.ok(before.paperLow < 140, `the test page really is shadowed (${before.paperLow.toFixed(0)})`);
  assert.ok(after.paper > 248, `paper white: ${after.paper.toFixed(1)}`);
  assert.ok(after.paperLow > 235, `even in the shadow: darkest 5% of paper ${after.paperLow.toFixed(1)} (was ${before.paperLow.toFixed(1)})`);
  assert.ok(after.ink < 70, `ink stays dark: ${after.ink.toFixed(1)}`);
  assert.ok(after.paper - after.ink > before.paper - before.ink, "more contrast than before");
  assert.ok(Math.abs(after.cast) < Math.abs(before.cast) / 3, `warm cast taken off: ${before.cast.toFixed(1)} → ${after.cast.toFixed(1)}`);
  assert.equal(out.width, img.width);
  assert.equal(out.height, img.height);
  assert.ok(out.data !== img.data && img.data[3] === 255, "a new picture; the photo is untouched");
});

test("an evenly lit page is left alone apart from whiter paper", () => {
  const img = lit(PAGE, () => 0.93);
  const before = measure(img, PAGE), after = measure(cleanScan(img), PAGE);
  assert.ok(after.paper > 248);
  assert.ok(after.ink <= before.ink + 3, `ink not faded: ${before.ink.toFixed(1)} → ${after.ink.toFixed(1)}`);
});

test("a coloured form keeps its colour: only a mild cast is corrected", () => {
  // blue paper, neutral light
  const out = cleanScan(lit(PAGE, () => 0.95, [0.7, 0.84, 1]));
  let r = 0, b = 0, n = 0;
  for (let i = 0; i < PAGE.g.length; i += 5) if (PAGE.g[i] > 235) { r += out.data[i * 4]; b += out.data[i * 4 + 2]; n++; }
  assert.ok(b / n - r / n > 8, `still blue: R ${(r / n).toFixed(0)} B ${(b / n).toFixed(0)}`);
});

test("a page looks like paper; a card's front with a photo and a dark picture don't", () => {
  assert.ok(paperShare(lightField(lit(PAGE, SHADOWED, WARM))) >= 0.45, "a page");
  const dark = lit(PAGE, () => 0.25);
  assert.ok(cleanScan(dark).paper < 0.45 || paperShare(lightField(dark)) < 0.45, "a dark picture");
  // the ID card front: a portrait and printed fields over a tinted background
  const front = lit(FRONT, () => 1);
  const share = paperShare(lightField(front));
  assert.ok(share < 0.9, `card front ${share.toFixed(2)}`);
});
