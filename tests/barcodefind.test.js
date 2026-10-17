// Finding a barcode anywhere in the camera's view (apps/mobile/src/core/barcodefind.js),
// the way a store's scan-and-go app does. The specimen license's back (test data,
// tests/fixtures/docs/card-back.pgm.gz, from tests/fixtures/id/card-back.jpg) is laid
// into 1920×1080 camera-like views: centred, sideways, small and far, tilted, on a
// desk covered in printed text, with sensor noise. The camera looks at a 400 px copy,
// then closer around what stood out; these tests do the same.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { locateBarcode, locateBarcodes, searchBox, readBox, fromArea, barAngle, barTracker, boxCorners, overlap } from "../apps/mobile/src/core/barcodefind.js";
import { shrink } from "../apps/mobile/src/core/docfind.js";

const fixture = (n) => {
  const b = gunzipSync(readFileSync(new URL(`./fixtures/docs/${n}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
};
const BACK = fixture("card-back"), FRONT = fixture("card-front"), LETTER = fixture("page-letter");
// where the barcode is on the card (500×316)
const BAR = { x0: 24, y0: 83, x1: 476, y1: 242 };

/**
 * A W×H view with `card` centred at (cx, cy), `size` px wide, turned `deg` clockwise.
 * desk: a grey level, or "text" (a printed page under everything). Returns { view,
 * truth (the barcode's box in the view) }.
 */
function view({ card = BACK, cx, cy, size, deg = 0, W = 1920, H = 1080, desk = 70, seed = 1 }) {
  let r = seed;
  const rnd = () => ((r = (r * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const s = size / card.w, a = (deg * Math.PI) / 180, cos = Math.cos(a), sin = Math.sin(a);
  const g = new Uint8ClampedArray(W * H);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const dx = x - cx, dy = y - cy;
    const u = (dx * cos + dy * sin) / s + card.w / 2, v = (-dx * sin + dy * cos) / s + card.h / 2;
    let val;
    if (u >= 0 && v >= 0 && u < card.w - 1 && v < card.h - 1) val = card.g[(v | 0) * card.w + (u | 0)];
    else if (desk === "text") val = 30 + 0.75 * LETTER.g[((y >> 1) % LETTER.h) * LETTER.w + ((x >> 1) % LETTER.w)];
    else val = desk;
    g[y * W + x] = val + (rnd() - 0.5) * 12;
  }
  const corners = [[BAR.x0, BAR.y0], [BAR.x1, BAR.y0], [BAR.x1, BAR.y1], [BAR.x0, BAR.y1]].map(([u, v]) => {
    const px = (u - card.w / 2) * s, py = (v - card.h / 2) * s;
    return { x: cx + px * cos - py * sin, y: cy + px * sin + py * cos };
  });
  const xs = corners.map((p) => p.x), ys = corners.map((p) => p.y);
  const truth = { x: Math.min(...xs), y: Math.min(...ys), w: Math.max(...xs) - Math.min(...xs), h: Math.max(...ys) - Math.min(...ys) };
  return { view: { w: W, h: H, g }, truth };
}

/** A part of a grey image. */
function crop(im, b) {
  const x0 = Math.round(b.x), y0 = Math.round(b.y), w = Math.round(b.w), h = Math.round(b.h);
  const g = new Uint8ClampedArray(w * h);
  for (let y = 0; y < h; y++) g.set(im.g.subarray((y0 + y) * im.w + x0, (y0 + y) * im.w + x0 + w), y * w);
  return { w, h, g };
}

/** As the camera does: a 400 px look at everything, then a closer look around the strongest. */
function find(v) {
  const small = shrink(v, 400), k = v.w / small.w;
  const spot = locateBarcode(small);
  if (!spot) return null;
  const coarse = { box: fromArea(spot.box, { x: 0, y: 0 }, k), upright: spot.upright };
  const win = searchBox(coarse, v.w, v.h);
  const near = shrink(crop(v, win), 720);
  const closer = locateBarcodes(near).map((c) => ({ box: fromArea(c.box, win, win.w / near.w), upright: c.upright })).find((c) => overlap(c.box, coarse.box) > 0.3);
  return closer || coarse;
}

/** Share of `inner` inside `outer`. */
function inside(inner, outer) {
  const w = Math.min(inner.x + inner.w, outer.x + outer.w) - Math.max(inner.x, outer.x);
  const h = Math.min(inner.y + inner.h, outer.y + outer.h) - Math.max(inner.y, outer.y);
  return w <= 0 || h <= 0 ? 0 : (w * h) / (inner.w * inner.h);
}

const CASES = [
  { name: "held up close, centred", at: { cx: 960, cy: 540, size: 1100 }, upright: true },
  { name: "sideways, off to the right", at: { cx: 1500, cy: 520, size: 700, deg: 90 }, upright: false },
  { name: "small and far, low left corner, on a desk of printed text", at: { cx: 330, cy: 860, size: 430, desk: "text" }, upright: true },
  { name: "tilted 8°, on printed text", at: { cx: 1200, cy: 600, size: 640, deg: 8, desk: "text" }, upright: true },
  { name: "sideways and tilted (93°), lower right, on printed text", at: { cx: 1550, cy: 700, size: 520, deg: 93, desk: "text" }, upright: false },
  { name: "upside down", at: { cx: 800, cy: 500, size: 760, deg: 180 }, upright: true },
];

for (const c of CASES) {
  test(`finds the barcode anywhere in view: ${c.name}`, () => {
    const { view: v, truth } = view(c.at);
    const found = find(v);
    assert.ok(found, "no barcode found");
    assert.equal(found.upright, c.upright, "which way the bars run");
    // the highlight sits on the barcode: mostly inside it, covering most of it
    assert.ok(inside(found.box, { x: truth.x - 20, y: truth.y - 20, w: truth.w + 40, h: truth.h + 40 }) > 0.85, `highlight off the barcode: ${JSON.stringify(found.box)} vs ${JSON.stringify(truth)}`);
    assert.ok(inside(truth, found.box) > 0.6, `highlight covers too little: ${JSON.stringify(found.box)} vs ${JSON.stringify(truth)}`);
    // and what's handed to the reader holds all of it
    const rb = readBox(found, v.w, v.h);
    assert.ok(inside(truth, rb) > 0.97, `the reader's crop cuts the barcode: ${JSON.stringify(rb)} vs ${JSON.stringify(truth)}`);
    assert.ok(rb.w * rb.h < v.w * v.h * 0.6, "the reader's crop is a spot, not the whole view");
  });
}

test("the bars' tilt is measured, so the crop can be turned exactly upright", () => {
  for (const deg of [0, 3, -8, 12, 87, 93, 180]) {
    const { view: v, truth } = view({ cx: 960, cy: 540, size: 900, deg });
    const a = barAngle(v, truth);
    // bars upright are 0; the gradient runs across them, which is the card's own tilt
    const want = ((deg + 90) % 180) - 90;
    const diff = Math.abs(((a - want + 270) % 180) - 90);
    assert.ok(diff < 1.5, `tilt ${deg}°: measured ${a.toFixed(2)}°`);
  }
});

test("text, an ID's front and an empty table aren't taken for a barcode", () => {
  const empty = view({ card: BACK, cx: -5000, cy: 0, size: 10, desk: 90 }).view;
  assert.equal(locateBarcode(shrink(empty, 400)), null, "empty table");
  for (const size of [1500, 900, 600]) {
    const front = view({ card: FRONT, cx: 960, cy: 540, size }).view;
    assert.equal(locateBarcode(shrink(front, 400)), null, `ID front at ${size} px`);
  }
  for (const k of [1, 2, 3]) {
    // a full view of printed text at three sizes
    const W = 1200, H = 900, g = new Uint8ClampedArray(W * H);
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) g[y * W + x] = LETTER.g[(((y / k) | 0) % LETTER.h) * LETTER.w + (((x / k) | 0) % LETTER.w)];
    assert.equal(locateBarcode(shrink({ w: W, h: H, g }, 400)), null, `printed text at ${k}×`);
  }
});

test("a store card's barcode beside the license: both found, either can be passed over", () => {
  const a = view({ cx: 520, cy: 540, size: 760 }).view;
  const b = view({ cx: 1480, cy: 560, size: 640, deg: 90 });
  // two cards in one view: the left half of one, the right half of the other
  const g = new Uint8ClampedArray(a.g.length);
  for (let y = 0; y < 1080; y++) for (let x = 0; x < 1920; x++) g[y * 1920 + x] = x < 960 ? a.g[y * 1920 + x] : b.view.g[y * 1920 + x];
  const small = shrink({ w: 1920, h: 1080, g }, 400), k = 1920 / small.w;
  const all = locateBarcodes(small).map((c) => fromArea(c.box, { x: 0, y: 0 }, k));
  assert.ok(all.length >= 2, `found ${all.length}`);
  assert.ok(all.some((x) => x.x + x.w / 2 < 960) && all.some((x) => x.x + x.w / 2 > 960), "one on each side");
});

test("the reader's crop reaches both ways from a far barcode's end bars, and stays in view", () => {
  // only the start bars seen: a narrow, tall patch (bars upright)
  const rb = readBox({ box: { x: 900, y: 500, w: 40, h: 120 }, upright: true }, 1920, 1080);
  assert.ok(rb.x < 900 - 300 && rb.x + rb.w > 940 + 300, `stretched both ways across the bars: ${JSON.stringify(rb)}`);
  assert.ok(rb.h < 200, "not along them");
  const edge = readBox({ box: { x: 10, y: 1000, w: 70, h: 30 }, upright: false }, 1920, 1080);
  assert.ok(edge.x >= 0 && edge.y >= 0 && edge.x + edge.w <= 1920 && edge.y + edge.h <= 1080, "kept inside the view");
  const win = searchBox({ box: { x: 900, y: 500, w: 40, h: 120 }, upright: true }, 1920, 1080);
  assert.ok(win.x <= 900 - 400 && win.x + win.w >= 940 + 400, "the closer look covers a whole license barcode either way");
});

test("the highlight glides, holds through a missed look or two, and lets go", () => {
  const t = barTracker({ lose: 3 });
  assert.equal(t.feed(null, 0), null);
  const a = t.feed({ box: { x: 100, y: 100, w: 300, h: 100 } }, 1000);
  assert.deepEqual(a, { x: 100, y: 100, w: 300, h: 100 });
  const b = t.feed({ box: { x: 110, y: 104, w: 300, h: 100 } }, 1100);
  assert.ok(b.x > 100 && b.x < 110, "smoothed, not jumped");
  assert.equal(t.held(1500), 500);
  assert.ok(t.feed(null, 1600) && t.feed(null, 1700), "held through two misses");
  assert.equal(t.feed(null, 1800), null, "let go after three");
  // a different barcode somewhere else: jumps there, and the clock restarts
  t.feed({ box: { x: 100, y: 100, w: 300, h: 100 } }, 2000);
  const far = t.feed({ box: { x: 1200, y: 700, w: 200, h: 80 } }, 2100);
  assert.deepEqual(far, { x: 1200, y: 700, w: 200, h: 80 });
  assert.equal(t.held(2200), 100);
  assert.equal(boxCorners({ x: 1, y: 2, w: 3, h: 4 }).length, 4);
  assert.equal(overlap({ x: 0, y: 0, w: 10, h: 10 }, { x: 5, y: 5, w: 100, h: 100 }), 0.25);
});

test("quick enough to run on every look", () => {
  const { view: v } = view({ cx: 1500, cy: 700, size: 520, deg: 93, desk: "text" });
  const small = shrink(v, 400);
  for (let i = 0; i < 5; i++) locateBarcode(small);
  const t = performance.now();
  for (let i = 0; i < 10; i++) locateBarcode(small);
  const ms = (performance.now() - t) / 10;
  assert.ok(ms < 120, `${ms.toFixed(1)} ms a look`);
});
