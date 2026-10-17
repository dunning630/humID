// Finding a document anywhere in the camera's view, straightening it and turning it
// upright (apps/mobile/src/core/docfind.js). Real text pages (rendered once with real
// fonts, tests/fixtures/docs) are laid into camera-like views here: tilted, in
// perspective, off-centre, on plain, dark and grained tables, with a thumb over one
// side and sensor noise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { findDocument, lookAt, tracker, homography, warp, outputSize, orientation, rotateGray, shrink, toGray, PAPER } from "../apps/mobile/src/core/docfind.js";

const fixture = (n) => {
  const b = gunzipSync(readFileSync(new URL(`./fixtures/docs/${n}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
};
const PAGES = { letter: fixture("page-letter"), a4: fixture("page-a4"), card: fixture("page-card") };

/** Invert the rectangle → corners map, to draw a page into a view. */
function inverse(H) {
  const [a, b, c, d, e, f, g, h] = H;
  const m = [[a, b, c], [d, e, f], [g, h, 1]];
  const det = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
  const inv = [
    [(m[1][1] * m[2][2] - m[1][2] * m[2][1]) / det, (m[0][2] * m[2][1] - m[0][1] * m[2][2]) / det, (m[0][1] * m[1][2] - m[0][2] * m[1][1]) / det],
    [(m[1][2] * m[2][0] - m[1][0] * m[2][2]) / det, (m[0][0] * m[2][2] - m[0][2] * m[2][0]) / det, (m[0][2] * m[1][0] - m[0][0] * m[1][2]) / det],
    [(m[1][0] * m[2][1] - m[1][1] * m[2][0]) / det, (m[0][1] * m[2][0] - m[0][0] * m[2][1]) / det, (m[0][0] * m[1][1] - m[0][1] * m[1][0]) / det],
  ];
  return (x, y) => { const z = inv[2][0] * x + inv[2][1] * y + inv[2][2]; return [(inv[0][0] * x + inv[0][1] * y + inv[0][2]) / z, (inv[1][0] * x + inv[1][1] * y + inv[1][2]) / z]; };
}

/**
 * A camera view W×H with `page` (turned `turn` degrees clockwise) whose corners land on
 * `quad` (tl, tr, br, bl of the turned page). table: grey level or "grain"; thumb: cover
 * part of one side.
 */
function view({ page, turn = 0, quad, W = 960, H = 720, table = 60, thumb = false, seed = 1 }) {
  let r = seed;
  const rnd = () => ((r = (r * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const p = rotateGray(page, turn);
  const back = inverse(homography(p.w, p.h, quad));
  const g = new Uint8ClampedArray(W * H);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const [u, v] = back(x + 0.5, y + 0.5);
    let val;
    if (u >= 0 && v >= 0 && u < p.w - 1 && v < p.h - 1) val = p.g[(v | 0) * p.w + (u | 0)];
    else val = table === "grain" ? 105 + 18 * Math.sin(x / 9 + 3 * Math.sin(y / 50)) : table;
    if (thumb) { const dx = x - thumb.x, dy = (y - thumb.y) / 1.4; if (dx * dx + dy * dy < thumb.r * thumb.r) val = 150 + (x % 7); }
    g[y * W + x] = Math.max(0, Math.min(255, val * (0.88 + 0.12 * (x / W)) + (rnd() - 0.5) * 10));
  }
  return { w: W, h: H, g };
}

/** Corners for a page centred at (cx, cy), long-side `size`, tilted `deg`, `k` perspective. */
function place(page, turn, { cx, cy, size, deg = 0, k = 0 }) {
  const sideways = turn % 180 !== 0;
  const pw = sideways ? page.h : page.w, ph = sideways ? page.w : page.h;
  const s = size / Math.max(pw, ph), w = pw * s, h = ph * s, a = (deg * Math.PI) / 180;
  return [[-w / 2 * (1 - k), -h / 2], [w / 2 * (1 - k), -h / 2], [w / 2 * (1 + k), h / 2], [-w / 2 * (1 + k), h / 2]]
    .map(([x, y]) => ({ x: cx + x * Math.cos(a) - y * Math.sin(a), y: cy + x * Math.sin(a) + y * Math.cos(a) }));
}

/** Worst corner distance between two outlines (as fractions of the view's diagonal). */
function cornerError(found, truth, W, H) {
  let best = Infinity;
  for (let s = 0; s < 4; s++) best = Math.min(best, Math.max(...truth.map((t, i) => Math.hypot(found[(i + s) % 4].x - t.x, found[(i + s) % 4].y - t.y))));
  return best / Math.hypot(W, H);
}

/** Look as the camera does: a 320 px copy, corners scaled back to the view. */
function find(v, opts) {
  const small = shrink(v, 320), k = v.w / small.w;
  const d = findDocument(small, opts);
  return d && { ...d, quad: d.quad.map((p) => ({ x: p.x * k, y: p.y * k })) };
}

const CASES = [
  { name: "a letter page, upright, off to the left on a dark table", page: "letter", turn: 0, at: { cx: 330, cy: 380, size: 560, deg: -6 } },
  { name: "an A4 page, tilted 18° and in perspective, low on a grained table", page: "a4", turn: 0, at: { cx: 560, cy: 420, size: 520, deg: 18, k: 0.1 }, table: "grain" },
  { name: "a letter page upside down, top right, on a mid-grey table", page: "letter", turn: 180, at: { cx: 640, cy: 330, size: 500, deg: 9 }, table: 120 },
  { name: "a letter page sideways, a thumb over its left side", page: "letter", turn: 90, at: { cx: 480, cy: 360, size: 640, deg: -12, k: 0.06 }, thumb: true },
  { name: "a card, small and far right, tilted the other way", page: "card", turn: 0, at: { cx: 700, cy: 300, size: 380, deg: -20 }, ratio: PAPER.id1 },
  { name: "a card standing on end, in perspective", page: "card", turn: 270, at: { cx: 420, cy: 400, size: 460, deg: 7, k: 0.08 }, ratio: PAPER.id1, table: 35 },
];

for (const c of CASES) {
  test(`finds the document anywhere in view: ${c.name}`, () => {
    const page = PAGES[c.page];
    const quad = place(page, c.turn, c.at);
    let thumb = false;
    if (c.thumb) { const a = quad[3], b = quad[0]; thumb = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, r: 55 }; }
    const v = view({ page, turn: c.turn, quad, table: c.table ?? 60, thumb });
    const d = find(v, { ratio: c.ratio || null });
    assert.ok(d, "no document found");
    const err = cornerError(d.quad, quad, v.w, v.h);
    assert.ok(err < 0.012, `corners off by ${(err * 100).toFixed(1)}% of the view`);
  });
}

test("straightens it and works out which way up it reads, for every turn", () => {
  for (const name of ["letter", "a4"]) {
    for (const turn of [0, 90, 180, 270]) {
      const page = PAGES[name];
      const quad = place(page, turn, { cx: 480, cy: 360, size: 680, deg: 8, k: 0.05 });
      const v = view({ page, turn, quad, W: 960, H: 720, table: 50, seed: turn + 3 });
      const d = find(v);
      assert.ok(d, `${name} turned ${turn}: not found`);
      const rgba = { width: v.w, height: v.h, data: new Uint8ClampedArray(v.w * v.h * 4) };
      for (let i = 0; i < v.g.length; i++) rgba.data[i * 4] = rgba.data[i * 4 + 1] = rgba.data[i * 4 + 2] = v.g[i];
      const size = outputSize(d.quad, { max: 1400 });
      const flat = toGray(warp(rgba, d.quad, size.width, size.height));
      const o = orientation(flat);
      assert.equal(o.rotate, (360 - turn) % 360, `${name} turned ${turn}: proposed ${o.rotate}`);
    }
  }
});

test("which way up, straight from the page: pages and a card, all four turns", () => {
  for (const [name, landscape] of [["letter", false], ["a4", false], ["card", true]]) {
    for (const turn of [0, 90, 180, 270]) {
      const o = orientation(rotateGray(PAGES[name], turn), { landscape });
      assert.equal(o.rotate, (360 - turn) % 360, `${name} turned ${turn}: proposed ${o.rotate} (${o.lines}, ${o.confidence})`);
    }
  }
});

test("a blank sheet: no confident turn proposed", () => {
  const g = new Uint8ClampedArray(600 * 800).fill(230);
  const o = orientation({ w: 600, h: 800, g });
  assert.equal(o.rotate, 0);
  assert.equal(o.confidence, 0);
});

test("nothing there: an empty table, or a busy one with no document", () => {
  const empty = view({ page: PAGES.card, quad: place(PAGES.card, 0, { cx: -2000, cy: -2000, size: 10 }), table: 70 });
  assert.equal(find(empty), null);
  const grain = view({ page: PAGES.card, quad: place(PAGES.card, 0, { cx: -2000, cy: -2000, size: 10 }), table: "grain" });
  assert.equal(find(grain), null);
});

test("the straightened page keeps its proportions (snapped to a known paper size)", () => {
  const page = PAGES.letter;
  const quad = place(page, 0, { cx: 480, cy: 360, size: 650, deg: 0, k: 0.08 });
  const v = view({ page, quad });
  const d = find(v);
  const size = outputSize(d.quad);
  assert.ok(Math.abs(size.height / size.width - PAPER.letter) < 0.01, `${size.width}×${size.height}`);
  const card = outputSize([{ x: 0, y: 0 }, { x: 320, y: 4 }, { x: 318, y: 206 }, { x: 2, y: 200 }], { prefer: "id1" });
  assert.ok(Math.abs(card.width / card.height - PAPER.id1) < 0.01);
});

test("warp maps the corners exactly and stays inside the picture", () => {
  const H = homography(100, 50, [{ x: 10, y: 20 }, { x: 210, y: 30 }, { x: 200, y: 140 }, { x: 5, y: 120 }]);
  const map = (x, y) => { const z = H[6] * x + H[7] * y + 1; return [(H[0] * x + H[1] * y + H[2]) / z, (H[3] * x + H[4] * y + H[5]) / z]; };
  assert.deepEqual(map(0, 0).map(Math.round), [10, 20]);
  assert.deepEqual(map(100, 50).map(Math.round), [200, 140]);
  const src = { width: 4, height: 4, data: new Uint8ClampedArray(64).fill(200) };
  const out = warp(src, [{ x: -5, y: -5 }, { x: 9, y: -5 }, { x: 9, y: 9 }, { x: -5, y: 9 }], 8, 8);
  assert.ok(out.data.every((v, i) => (i % 4 === 3 ? v === 255 : v === 200)));
});

test("live: the outline settles and the photo is taken only once it holds still", () => {
  const page = PAGES.letter;
  const t = tracker({ need: 4 });
  let fired = false, prev = null, prior = null;
  // the hand moves for three looks, then holds
  const at = [{ cx: 380, cy: 360 }, { cx: 430, cy: 350 }, { cx: 470, cy: 365 }, ...Array(6).fill({ cx: 480, cy: 360 })];
  for (const [i, p] of at.entries()) {
    const v = shrink(view({ page, quad: place(page, 0, { ...p, size: 640, deg: 4 }), seed: i + 1 }), 320);
    const look = lookAt(v, { shape: "full", prev, prior });
    prev = v;
    const r = t.feed(look, v.w, v.h);
    prior = r.quad;
    assert.ok(look.found, `look ${i}: ${look.hint}`);
    if (i < 5) assert.equal(r.fire, false, `fired too early, at look ${i}`);
    fired ||= r.fire;
  }
  assert.ok(fired, "never took the photo");
});

test("live: hints say what's needed", () => {
  const page = PAGES.letter;
  const far = shrink(view({ page, quad: place(page, 0, { cx: 480, cy: 360, size: 260, deg: 3 }) }), 320);
  const look = lookAt(far, { shape: "full" });
  assert.ok(look.found && !look.ok);
  assert.match(look.hint, /closer/);
  const none = shrink(view({ page, quad: place(page, 0, { cx: -3000, cy: 0, size: 10 }) }), 320);
  assert.match(lookAt(none, { shape: "full" }).hint, /Point the camera/);
  const card = shrink(view({ page, quad: place(page, 0, { cx: 480, cy: 360, size: 600 }) }), 320);
  assert.match(lookAt(card, { shape: "id1" }).hint, /card/, "a letter page isn't a card");
});
