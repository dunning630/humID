// Auto-capture for ID photos (apps/mobile/src/core/detect.js): it takes the photo only
// when a document of the right shape is lined up, lit, sharp and steady. Drawn test
// images stand in for the camera.
import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFrame, autoShutter, toGray, ASPECT } from "../apps/mobile/src/core/detect.js";

const W = 320, H = 300;
// the on-screen frame, as it sits in the crop the camera hands over (15% margin each side)
const guideFor = (shape) => {
  const gw = W / 1.3, gh = gw / ASPECT[shape];
  const x0 = (W - gw) / 2, y0 = (H - gh) / 2;
  return { x0: x0 / W, y0: y0 / H, x1: (x0 + gw) / W, y1: (y0 + gh) / H };
};

/** A scene: dark, slightly noisy table; optionally a document with some print on it. */
function scene({ shape = "id1", doc = true, scale = 1, dx = 0, dy = 0, card = 225, table = 50, glare = false, seed = 1 } = {}) {
  let r = seed;
  const rnd = () => ((r = (r * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const g = new Uint8ClampedArray(W * H);
  for (let i = 0; i < g.length; i++) g[i] = table + rnd() * 10;
  if (doc) {
    const gd = guideFor(shape);
    const cx = ((gd.x0 + gd.x1) / 2) * W + dx, cy = ((gd.y0 + gd.y1) / 2) * H + dy;
    const w = (gd.x1 - gd.x0) * W * scale, h = (gd.y1 - gd.y0) * H * scale;
    const x0 = Math.round(cx - w / 2), y0 = Math.round(cy - h / 2), x1 = Math.round(cx + w / 2), y1 = Math.round(cy + h / 2);
    for (let y = Math.max(0, y0); y < Math.min(H, y1); y++) for (let x = Math.max(0, x0); x < Math.min(W, x1); x++) {
      let v = card + rnd() * 6;
      if (y > y0 + h * 0.3 && y < y0 + h * 0.4 && x > x0 + w * 0.4 && x < x0 + w * 0.9) v = 40;   // a line of print
      if (y > y0 + h * 0.2 && y < y0 + h * 0.75 && x > x0 + w * 0.05 && x < x0 + w * 0.3) v = 140; // a photo
      if (glare && y > y0 + h * 0.1 && y < y0 + h * 0.9 && x > x0 + w * 0.1 && x < x0 + w * 0.9) v = 255;
      g[y * W + x] = v;
    }
  }
  return { w: W, h: H, g };
}
function blur(im, r = 4) {
  const out = new Uint8ClampedArray(im.g.length);
  for (let y = 0; y < im.h; y++) for (let x = 0; x < im.w; x++) {
    let s = 0, n = 0;
    for (let k = -r; k <= r; k++) for (let j = -r; j <= r; j++) { const xx = x + j, yy = y + k; if (xx >= 0 && yy >= 0 && xx < im.w && yy < im.h) { s += im.g[yy * im.w + xx]; n++; } }
    out[y * im.w + x] = s / n;
  }
  return { ...im, g: out };
}
const look = (im, opts = {}) => analyzeFrame(im, { guide: guideFor(opts.shape || "id1"), ...opts });

test("a card lined up in the frame, lit, sharp and steady: take it", () => {
  const a = scene(), b = scene({ seed: 2 });
  const r = look(b, { prev: a });
  assert.ok(r.found && r.aligned && r.light && r.sharp && r.steady && !r.glare, JSON.stringify(r));
  assert.equal(r.ok, true);
});

test("a passport page uses its own shape; a card where a passport is expected doesn't fit", () => {
  assert.equal(look(scene({ shape: "td3" }), { shape: "td3" }).ok, true);
  assert.equal(look(scene({ shape: "id1" }), { shape: "td3" }).aligned, false);
});

test("nothing in the frame, or only a table: never", () => {
  const r = look(scene({ doc: false }));
  assert.equal(r.found, false);
  assert.equal(r.ok, false);
  assert.match(r.hint, /Fit the document/);
});

test("too far away, or off to one side: says how to fix it", () => {
  const far = look(scene({ scale: 0.7 }));
  assert.equal(far.ok, false);
  assert.match(far.hint, /closer|Fit|Line/);
  const off = look(scene({ dx: 60 }));
  assert.equal(off.ok, false);
});

test("blurred (out of focus or moving): waits", () => {
  const r = look(blur(scene(), 3));
  assert.equal(r.sharp, false, `sharpness ${r.sharpness}`);
  assert.equal(r.ok, false);
});

test("too dark, or glare across it: says so", () => {
  const dim = scene(); dim.g = dim.g.map((v) => v * 0.18); // the same scene in a dark room
  const dark = look(dim);
  assert.equal(dark.light, false);
  assert.match(dark.hint, /more light/);
  const glare = look(scene({ glare: true }));
  assert.equal(glare.glare, true);
  assert.match(glare.hint, /Glare/);
});

test("the picture moved since the last look: waits", () => {
  const r = look(scene({ dx: 4 }), { prev: scene({ dx: -14 }) });
  assert.equal(r.steady, false);
  assert.equal(r.ok, false);
});

test("the shutter needs several good looks in a row; a bad one starts again", () => {
  const s = autoShutter({ need: 3 });
  const good = { ok: true }, bad = { ok: false };
  assert.deepEqual([good, good, bad, good, good].map((l) => s.feed(l)), [false, false, false, false, false]);
  assert.equal(s.feed(good), true);
});

test("toGray weighs green most, like the eye", () => {
  const g = toGray({ width: 3, height: 1, data: Uint8ClampedArray.from([255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255]) });
  assert.ok(g.g[1] > g.g[0] && g.g[0] > g.g[2]);
});
