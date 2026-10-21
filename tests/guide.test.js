// The guided scan's pure parts (apps/mobile/src/core/guide.js, guidecap.js's maths, scanflow's guided words):
// the metrics read off a synthetic camera view, the verdict they give, the hold timer, the templates.
import { test } from "node:test";
import assert from "node:assert/strict";
import { measure, judge, templateFor, holdTracker, liveConstraints, previewTurned, stillMapping, rectInStill, agree, RATIO, MESSAGES, TH, motionOf, quadFromEdges, zoomFor } from "../apps/mobile/src/core/guide.js";
import { begin, step, view, SAY_AFTER } from "../apps/mobile/src/core/capture.js";
import { SCAN_MODE } from "../apps/mobile/src/core/addroute.js";
import { scene, pgm, blur } from "./support/guideview.js";

const back = pgm("card-back"), front = pgm("card-front"), pp = pgm("passport-page");
const LIC = templateFor({ kind: "driver_license", side: "back", read: { barcode: true } });
const PP = templateFor({ kind: "passport", side: "front", shape: "td3", read: { mrz: true } });
const verdict = (o, tpl = LIC) => {
  const { im, guide } = scene(o), prev = scene({ ...o, seed: 9 }).im;
  const m = measure(im, guide, { prev });
  return { m, v: judge(m, tpl, {}) };
};
const GOOD = { card: back, table: 62, size: 0.97 };

test("a card that fills the outline is present, aligned, steady, sharp and ready", () => {
  const { v } = verdict(GOOD);
  assert.equal(v.key, null); assert.ok(v.present && v.aligned && v.ready, JSON.stringify(v));
});

test("size: too small says Move closer, a bit small says Fill, too big says Move back", () => {
  assert.equal(verdict({ ...GOOD, size: 0.6 }).v.key, "closer");
  assert.equal(verdict({ ...GOOD, size: 0.8 }).v.key, "fill");
  assert.equal(verdict({ ...GOOD, size: 1.35 }).v.key, "back");
  for (const o of [{ size: 0.6 }, { size: 1.35 }]) assert.equal(verdict({ ...GOOD, ...o }).v.ready, false);
});

test("off to the side, the message says which way", () => {
  const { v } = verdict({ ...GOOD, dx: 0.12 });
  assert.equal(v.key, "shift"); assert.match(v.detail, /left|right/i);
});

test("turned in the plane says to straighten, small turns are left to the deskew", () => {
  assert.equal(verdict({ ...GOOD, size: 0.93, deg: 8 }).v.key, "tilt");
  const small = verdict({ ...GOOD, size: 0.95, deg: 3 }).v;
  assert.equal(small.key, null); assert.ok(small.deskew > 1 && small.deskew <= 10 || Math.abs(small.deskew) > 1, "deskew " + small.deskew);
});

test("a phone held at an angle (keystone) says to hold it flat", () => {
  assert.equal(verdict({ ...GOOD, keyV: 0.1 }).v.key, "flat");
});

test("blur is judged against sharpness, glare against saturated patches, light against brightness", () => {
  assert.equal(verdict({ ...GOOD, blurPx: 3 }).v.key, "blur");
  assert.equal(verdict({ ...GOOD, glare: 0.18 }).v.key, "glare");
  assert.equal(verdict({ ...GOOD, dark: 0.25 }).v.key, "dark");
  assert.equal(MESSAGES.dark.help, "light");
});

test("nothing in view is not an alarm: an empty desk, dark or light, says nothing but dark rooms", () => {
  const e = verdict({ card: back, size: 0.97, empty: true });
  assert.equal(e.v.present, false); assert.equal(e.v.ready, false);
  assert.equal(verdict({ card: back, size: 0.97, empty: true, table: "grain" }).v.key, null);
});

test("a passport page works on the wider template and says so in its words", () => {
  const ok = verdict({ card: pp, ratio: RATIO.td3, size: 0.97 }, PP).v;
  assert.ok(ok.ready, JSON.stringify(ok));
  const t = verdict({ card: pp, ratio: RATIO.td3, size: 0.93, deg: 9 }, PP).v;
  assert.equal(t.key, "tilt");
  assert.equal(verdict({ card: pp, ratio: RATIO.td3, size: 0.65 }, PP).v.key, "closer");
});

test("motion: the same view twice is still, a moved one is not", () => {
  const a = scene(GOOD), b = scene({ ...GOOD, dx: 0.03, dy: 0.02 });
  assert.ok(motionOf(a.im, scene({ ...GOOD, seed: 9 }).im, a.guide) < TH.steady);
  assert.ok(motionOf(a.im, b.im, a.guide) > TH.steady);
});

test("sharpness is relative: a blurred picture scores lower than the same one sharp", () => {
  const s = scene(GOOD), b = { ...s.im, ...blur(s.im, 2) };
  assert.ok(measure(b, s.guide).focus < measure(s.im, s.guide).focus);
});

test("holdTracker: TH.holdMs of ready fires once; one bad look under the grace doesn't restart; a longer gap does", () => {
  const T = 1000, H = TH.holdMs, G = TH.graceMs; // performance.now() is never 0
  assert.ok(H <= 400, "3.1.1: a short hold: the sharpest moment, not a long wait for stillness");
  let h = holdTracker(), r;
  for (let t = 0; t < H; t += 50) { r = h.feed(true, T + t); assert.equal(r.fire, false); }
  assert.ok(r.progress > 0.7 && r.progress < 1);
  assert.equal(h.feed(true, T + H).fire, true);
  assert.equal(h.feed(true, T + H + 50).fire, false, "only once");
  h = holdTracker(); h.feed(true, T); h.feed(true, T + 100); h.feed(false, T + 150); // a gap within grace
  assert.equal(h.feed(true, T + H).fire, true);
  h = holdTracker(); h.feed(true, T); h.feed(true, T + 100); h.feed(false, T + 150); h.feed(false, T + 100 + G + 50); // past grace
  assert.equal(h.feed(true, T + 100 + G + 100).fire, false);
  assert.equal(h.feed(true, T + 100 + G + 100 + H).fire, true);
});

test("3.1.1: the document's corners from its four measured edges (one missing is mirrored); nonsense is refused", () => {
  const { im, guide } = scene({ ...GOOD, size: 0.8 });
  const q = quadFromEdges(measure(im, guide).edges, guide);
  assert.ok(q, "found");
  const w = (q[1].x - q[0].x + q[2].x - q[3].x) / 2, h = (q[3].y - q[0].y + q[2].y - q[1].y) / 2;
  assert.ok(Math.abs(w / guide.w - 0.8) < 0.03, `width ${(w / guide.w).toFixed(3)} of the outline`);
  assert.ok(Math.abs(w / h - RATIO.id1) < 0.06, `card proportions ${(w / h).toFixed(3)}`);
  const cx = (q[0].x + q[2].x) / 2, cy = (q[0].y + q[2].y) / 2;
  assert.ok(Math.abs(cx - (guide.x + guide.w / 2)) < 3 && Math.abs(cy - (guide.y + guide.h / 2)) < 3, "centred where it lies");
  const e = (off, slope = 0) => ({ found: true, off, slope });
  const three = quadFromEdges({ top: e(-0.1), bottom: e(-0.1), left: e(-0.1), right: { found: false } }, { x: 0, y: 0, w: 100, h: 60 });
  assert.ok(Math.abs(three[1].x - 90) < 1e-6, "the missing right side mirrors the left");
  assert.equal(quadFromEdges({ top: e(0), bottom: { found: false }, left: e(0), right: { found: false } }, { x: 0, y: 0, w: 100, h: 60 }), null);
  assert.equal(quadFromEdges({ top: e(-0.9), bottom: e(-0.9), left: e(0), right: e(0) }, { x: 0, y: 0, w: 100, h: 60 }), null, "top below bottom");
});

test("3.1.1: zoom so the phone is held far enough to focus, only where the camera offers zoom", () => {
  const card = templateFor({ kind: "card" }), page = templateFor({ kind: "page" });
  assert.equal(zoomFor(LIC, {}), 1, "no zoom offered: none");
  assert.equal(zoomFor(LIC, { zoom: { min: 1, max: 1 } }), 1);
  assert.equal(zoomFor(LIC, { zoom: { min: 1, max: 8, step: 0.1 } }), 2);
  assert.equal(zoomFor(card, { zoom: { min: 1, max: 1.6, step: 0.1 } }), 1.6, "as far as it goes");
  assert.equal(zoomFor(PP, { zoom: { min: 1, max: 8, step: 0.5 } }), 1.5);
  assert.equal(zoomFor(page, { zoom: { min: 1, max: 8 } }), 1, "a page is held far enough already");
});

test("the template follows the kind: ID-1 for cards and licences, ID-3 for passports; zones; forbid", () => {
  assert.equal(LIC.ratio, RATIO.id1); assert.equal(PP.ratio, RATIO.td3);
  assert.ok(Math.abs(RATIO.id1 - 85.6 / 54) < 1e-9 && Math.abs(RATIO.td3 - 125 / 88) < 1e-9);
  assert.equal(templateFor({ kind: "driver_license", side: "front" }).forbid.barcode, true);
  assert.equal(LIC.forbid.barcode, false);
  assert.equal(templateFor({ kind: "card", side: "back" }).shape, "id1");
  assert.ok(PP.zones.some((z) => /mrz/i.test(z.k)));
  for (const [k, mode] of Object.entries(SCAN_MODE || {})) {
    const tpl = templateFor({ kind: k, shape: mode?.passport || k === "passport" ? "td3" : "id1" });
    assert.ok(tpl.ratio === RATIO.id1 || tpl.ratio === RATIO.td3, k);
  }
});

test("live constraints ask for the long side only, never a crop (1080p; 1440p for a passport); a wrong-way preview is noticed and re-asked in the screen's orientation", () => {
  const c = liveConstraints(LIC, { portrait: true }), p = liveConstraints(PP, { portrait: true });
  assert.equal(c.width.ideal, 1920); assert.equal(c.height, undefined); assert.equal(c.resizeMode, "none");
  assert.equal(p.width.ideal, 2560); assert.equal(p.height, undefined);
  const e = liveConstraints(LIC, { portrait: true, exact: true }), q = liveConstraints(PP, { portrait: true, exact: true });
  assert.equal(e.width.ideal, 1080); assert.equal(e.height.ideal, 1920);
  assert.equal(q.width.ideal, 1440); assert.equal(q.height.ideal, 2560);
  assert.equal(liveConstraints(LIC, { portrait: false, exact: true }).width.ideal, 1920);
  assert.equal(previewTurned(1920, 1080, true), true); assert.equal(previewTurned(1080, 1920, true), false);
  assert.equal(previewTurned(1920, 1080, false), false); assert.equal(previewTurned(1080, 1080, true), true);
});

test("the still: mapping of the preview into a photo of another shape, and the framing check", () => {
  const m = stillMapping(1080, 1920, 3024, 4032);
  assert.ok(Math.abs(m.scale - 2.1) < 1e-9); assert.ok(m.ox > 0 && m.oy === 0);
  const r = rectInStill({ x: 100, y: 200, w: 300, h: 150 }, stillMapping(1080, 1920, 2160, 3840));
  assert.deepEqual(r, { x: 200, y: 400, w: 600, h: 300 });
  const a = { w: 40, h: 30, g: Uint8ClampedArray.from({ length: 1200 }, (_, i) => (i * 37 + ((i / 40) | 0) * 11) % 251) };
  assert.ok(agree(a, a).score > 0.99);
  const shifted = { w: 40, h: 30, g: new Uint8ClampedArray(1200) };
  for (let y = 0; y < 30; y++) for (let x = 0; x < 40; x++) shifted.g[y * 40 + x] = a.g[y * 40 + Math.min(39, x + 2)];
  const s = agree(a, shifted); assert.ok(s.score > 0.9 && Math.abs(s.dx) === 2, JSON.stringify(s));
  const other = { w: 40, h: 30, g: Uint8ClampedArray.from({ length: 1200 }, (_, i) => (i * i * 13 + 7) % 256) };
  assert.ok(agree(a, other).score < 0.6);
  assert.equal(agree(a, { w: 10, h: 10, g: new Uint8ClampedArray(100) }).score, -1);
});

test("the camera's machine on guided verdicts: aiming says the frame; a problem is said after its own delay", () => {
  let s = begin({ expect: "barcode", now: 0 });
  s = step(s, { t: "ready" }, 100);
  assert.match(view(s, { noun: "license" }).headline, /frame/i);
  assert.ok(SAY_AFTER.blur > 700 && SAY_AFTER.dark < SAY_AFTER.blur);
  const v = { key: "closer", detail: "x", present: true, aligned: false };
  s = step(s, { t: "look", v, progress: 0 }, 200);
  assert.notEqual(view(s).headline, "Move closer", "not at once");
  s = step(s, { t: "look", v, progress: 0 }, 1200);
  assert.equal(view(s).headline, "Move closer");
});

test("3.0.1: a paper page's outline stands up between US Letter and A4, and both line up in it", () => {
  const PAGE = templateFor({ kind: "page" });
  assert.equal(PAGE.shape, "page"); assert.equal(PAGE.ratio, RATIO.page); assert.equal(PAGE.noun, "page");
  assert.ok(RATIO.page > 11 / 8.5 && RATIO.page < 297 / 210);
  const letter = pgm("page-letter"), a4 = pgm("page-a4");
  for (const [name, page, size] of [["Letter", letter, 0.97], ["A4", a4, 0.94]]) {
    const o = { card: page, ratio: 1 / RATIO.page, size, table: 62 };
    const { im, guide } = scene(o), prev = scene({ ...o, seed: 9 }).im;
    const v = judge(measure(im, guide, { prev }), PAGE, {});
    assert.ok(v.ready, `${name} in the page outline: ${JSON.stringify({ key: v.key, scale: v.scale })}`);
  }
});

test("3.0.1: a page bright all over isn't glare; a bright patch on it still is", () => {
  const PAGE = templateFor({ kind: "page" });
  const m = { n: 1, sides: 4, p95: 255, mean: 230, p50: 245, patch: 20, sat: 0.7, energy: 12, scale: 0.97, edges: {}, dx: 0, dy: 0, rot: 0, rotSpread: 0, flatH: 0, flatV: 0, aspect: 0, focus: 2, motion: 0 };
  assert.notEqual(judge(m, PAGE, {}).key, "glare");
  assert.equal(judge({ ...m, sat: 0.2 }, PAGE, {}).key, "glare");
});
