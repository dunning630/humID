// The document camera's guidance (apps/mobile/src/core/lookstate.js, 5.0): the one set of rules
// every camera follows (the iPhone and Android ports copy it; tests/fixtures/guidance.json is the
// golden set the Android unit test runs too), and the web camera's zoom for the lens's minimum
// focus distance (core/webcam.js).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { guidance, fitOf, changed, RULES } from "../apps/mobile/src/core/lookstate.js";
import { zoomFor, fovAcross } from "../apps/mobile/src/core/webcam.js";

const G = JSON.parse(readFileSync(new URL("./fixtures/guidance.json", import.meta.url), "utf8"));

for (const c of G.fit) {
  test(`fit: ${c.name} → ${c.key}`, () => {
    assert.equal(fitOf(c.quad, c.frame, c.ratio), c.key);
  });
}

for (const r of G.runs) {
  test(`guidance: ${r.name}`, () => {
    const g = guidance();
    const out = r.frames.map((f) => g.feed(f.m, f.t));
    for (const e of r.expect) {
      const got = out[e.i];
      for (const [k, v] of Object.entries(e)) if (k !== "i") assert.deepEqual(got[k], v, `frame ${e.i} ${k}: ${JSON.stringify(got)}`);
    }
  });
}

test("the rules' numbers are the audit's (focusing after 250 ms of real AF, too close after 600 ms, a 300 ms hold)", () => {
  assert.equal(RULES.focusingMs, 250);
  assert.equal(RULES.tooCloseMs, 600);
  assert.equal(RULES.holdMs, 300);
});

test("'focusing' never comes from a look the camera hasn't called scanning", () => {
  const g = guidance();
  for (let t = 0; t < 3000; t += 100) {
    for (const focus of [null, "focused"]) {
      const l = g.feed({ found: true, fit: null, light: "ok", focus, steady: t % 400 !== 0, sharp: t % 700 !== 0 }, t);
      assert.notEqual(l.state, "focusing", `t=${t} focus=${focus}`);
    }
  }
});

test("reset starts a fresh attempt: it can fire again", () => {
  const g = guidance();
  const m = { found: true, fit: null, light: "ok", focus: "focused", steady: true };
  g.feed(m, 0);
  assert.equal(g.feed(m, 300).fire, true);
  assert.equal(g.feed(m, 600).fire, false, "once");
  g.reset();
  g.feed(m, 1000);
  assert.equal(g.feed(m, 1300).fire, true);
});

test("losing the document lets go of the hold and the corners", () => {
  const g = guidance();
  const m = { found: true, quad: [[0, 0], [1, 0], [1, 1], [0, 1]], fit: null, light: "ok", focus: "focused", steady: true };
  g.feed(m, 0);
  const lost = g.feed({ found: false, light: "ok" }, 100);
  assert.equal(lost.state, "searching"); assert.equal(lost.quad, null); assert.equal(lost.aligned, false);
  g.feed(m, 500);
  assert.equal(g.feed(m, 700).fire, false, "the hold starts again");
  assert.equal(g.feed(m, 800).fire, true);
});

test("changed(): only what the screen would draw differently is sent", () => {
  const a = { state: "sharp", key: null, focus: "focused", light: "ok", steady: true, aligned: true, progress: 0.31, quad: [[0, 0], [100, 0], [100, 60], [0, 60]] };
  assert.equal(changed(null, a), true);
  assert.equal(changed(a, { ...a }), false);
  assert.equal(changed(a, { ...a, progress: 0.33 }), false, "the ring by less than a tenth");
  assert.equal(changed(a, { ...a, progress: 0.42 }), true);
  assert.equal(changed(a, { ...a, quad: a.quad.map(([x, y]) => [x + 0.5, y]) }), false, "the corners by less than 1%");
  assert.equal(changed(a, { ...a, quad: a.quad.map(([x, y]) => [x + 3, y]) }), true);
  assert.equal(changed(a, { ...a, state: "focusing" }), true);
  assert.equal(changed(a, { ...a, quad: null }), true);
});

test("zoom from the minimum focus distance: z = 1.25 × MFD / d_fill(1×), within 1..2.5 and the camera's max", () => {
  // a card filling 92% of a portrait view's width, 24 mm-equivalent lens, 1080×1920
  const fov = fovAcross(1080, 1920);
  assert.ok(fov > 35 && fov < 50, `about 40° across a portrait view: ${fov}`);
  const base = { docMm: 85.6, frameFrac: 0.92, fovDeg: fov };
  // a card fills the frame at about 13 cm at 1×: a 20 cm minimum focus distance asks for about 2×
  const z = zoomFor({ ...base, mfdMm: 200 });
  assert.ok(z > 1.7 && z < 2.3, `z=${z}`);
  assert.equal(zoomFor({ ...base, mfdMm: 80 }), 1, "a camera that focuses close needs no zoom");
  assert.equal(zoomFor({ ...base, mfdMm: 600 }), 2.5, "never more than 2.5");
  assert.equal(zoomFor({ ...base, mfdMm: 600, max: 2 }), 2, "never more than the camera has");
  assert.equal(zoomFor({ ...base, mfdMm: 0 }), 1, "unknown: no zoom");
  assert.ok(zoomFor({ ...base, mfdMm: 200, docMm: 125 }) < z, "a passport page is bigger: less zoom");
  assert.equal(zoomFor({ ...base, mfdMm: 200, docMm: 216 }), 1, "a page needs none");
});
