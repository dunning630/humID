// What the camera asks for and the shape of the screen that shows it (5.0): scan.js's modes,
// the web camera's small copy and its corners (core/webcam.js on core/docfind.js), the warp
// maths, and the screen (screens/add/camera.jsx, brand/flows.css), checked as source like
// tests/ia.test.js does. The guidance itself is tests/lookstate.test.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { TIPS } from "../apps/mobile/src/core/capture.js";
import { findDocument, shrink, warp, homography, applyHomography } from "../apps/mobile/src/core/docfind.js";

const src = (f) => readFileSync(new URL(`../apps/mobile/src/${f}`, import.meta.url), "utf8");
const noComments = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

/* ---------------- scan modes: the entry point ---------------- */

test("scan.js names what each mode asks of the camera, for the Add camera to call", () => {
  const t = noComments(src("core/scan.js"));
  assert.match(t, /export const SCAN_MODES = \{/);
  for (const m of ["license", "passport", "card"]) assert.match(t, new RegExp(`\\b${m}: \\{`), `${m} mode`);
  assert.match(t, /export function scanOptions\(mode/);
  assert.match(t, /export function warmScan\(mode/);
  assert.match(t, /passport: \{\s*front: \{ shape: "td3", read: \{ mrz: true \}/);
  assert.match(t, /back: \{ shape: "id1", read: \{ barcode: true \}/);
  const cam = noComments(src("screens/add/camera.jsx"));
  assert.match(cam, /props\.mode \? scanOptions\(props\.mode/, "DocCamera takes a mode");
});

/* ---------------- the analysis ---------------- */

const fixture = (n) => {
  const b = gunzipSync(readFileSync(new URL(`./fixtures/docs/${n}.pgm.gz`, import.meta.url)));
  const head = b.toString("latin1", 0, 32).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  const w = +head[1], h = +head[2];
  return { w, h, g: new Uint8ClampedArray(b.subarray(head[0].length, head[0].length + w * h)) };
};

test("analysing small is as exact as analysing big: corners within 1% of the view", () => {
  const page = fixture("page-letter");
  const W = 960, H = 720, quad = [{ x: 220, y: 120 }, { x: 740, y: 150 }, { x: 720, y: 640 }, { x: 200, y: 600 }];
  const m = homography(page.w, page.h, quad);
  const rgba = { width: W, height: H, data: new Uint8ClampedArray(W * H * 4).fill(60) };
  const flat = { width: page.w, height: page.h, data: new Uint8ClampedArray(page.w * page.h * 4) };
  for (let i = 0; i < page.g.length; i++) { flat.data[i * 4] = flat.data[i * 4 + 1] = flat.data[i * 4 + 2] = page.g[i]; flat.data[i * 4 + 3] = 255; }
  // paint by forward-mapping every page pixel (dense enough at this scale) onto the view
  for (let y = 0; y < page.h; y++) for (let x = 0; x < page.w; x++) {
    const p = applyHomography(m, x + 0.5, y + 0.5);
    const px = Math.round(p.x), py = Math.round(p.y);
    for (let dy = 0; dy <= 1; dy++) for (let dx = 0; dx <= 1; dx++) {
      const o = ((py + dy) * W + px + dx) * 4;
      if (px + dx >= 0 && px + dx < W && py + dy >= 0 && py + dy < H) rgba.data[o] = rgba.data[o + 1] = rgba.data[o + 2] = page.g[y * page.w + x];
    }
  }
  const g = new Uint8ClampedArray(W * H);
  for (let i = 0; i < g.length; i++) g[i] = rgba.data[i * 4];
  const view = { w: W, h: H, g };
  for (const px of [320, 224]) {
    const small = shrink(view, px), k = W / small.w;
    const r = findDocument(small, { minArea: 0.12 });
    assert.ok(r, `found at ${px}`);
    const err = Math.max(...r.quad.map((p, i) => Math.hypot(p.x * k - quad[i].x, p.y * k - quad[i].y))) / Math.hypot(W, H);
    assert.ok(err < 0.012, `${px} px: corners off by ${(err * 100).toFixed(2)}%`);
  }
});

/* ---------------- warping a part ---------------- */

function demoCard(W = 900, H = 600) {
  // a source picture with structure everywhere, so any sampling difference shows
  const data = new Uint8ClampedArray(W * H * 4);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const o = (y * W + x) * 4, v = 128 + 90 * Math.sin(x / 7) * Math.cos(y / 11) + 30 * Math.sin((x + y) / 3);
    data[o] = v; data[o + 1] = v * 0.9; data[o + 2] = v * 0.8; data[o + 3] = 255;
  }
  return { width: W, height: H, data };
}
const PERSPECTIVE_QUAD = [{ x: 140, y: 90 }, { x: 760, y: 130 }, { x: 730, y: 470 }, { x: 110, y: 500 }];

test("a cropped warp is exactly that part of the whole warp", () => {
  const img = demoCard();
  const full = warp(img, PERSPECTIVE_QUAD, 500, 315);
  const part = warp(img, PERSPECTIVE_QUAD, 500, 315, { x: 0, y: 200, w: 500, h: 115 });
  assert.equal(part.width, 500);
  assert.equal(part.height, 115);
  for (let y = 0; y < 115; y++) for (let x = 0; x < 500; x++) {
    for (let c = 0; c < 4; c++) assert.equal(part.data[(y * 500 + x) * 4 + c], full.data[((y + 200) * 500 + x) * 4 + c]);
  }
});

/* ---------------- the screen ---------------- */

test("the camera screen: one panel under the frame, a live region, 44 px targets, native first, frame-paced web looks", () => {
  const cam = noComments(src("screens/add/camera.jsx"));
  const css = src("brand/flows.css");
  assert.match(cam, /class="dc-panel"/, "the panel is on the camera");
  assert.match(cam, /\{guided && panel\}/, "for a document with a frame, the panel hangs under the frame");
  assert.match(cam, /role="status" aria-atomic="true" aria-live=\{/, "the words are a live region");
  for (const w of ["Try again", "Keep the photo", "Continue"]) assert.match(cam, new RegExp(w), `${w} is one tap away`);
  assert.match(noComments(src("core/webcam.js")), /requestVideoFrameCallback/, "the web camera is paced by the video's frames");
  assert.match(cam, /nat\.available\s*\?\s*await openNative\(/, "the native camera first, the web camera where there is none");
  assert.match(cam, /cheer\(\)/, "a haptic cue when it's done (the native camera plays the phone's own)");
  assert.match(cam, /GIVE_UP_MS/, "the scan stops at its budget");
  assert.doesNotMatch(cam, /grayOf\(v, 320\)/);
  assert.doesNotMatch(cam, /liveCard\(/, "no whole-card straightening per read");
  const rule = (sel) => (css.match(new RegExp(`${sel.replace(/[.[\]]/g, "\\$&")} \\{([^}]*)\\}`)) || [])[1] || "";
  assert.match(rule(".dc-act"), /min-height: 44px/);
  assert.match(rule(".dc-act"), /min-width: 44px/);
  assert.match(rule(".dc-say"), /min-height: 44px/);
  assert.match(rule(".dc-side"), /min-height: 44px/);
  assert.match(css, /prefers-reduced-motion: reduce\) \{[\s\S]{0,600}\.dc-/, "the camera's motion stops under reduced motion");
  assert.doesNotMatch(css.match(/@keyframes dc-sweep \{[^}]*\}/)[0], /top|left|width|height/, "the sweep moves by transform only (no layout every frame)");
});

test("the build ships the scan worker (clean scan, barcode reads of imported photos), reachable under the app's policy", () => {
  assert.match(src("../build.mjs"), /scanworker: here\("\.\/src\/core\/scanworker\.js"\)/);
  assert.match(noComments(src("core/scanjobs.js")), /__HUMID_WORKER__/, "the worker is started by its hashed build name");
  const conf = JSON.parse(readFileSync(new URL("../apps/mobile/src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.match(conf.app.security.csp, /worker-src 'self'/);
});

test("nothing from a scan is logged or kept: no console output, no storage, no network in the scan files", () => {
  for (const f of ["core/scanworker.js", "core/capture.js", "core/lookstate.js", "core/doctpl.js", "core/doccam.js", "core/webcam.js", "screens/add/camera.jsx"]) {
    const t = noComments(src(f));
    assert.doesNotMatch(t, /console\.|localStorage|sessionStorage|indexedDB|fetch\(|XMLHttpRequest|sendBeacon|WebSocket/, `${f}`);
  }
  assert.doesNotMatch(noComments(src("screens/add/ids.jsx")), /console\./);
});

test("the instructions have plain, short words", () => {
  for (const [id, f] of Object.entries(TIPS)) {
    assert.ok(f.title.length <= 28, `${id} title`);
    if (f.detail) assert.ok(f.detail.length <= 80, `${id} detail`);
  }
});

test("the stylesheets' braces balance (a missing one silently drops every rule after it)", () => {
  for (const f of ["brand/tokens.css", "brand/base.css", "brand/flows.css", "brand/shell.css"]) {
    const css = src(f);
    assert.equal((css.match(/\{/g) || []).length, (css.match(/\}/g) || []).length, f);
  }
});
