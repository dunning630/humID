#!/usr/bin/env node
// Writes tests/fixtures/docfind-golden.json: the app's own document detector
// (apps/mobile/src/core/docfind.js findDocument) on small grey copies of the camera fixtures,
// cut round the frame as the Android camera cuts its analysis picture. The Android port
// (plugins/humid-docscan/android/…/DocFind.kt) is tested against it (DocFindTest.kt).
//
//   python3 tests/fixtures/id/make-grey.py OUT_DIR    (first frame of each fixture as PGM; needs Pillow)
//   node tools/docfind-golden.mjs OUT_DIR
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { findDocument, shrink, PAPER } from "../apps/mobile/src/core/docfind.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const dir = process.argv[2];
if (!dir) { console.error("usage: node tools/docfind-golden.mjs DIR_OF_PGM"); process.exit(2); }

function pgm(p) {
  const b = readFileSync(p);
  const m = b.toString("latin1", 0, 40).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  return { w: +m[1], h: +m[2], g: new Uint8ClampedArray(b.subarray(m[0].length)) };
}
/** The frame and a 30% margin round it (tests/fixtures/id/make-guided.py GUIDE_*), as a grey picture. */
function around(im, [gx, gy, gw, gh]) {
  const x0 = Math.max(0, Math.round(gx - gw * 0.3)), y0 = Math.max(0, Math.round(gy - gh * 0.3));
  const x1 = Math.min(im.w, Math.round(gx + gw * 1.3)), y1 = Math.min(im.h, Math.round(gy + gh * 1.3));
  const w = x1 - x0, h = y1 - y0, g = new Uint8ClampedArray(w * h);
  for (let y = 0; y < h; y++) g.set(im.g.subarray((y0 + y) * im.w + x0, (y0 + y) * im.w + x1), y * w);
  return { w, h, g };
}
const ID1 = [141, 709, 797, 503], TD3 = [141, 680, 797, 561], PAGE = [141, 422, 797, 1076];
const CASES = [
  ["lic-back-ok", ID1, PAPER.id1], ["lic-back-small", ID1, PAPER.id1], ["lic-back-big", ID1, PAPER.id1], ["lic-front-ok", ID1, PAPER.id1],
  ["pp-ok", TD3, PAPER.td3], ["pay-front-ok", ID1, PAPER.id1], ["page-letter-ok", PAGE, null], ["camera-empty", ID1, PAPER.id1],
];
const out = [];
for (const [name, frame, ratio] of CASES) {
  const small = shrink(around(pgm(join(dir, `${name}.pgm`)), frame), 256);
  const minArea = 0.1;
  const d = findDocument(small, { minArea, ratio });
  out.push({ name, w: small.w, h: small.h, ratio, minArea, grey: Buffer.from(small.g).toString("base64"), quad: d ? d.quad.map((p) => [+p.x.toFixed(2), +p.y.toFixed(2)]) : null, r: d ? +d.ratio.toFixed(3) : null });
  console.log(name, small.w, small.h, d ? "found" : "none");
}
writeFileSync(join(root, "tests/fixtures/docfind-golden.json"), JSON.stringify({ about: "tools/docfind-golden.mjs: apps/mobile/src/core/docfind.js findDocument on grey copies of tests/fixtures/id/guide (the frame and 30% round it, 256 px). For DocFindTest.kt.", cases: out }) + "\n");
