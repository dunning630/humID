// How the Add camera routes a photo (apps/mobile/src/core/addroute.js): by the
// straightened photo's shape, by what the live outline looks like, by a cheap look at
// the foot of a page for an MRZ, and by which read names which ID kind.
import { test } from "node:test";
import assert from "node:assert/strict";
import { shapeOf, liveLabel, mrzBandLikely, idKindFrom } from "../apps/mobile/src/core/addroute.js";

test("shapeOf: ID-1 cards, passport pages, and everything else", () => {
  assert.equal(shapeOf(1586, 1000), "card");
  assert.equal(shapeOf(1000, 1586), "card", "either way round");
  assert.equal(shapeOf(1700, 1000), "card", "a little off is still a card");
  assert.equal(shapeOf(1420, 1000), "page-td3");
  assert.equal(shapeOf(1000, 1414), "page-td3", "A4 has the passport page's proportion: worth a look, nothing more");
  assert.equal(shapeOf(1000, 1294), "page", "a letter page");
  assert.equal(shapeOf(1000, 1000), "page");
  assert.equal(shapeOf(0, 0), "page");
});

test("liveLabel: the outline's shape and a barcode on it decide what the camera says it sees", () => {
  assert.equal(liveLabel(null), null);
  assert.equal(liveLabel({ found: false }), null);
  assert.deepEqual(liveLabel({ found: true, ratio: 1.59 }), { icon: "card", text: "Looks like a card" });
  assert.deepEqual(liveLabel({ found: true, ratio: 1.59 }, { barcode: true }), { icon: "barcode", text: "Looks like a driver's license" });
  assert.deepEqual(liveLabel({ found: true, ratio: 1.3 }), { icon: "file", text: "Document" });
  assert.deepEqual(liveLabel({ found: true, ratio: 1.3 }, { barcode: true }), { icon: "file", text: "Document" }, "a barcode on a page says nothing");
});

/** A grey band w×h: paper everywhere, then dark rows where `lines` says ([y0, y1, density]). */
function band(w, h, lines) {
  const g = new Uint8ClampedArray(w * h).fill(230);
  for (const [y0, y1, density, from = 0, to = 1] of lines) {
    for (let y = y0; y < y1; y++) for (let x = Math.round(w * from); x < w * to; x++) if (((x * 7 + y * 3) % 100) / 100 < density) g[y * w + x] = 20;
  }
  return { w, h, g };
}

test("mrzBandLikely: two or three dense full-width lines pass; a blank foot, a signature or one line don't", () => {
  assert.equal(mrzBandLikely(band(400, 120, [[20, 32, 0.4], [50, 62, 0.4]])), true, "two MRZ-like lines");
  assert.equal(mrzBandLikely(band(400, 120, [[10, 20, 0.4], [30, 40, 0.4], [50, 60, 0.4]])), true, "three lines (an ID card's)");
  assert.equal(mrzBandLikely(band(400, 120, [])), false, "a blank foot");
  assert.equal(mrzBandLikely(band(400, 120, [[20, 32, 0.4]])), false, "one line");
  assert.equal(mrzBandLikely(band(400, 120, [[20, 32, 0.4, 0.1, 0.5], [50, 62, 0.4, 0.1, 0.5]])), false, "lines that don't span the width (a signature, a short footer)");
  assert.equal(mrzBandLikely(band(400, 120, [[20, 32, 0.9], [50, 62, 0.9]])), false, "solid bars, not print");
  assert.equal(mrzBandLikely({ w: 0, h: 0, g: new Uint8ClampedArray(0) }), false);
  assert.equal(mrzBandLikely(band(400, 8, [[1, 3, 0.4], [5, 7, 0.4]])), false, "too small to say");
});

test("idKindFrom: a license barcode, or the MRZ's own document code", () => {
  assert.equal(idKindFrom({ barcode: "@\n\u001eANSI 636035..." }), "driver_license");
  assert.equal(idKindFrom({ mrz: { kind: "passport" } }), "passport");
  assert.equal(idKindFrom({ mrz: { kind: "visa" } }), "passport", "a visa page is handled like a passport page");
  assert.equal(idKindFrom({ mrz: { kind: "id_card" } }), "id_card");
  assert.equal(idKindFrom({ mrz: { kind: "residence_permit" } }), "residence_permit");
  assert.equal(idKindFrom({}), null);
});

import { guideFor, GUIDE, SCAN_MODE, LIGHT_TIP } from "../apps/mobile/src/core/addroute.js";

test("choose first: each kind that opens the camera from Add has its own guidance and scan mode", () => {
  assert.equal(guideFor("card").mode, "card");
  assert.equal(guideFor("card").shape, "id1");
  assert.equal(guideFor("photo").mode, "photo");
  assert.equal(guideFor("photo").shape, "full");
  assert.equal(guideFor("file"), null, "a file has no camera");
  for (const g of Object.values(GUIDE)) assert.ok(g.hold.length > 20 && g.title && g.eyebrow);
  assert.match(LIGHT_TIP, /light/i);
});

test("the scan mode follows the kind picked: license=barcode, passport=MRZ, card=card scan", () => {
  assert.equal(SCAN_MODE.driver_license, "barcode");
  assert.equal(SCAN_MODE.passport, "mrz");
  assert.equal(SCAN_MODE.card, "card");
});
