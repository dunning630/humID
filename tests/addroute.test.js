// How the Add camera routes a photo (apps/mobile/src/core/addroute.js): by the
// straightened photo's shape, and by which read names which ID kind.
import { test } from "node:test";
import assert from "node:assert/strict";
import { shapeOf, idKindFrom } from "../apps/mobile/src/core/addroute.js";

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
