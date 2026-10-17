// A chip photo (DG2, JPEG 2000) is decoded on the phone. Its header decides the
// canvas size, so a hostile chip or file could declare a huge image and have the
// app allocate hundreds of megabytes: the size is checked before anything is allocated.
import { test } from "node:test";
import assert from "node:assert/strict";
import { portraitTooBig, MAX_PORTRAIT_PIXELS, MAX_PORTRAIT_BYTES, jp2ToJpeg, portraitImage } from "../apps/mobile/src/core/scan.js";

test("a declared size over the cap is refused; an ID portrait's isn't", () => {
  assert.equal(MAX_PORTRAIT_PIXELS, 4_000_000);
  assert.equal(portraitTooBig({ width: 480, height: 640 }), false);
  assert.equal(portraitTooBig({ width: 2000, height: 2000 }), false);
  assert.equal(portraitTooBig({ width: 2001, height: 2000 }), true);
  assert.equal(portraitTooBig({ width: 65535, height: 65535 }), true);
  assert.equal(portraitTooBig({ width: 0, height: 100 }), true);
  assert.equal(portraitTooBig({ width: -1, height: 100 }), true);
  assert.equal(portraitTooBig({}), true);
});

test("photo bytes over the cap are refused before the decoder loads", async () => {
  const big = new Uint8Array(MAX_PORTRAIT_BYTES + 1);
  await assert.rejects(jp2ToJpeg(big), /too large/);
  await assert.rejects(portraitImage({ type: "image/jp2", bytes: big }), /too large/);
  await assert.rejects(portraitImage({ type: "image/jpeg", bytes: big }), /too large/);
  await assert.rejects(jp2ToJpeg(null));
});
