// Links that leave HumID (apps/mobile/src/core/external.js): only https, tel and mailto open; nothing else.
import { test } from "node:test";
import assert from "node:assert/strict";
import { openExternal } from "../apps/mobile/src/core/external.js";

test("openExternal opens https, tel and mailto in a new, isolated window and ignores everything else", () => {
  const opened = [];
  globalThis.window = { open: (...a) => { opened.push(a); return null; } };
  try {
    openExternal("https://example.com/buy");
    openExternal("tel:+18005551212");
    openExternal("mailto:help@example.com");
    for (const bad of ["javascript:alert(1)", "http://example.com", "file:///etc/passwd", "intent://x", "", null, 42, "ftp://x"]) openExternal(bad);
    assert.deepEqual(opened.map((a) => a[0]), ["https://example.com/buy", "tel:+18005551212", "mailto:help@example.com"]);
    for (const a of opened) assert.deepEqual(a.slice(1), ["_blank", "noopener,noreferrer"]);
  } finally { delete globalThis.window; }
});
