// Leaving HumID for another app (apps/mobile/src/core/external.js): only https:,
// tel: and mailto: are ever handed to the system, and the browser path opens
// them with no opener and no referrer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { externalUrl, openExternal } from "../apps/mobile/src/core/external.js";

test("only https, tel and mailto; nothing that could run or read anything", () => {
  assert.equal(externalUrl("https://humidsecure.ai/buy"), "https://humidsecure.ai/buy");
  assert.equal(externalUrl("  https://maps.example/?q=41.9,-88.3 "), "https://maps.example/?q=41.9,-88.3");
  assert.equal(externalUrl("tel:+1 (630) 555-0100"), "tel:+1 (630) 555-0100");
  assert.equal(externalUrl("mailto:help@example.com"), "mailto:help@example.com");
  for (const bad of [
    "http://humidsecure.ai", "javascript:alert(1)", "JAVASCRIPT:alert(1)", "file:///etc/passwd", "intent://x#Intent;end",
    "tauri://localhost/", "ipc://x", "data:text/html,<script>", "ftp://x", "sms:+1", "blob:https://x/y",
    "https://user:pw@example.com/", "https://", "mailto:a@b.com?subject=x", "mailto:a@b", "tel:abc", "tel:+1\n",
    "", null, undefined, 42, "https://x/" + "a".repeat(3000), "https://x/\u0000",
  ]) assert.equal(externalUrl(bad), null, `${String(bad).slice(0, 40)} should be refused`);
});

test("in a browser: a new tab, no opener, no referrer; a refused URL opens nothing", async () => {
  const calls = [];
  globalThis.open = (...a) => { calls.push(a); return {}; };
  try {
    assert.equal(await openExternal("https://example.com/x"), true);
    assert.deepEqual(calls, [["https://example.com/x", "_blank", "noopener,noreferrer"]]);
    assert.equal(await openExternal("javascript:alert(1)"), false);
    assert.equal(calls.length, 1);
  } finally { delete globalThis.open; }
});
