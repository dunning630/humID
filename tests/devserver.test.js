// PC-25: the dev server (npm run dev) serves the app's dist folder and nothing else,
// on this computer only. Turned from scratchpad/poc/servers/devserver-traversal.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, sep } from "node:path";
import { devFile } from "../tools/devfiles.mjs";

const root = join("/srv", "humid", "apps", "mobile", "dist");
const dist = root + sep; // as tools/dev.mjs passes it, with the trailing separator
const at = (p) => devFile(dist, new URL(p, "http://x").pathname);

test("an encoded ../ can't leave dist", () => {
  for (const p of ["/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/..%5c..%5cetc%5cpasswd", "/assets/..%2f..%2f..%2fsecret", "/%2e%2e"]) {
    const f = at(p);
    assert.ok(f === null || f === root || f.startsWith(dist), `${p} -> ${f}`);
  }
  assert.equal(at("/..%2f..%2fetc%2fpasswd"), null);
  assert.equal(devFile(dist, "/%E0%A4%A"), null, "bad percent-encoding");
  assert.equal(devFile(dist, "/index.html%00.png"), null, "NUL");
});

test("ordinary paths map to files in dist", () => {
  assert.equal(at("/"), root, "dist itself (its index.html is served)");
  assert.equal(at("/index.html"), join(dist, "index.html"));
  assert.equal(at("/assets/app-X.js"), join(dist, "assets", "app-X.js"));
  assert.equal(at("/assets/../sw.js"), join(dist, "sw.js"));
});

test("the dev server uses the contained lookup and listens on 127.0.0.1 unless told otherwise", () => {
  const src = readFileSync(new URL("../tools/dev.mjs", import.meta.url), "utf8");
  assert.match(src, /devFile\(dist, url\.pathname\)/);
  assert.doesNotMatch(src, /join\(dist, decodeURIComponent/);
  assert.match(src, /const HOST = process\.env\.HOST \|\| "127\.0\.0\.1"/);
  assert.match(src, /\.listen\(PORT, HOST,/);
});
