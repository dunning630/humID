// LIVE-07: HumID's "live" is a biometric match, not liveness detection. Every document
// that promises a live human says so in the same words, and none claims more.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

const repo = new URL("../", import.meta.url);
// whitespace and line-comment markers collapsed, so a sentence wrapped across lines still matches
const read = (p) => readFileSync(new URL(p, repo), "utf8").replace(/\n\s*\/\/\s?/g, " ").replace(/\s+/g, " ");
const SENTENCE = "a Class-3 biometric match on attested hardware and relies on the device's own anti-spoofing; it performs no additional liveness detection.";

test("the documents that promise a live human state what 'live' means", () => {
  for (const f of ["docs/SECURITY.md", "docs/MESSAGING.md", "docs/CONTINUITY.md", "packages/msg/src/live.js"]) {
    assert.ok(read(f).includes(SENTENCE), f);
  }
});

test("no document claims liveness or anti-spoof detection of HumID's own", () => {
  const bad = [];
  const claim = /\b(HumID|we|it) (detects?|performs?|runs?|does) (liveness|anti-?spoof|presentation[- ]attack)|proof of life|detects? (fake|spoofed) (fingers?|faces?)/i;
  for (const f of readdirSync(new URL("docs/", repo)).filter((n) => n.endsWith(".md"))) {
    const text = read(`docs/${f}`).replace(/performs no additional liveness detection/g, "");
    if (claim.test(text)) bad.push(`docs/${f}: ${text.match(claim)[0]}`);
  }
  assert.deepEqual(bad, []);
});
