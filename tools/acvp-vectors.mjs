#!/usr/bin/env node
// Refresh tests/fixtures/acvp/ from NIST's ACVP server vectors: the known-answer tests that
// tests/kat.test.js runs against the ML-KEM-1024, ML-DSA-87 and SLH-DSA-SHA2-256f code HumID
// ships (@noble/post-quantum). Only the parameter sets and interfaces HumID uses are kept,
// and a few cases of each, so the fixtures stay small enough for the repo.
//
//   node tools/acvp-vectors.mjs <dir with ACVP-Server gen-val/json-files> <commit>
//
// The source is https://github.com/usnistgov/ACVP-Server, gen-val/json-files/<name>/
// internalProjection.json (each holds the inputs and the expected results). Pass the commit
// you took them from; it's written into each fixture with the file's SHA-256, so anyone can
// check them against NIST's copy.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const [src, commit] = process.argv.slice(2);
if (!src || !/^[0-9a-f]{40}$/.test(commit || "")) { console.error("usage: acvp-vectors.mjs <json-files dir> <40-hex ACVP-Server commit>"); process.exit(1); }
const out = new URL("../tests/fixtures/acvp/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });

/** One case per distinct `reason` (every kind of valid and broken input), then the first `n`. */
const byReason = (tests, n) => {
  const seen = new Set(), out = [];
  for (const t of tests) if (!seen.has(t.reason)) { seen.add(t.reason); out.push(t); }
  for (const t of tests) if (out.length < n && !out.includes(t)) out.push(t);
  return out;
};

/** name → [group filter, how many cases per group]. */
const PICK = {
  "ML-KEM-keyGen-FIPS203": [(g) => g.parameterSet === "ML-KEM-1024", 10],
  "ML-KEM-encapDecap-FIPS203": [(g) => g.parameterSet === "ML-KEM-1024", 10],
  "ML-DSA-keyGen-FIPS204": [(g) => g.parameterSet === "ML-DSA-87", 10],
  // HumID signs with the pure (non-prehash) external interface, hedged; both kinds are checked
  "ML-DSA-sigGen-FIPS204": [(g) => g.parameterSet === "ML-DSA-87" && g.signatureInterface === "external" && g.preHash === "pure", 5],
  "ML-DSA-sigVer-FIPS204": [(g) => g.parameterSet === "ML-DSA-87" && g.signatureInterface === "external" && g.preHash === "pure", 15],
  "SLH-DSA-keyGen-FIPS205": [(g) => g.parameterSet === "SLH-DSA-SHA2-256f", 10],
  // SLH-DSA signatures are 49 KB each and slow to make: two signing cases, and one verify case
  // for each kind of input (valid, modified message, R, SIGFORS, SIGHT, too large, too small)
  "SLH-DSA-sigGen-FIPS205": [(g) => g.parameterSet === "SLH-DSA-SHA2-256f" && g.signatureInterface === "external" && g.preHash === "pure" && g.deterministic, 2],
  "SLH-DSA-sigVer-FIPS205": [(g) => g.parameterSet === "SLH-DSA-SHA2-256f" && g.signatureInterface === "external" && g.preHash === "pure", 8],
};

for (const [name, [keep, n]] of Object.entries(PICK)) {
  const raw = readFileSync(join(src, name, "internalProjection.json"));
  const j = JSON.parse(raw);
  const testGroups = j.testGroups.filter(keep).map((g) => ({ ...g, tests: g.tests.some((t) => t.reason) ? byReason(g.tests, n) : g.tests.slice(0, n) }));
  if (!testGroups.length) throw new Error(`${name}: nothing matched`);
  const doc = {
    source: `https://github.com/usnistgov/ACVP-Server/blob/${commit}/gen-val/json-files/${name}/internalProjection.json`,
    sourceSha256: createHash("sha256").update(raw).digest("hex"),
    note: "A subset of NIST's ACVP vectors (tools/acvp-vectors.mjs). Every case is unchanged from the source.",
    algorithm: j.algorithm, mode: j.mode, revision: j.revision, vsId: j.vsId, testGroups,
  };
  const file = join(out, `${name}.json.gz`);
  writeFileSync(file, gzipSync(JSON.stringify(doc), { level: 9 }));
  console.log(`${name}: ${testGroups.reduce((a, g) => a + g.tests.length, 0)} cases in ${testGroups.length} groups`);
}
