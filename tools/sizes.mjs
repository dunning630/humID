import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { gzipSync, brotliCompressSync, constants } from "node:zlib";

const root = process.argv[2];
const files = [];
(function walk(d) {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    const s = statSync(p);
    if (s.isDirectory()) walk(p); else if (!/\.(br|gz)$/.test(e)) files.push(p);
  }
})(root);

// Sizes of every file in a build, raw / gzip / brotli, by category. Usage:
//   node tools/sizes.mjs apps/mobile/dist
// Precompressed siblings (.br/.gz) the build writes are skipped; the table recompresses
// each file itself so the numbers are comparable between builds.
const cat = (p) => {
  if (/\/ocr(-[0-9a-f]+)?\//.test(p)) return "ocr";
  if (/\/scan(-[0-9a-f]+)?\//.test(p)) return "zxing-wasm";
  if (p.endsWith(".woff2")) return "font";
  if (p.includes("/icons/") || p.endsWith(".ico")) return "icon";
  if (p.includes("/chunks/")) return "chunk";
  if (/\/app(-[A-Z0-9]+)?\.js$/.test(p) || /scanworker(-[A-Z0-9]+)?\.js$/.test(p) || p.endsWith("boot-guard.js") || p.endsWith("sw.js")) return "main-js";
  if (p.endsWith(".css")) return "css";
  return "other";
};
const rows = files.map((p) => {
  const b = readFileSync(p);
  return {
    file: relative(root, p), cat: cat(p), raw: b.length,
    gz: gzipSync(b, { level: 9 }).length,
    br: brotliCompressSync(b, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: b.length } }).length,
  };
}).sort((a, b) => b.raw - a.raw);
const fmt = (n) => (n >= 1024 * 1024 ? (n / 1048576).toFixed(2) + " MB" : (n / 1024).toFixed(1) + " KB");
console.log("| File | Category | Raw | gzip | brotli |");
console.log("|---|---|---:|---:|---:|");
for (const r of rows) console.log(`| ${r.file} | ${r.cat} | ${fmt(r.raw)} | ${fmt(r.gz)} | ${fmt(r.br)} |`);
const tot = {};
for (const r of rows) { const t = (tot[r.cat] ||= { raw: 0, gz: 0, br: 0, n: 0 }); t.raw += r.raw; t.gz += r.gz; t.br += r.br; t.n++; }
console.log("\n| Category | Files | Raw | gzip | brotli |\n|---|---:|---:|---:|---:|");
let all = { raw: 0, gz: 0, br: 0, n: 0 };
for (const [k, t] of Object.entries(tot).sort((a, b) => b[1].raw - a[1].raw)) { console.log(`| ${k} | ${t.n} | ${fmt(t.raw)} | ${fmt(t.gz)} | ${fmt(t.br)} |`); all.raw += t.raw; all.gz += t.gz; all.br += t.br; all.n += t.n; }
console.log(`| **total** | ${all.n} | ${fmt(all.raw)} | ${fmt(all.gz)} | ${fmt(all.br)} |`);
