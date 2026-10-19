// Build the HumID app into ./dist — used by both the native shells (Tauri: iOS, Android)
// and the installable web app the edge serves.
//
//   node build.mjs                 production build
//   node build.mjs --watch         rebuild on change
//   HUMID_SERVER_URL=https://vault.humidsecure.ai HUMID_SERVER_KID=<hex> node build.mjs
//     → native apps: which server to talk to, and its pinned key id.
//       Leave HUMID_SERVER_URL empty for the web app (same origin).
//   HUMID_ALLOW_DEMO=1   development build: demo gate (no sensor), demo passports, /dev endpoints
//   HUMID_SIMULATE=1     simulation build: the vault server runs inside the app (src/sim)
//   HUMID_OUT_DIR=<dir>  build somewhere other than ./dist (tests/bundle.test.js)
//   HUMID_NO_MINIFY=1    don't minify (profiling in the browser shows real function names)
//   HUMID_NO_COMPRESS=1  skip the .br/.gz siblings (faster local builds)
//
// 3.0: every file under assets/ carries a content hash in its name (app-<hash>.js, the
// scan worker, the OCR and barcode engines under ocr-<hash>/ and scan-<hash>/), so the edge
// can serve them immutable for a year and a new release is picked up at once; index.html,
// sw.js and manifest.webmanifest are the only unhashed files and are served no-cache. Each
// text/wasm asset also gets .br and .gz siblings, so the edge serves them precompressed.
//
// A release build (neither flag) contains none of the demo or simulation code: the flags
// are esbuild `define`s, always a literal true/false, and the app tests them inline, so
// esbuild drops those branches at parse time and never emits the sim server chunk.
// tests/bundle.test.js builds a release and checks.
import * as esbuild from "esbuild";
import { copyFile, mkdir, rm, readFile, writeFile, readdir, stat } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { brotliCompressSync, gzipSync, constants as Z } from "node:zlib";
import { fileURLToPath } from "node:url";
import { join, extname, relative } from "node:path";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const out = process.env.HUMID_OUT_DIR ? `${process.env.HUMID_OUT_DIR.replace(/\/$/, "")}/` : here("./dist/");
const watch = process.argv.includes("--watch");
const root = here("../../");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const short = (b) => sha(b).slice(0, 8);

// Module versions are stamped into the bundle, and module contracts are checked
// so incompatible module releases can never ship together.
const mods = ["codec", "crypto", "gate", "store", "io", "htp", "audit", "recovery", "api", "emrtd", "idscan", "pass", "cards", "wallet"];
const manifests = [];
const versions = {};
for (const m of mods) {
  const p = JSON.parse(await readFile(`${root}packages/${m}/package.json`, "utf8"));
  versions[p.name] = p.version;
  manifests.push(p);
}
const app = JSON.parse(await readFile(here("./package.json"), "utf8"));
versions[app.name] = app.version;

// The native plugins' major versions are their contracts (plugins/*/Cargo.toml).
const major = async (name) => /^version\s*=\s*"(\d+)\./m.exec(await readFile(`${root}plugins/${name}/Cargo.toml`, "utf8"))?.[1];
const provided = { "shell-command": "save_bytes@1", "native-plugin": `humid-gate@${await major("humid-gate")}`, "nfc-plugin": `humid-nfc@${await major("humid-nfc")}`, "docscan-plugin": `humid-docscan@${await major("humid-docscan")}` };
for (const p of manifests) Object.assign(provided, p.humid?.provides || {});
const problems = [];
for (const p of manifests) {
  for (const [k, want] of Object.entries(p.humid?.requires || {})) {
    if (JSON.stringify(provided[k]) !== JSON.stringify(want)) problems.push(`${p.name} needs ${k}=${JSON.stringify(want)}, bundle provides ${JSON.stringify(provided[k])}`);
  }
}
if (problems.length) { console.error("Module contract mismatch:\n  " + problems.join("\n  ")); process.exit(1); }

const server = process.env.HUMID_SERVER_URL || "";
const kid = (process.env.HUMID_SERVER_KID || "").toLowerCase();
if (kid && !/^[0-9a-f]{64}$/.test(kid)) { console.error("HUMID_SERVER_KID must be 64 hex characters"); process.exit(1); }

await rm(out, { recursive: true, force: true });
await mkdir(`${out}assets`, { recursive: true });
await mkdir(`${out}icons`, { recursive: true });

const allowDemo = process.env.HUMID_ALLOW_DEMO === "1";
const simulate = process.env.HUMID_SIMULATE === "1";
if (simulate || allowDemo) console.log(`NOT a release build: ${[simulate && "simulation (server inside the app)", allowDemo && "demo mode (no sensor)"].filter(Boolean).join(", ")}`);
// Release builds don't contain the demo gate at all: its module is swapped for an empty stub.
const noDemoGate = {
  name: "no-demo-gate",
  setup(b) {
    if (allowDemo) return;
    b.onResolve({ filter: /adapters\/demo\.js$/ }, () => ({ path: "demo-gate-removed", namespace: "humid-stub" }));
    b.onLoad({ filter: /.*/, namespace: "humid-stub" }, () => ({ contents: "export const demoAdapter = null;", loader: "js" }));
  },
};

/* ---------- the scanning engines, in content-hashed directories ---------- */
// Loaded by the app only when someone scans an ID or a card (src/core/scan.js): Tesseract's
// worker and WebAssembly core (SIMD and plain; the app picks at run time) with the MRZ and
// English models, and zxing-cpp's barcode reader. Copied as files so nothing is fetched at
// run time from anywhere but the app's own origin.
const MRZ_MODEL_SHA256 = "ece2a54f125a73792f9cec74e6f8e62f6e5e00c7f19153ba865af689be5b5f01";
const ENG_MODEL_SHA256 = "5dc5d8d640a212c9d6184921ba103b186f50e0fed9ee716c53e6b312b400d747";
const mod = (p) => [here(`./node_modules/${p}`), `${root}node_modules/${p}`].find((x) => existsSync(x)) || (() => { throw new Error(`missing ${p}: run npm ci`); })();
const model = await readFile(here("./vendor/ocr/mrz.traineddata"));
if (sha(model) !== MRZ_MODEL_SHA256) { console.error("vendor/ocr/mrz.traineddata doesn't match its recorded hash (see vendor/ocr/README.md)"); process.exit(1); }
const eng = await readFile(here("./vendor/ocr/eng.traineddata"));
if (sha(eng) !== ENG_MODEL_SHA256) { console.error("vendor/ocr/eng.traineddata doesn't match its recorded hash (see vendor/ocr/README.md)"); process.exit(1); }
const ocrFiles = {
  "mrz.traineddata": model,
  "eng.traineddata": eng,
  "worker.min.js": await readFile(mod("tesseract.js/dist/worker.min.js")),
  "tesseract-core-lstm.js": await readFile(mod("tesseract.js-core/tesseract-core-lstm.js")),
  "tesseract-core-lstm.wasm": await readFile(mod("tesseract.js-core/tesseract-core-lstm.wasm")),
  "tesseract-core-simd-lstm.js": await readFile(mod("tesseract.js-core/tesseract-core-simd-lstm.js")),
  "tesseract-core-simd-lstm.wasm": await readFile(mod("tesseract.js-core/tesseract-core-simd-lstm.wasm")),
};
const scanFiles = { "zxing_reader.wasm": await readFile(mod("zxing-wasm/dist/reader/zxing_reader.wasm")) };
const dirHash = (files) => short(Object.keys(files).sort().map((k) => `${k}:${sha(files[k])}`).join("\n"));
const OCR_DIR = `ocr-${dirHash(ocrFiles)}`;
const SCAN_DIR = `scan-${dirHash(scanFiles)}`;
for (const [dir, files] of [[OCR_DIR, ocrFiles], [SCAN_DIR, scanFiles]]) {
  await mkdir(`${out}assets/${dir}`, { recursive: true });
  for (const [name, bytes] of Object.entries(files)) await writeFile(`${out}assets/${dir}/${name}`, bytes);
}

/* ---------- the bundles ---------- */
const common = {
  plugins: [noDemoGate],
  bundle: true,
  format: "esm",
  target: ["safari16", "chrome110"],
  jsx: "automatic",
  jsxImportSource: "preact",
  minify: !watch && process.env.HUMID_NO_MINIFY !== "1",
  sourcemap: watch ? "inline" : false,
  outdir: `${out}assets`,
  entryNames: "[name]-[hash]",
  chunkNames: "chunks/[name]-[hash]",
  assetNames: "[name]-[hash]",
  legalComments: "eof",
  logLevel: "info",
  metafile: true,
};
const defines = {
  __HUMID_SERVER__: JSON.stringify(server),
  __HUMID_KID__: JSON.stringify(kid),
  __HUMID_VERSION__: JSON.stringify(app.version),
  __HUMID_MODULES__: JSON.stringify(versions),
  __HUMID_ALLOW_DEMO__: JSON.stringify(allowDemo),
  __HUMID_SIM__: JSON.stringify(simulate),
  __HUMID_OCR_DIR__: JSON.stringify(OCR_DIR),
  __HUMID_SCAN_DIR__: JSON.stringify(SCAN_DIR),
};
const outputsOf = (meta, ext) => Object.keys(meta.outputs).filter((f) => f.endsWith(ext)).map((f) => relative(out, f));

// The scan worker (document and barcode analysis off the main thread) is built first and
// its hashed name handed to the app (src/core/analyzer.js starts it by that name).
const workerBuild = await esbuild.build({ ...common, entryPoints: { scanworker: here("./src/core/scanworker.js") }, define: defines, splitting: false });
const WORKER = outputsOf(workerBuild.metafile, ".js").find((f) => /scanworker-/.test(f));

async function buildApp() {
  const r = await esbuild.build({
    ...common,
    entryPoints: { app: here("./src/main.jsx") },
    splitting: true,
    define: { ...defines, __HUMID_WORKER__: JSON.stringify(`/${WORKER}`) },
  });
  const js = outputsOf(r.metafile, ".js").find((f) => /^assets\/app-/.test(f));
  const css = outputsOf(r.metafile, ".css").find((f) => /^assets\/app-/.test(f));
  await writeFile(`${out}meta.json`, JSON.stringify(r.metafile));
  await stampShell({ js, css });
  await compressAll();
}

/* ---------- the shell: index.html, sw.js, manifest, icons ---------- */
async function stampShell({ js, css }) {
  const html = (await readFile(here("./src/index.html"), "utf8")).replace(/__APP_JS__/g, `/${js}`).replace(/__APP_CSS__/g, `/${css}`);
  await writeFile(`${out}index.html`, html);
  await copyFile(here("./src/boot-guard.js"), `${out}boot-guard.js`);
  // The service worker precaches the shell by its hashed names: a new release is a new list.
  const shell = ["/", `/${js}`, `/${css}`, "/boot-guard.js", "/manifest.webmanifest", "/icons/icon-192.png"];
  const sw = (await readFile(here("./src/sw.js"), "utf8")).replace("__HUMID_VERSION__", `humid-${app.version}-${short(Buffer.from(js + css))}`).replace("__HUMID_SHELL__", JSON.stringify(shell));
  await writeFile(`${out}sw.js`, sw);
  await writeFile(`${out}modules.json`, JSON.stringify(versions, null, 2));
  await writeFile(`${out}manifest.webmanifest`, JSON.stringify({
    name: "HumID", short_name: "HumID", description: "Your documents, sealed on your phone and opened only by you.",
    start_url: "/", scope: "/", display: "standalone", orientation: "portrait",
    background_color: "#0B1410", theme_color: "#0B1410",
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "/icons/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
  }, null, 2));
  const notice = (name, p) => { try { return `== ${name} ==\n\n${readFileSync(mod(p), "utf8")}`; } catch { return `== ${name} ==\n(see the package's license)`; } };
  await writeFile(`${out}THIRD-PARTY-scan.txt`, [
    "Document scanning in HumID uses the following, under their licenses.",
    `== MRZ model: DoubangoTelecom/tesseractMRZ (tessdata_fast/mrz.traineddata) ==\n\n${await readFile(here("./vendor/ocr/LICENSE-tesseractMRZ.txt"), "utf8")}`,
    "== English model: tesseract-ocr/tessdata_best (integer build, via @tesseract.js-data/eng 1.0.0, 4.0.0_best_int) ==\n\nApache License 2.0. Copyright Google and the Tesseract contributors.",
    notice("Tesseract.js (worker)", "tesseract.js/LICENSE.md"),
    notice("Tesseract.js core (Tesseract OCR and Leptonica, compiled to WebAssembly)", "tesseract.js-core/LICENSE"),
    notice("zxing-wasm (zxing-cpp compiled to WebAssembly; zxing-cpp is Apache-2.0)", "zxing-wasm/LICENSE"),
    notice("jpeg2000 (JPEG 2000 decoder from Mozilla PDF.js)", "jpeg2000/LICENCE"),
  ].join("\n\n"));
  // Web icons: the HumID hand (src/favicon/). The native app icons in src-tauri/icons are separate.
  const fav = here("./src/favicon/");
  for (const f of ["favicon.svg", "favicon-32.png", "apple-touch-icon.png", "icon-192.png", "icon-512.png", "icon-maskable-512.png"]) await copyFile(fav + f, `${out}icons/${f}`);
  await copyFile(fav + "favicon.ico", `${out}favicon.ico`);
}

/* ---------- precompressed siblings for the edge (file_server precompressed br gzip) ---------- */
const COMPRESS = new Set([".js", ".css", ".wasm", ".traineddata", ".svg", ".json", ".txt", ".html", ".webmanifest"]);
async function compressAll() {
  if (watch || process.env.HUMID_NO_COMPRESS === "1") return;
  const walk = async (dir) => (await Promise.all((await readdir(dir)).map(async (n) => { const p = join(dir, n); return (await stat(p)).isDirectory() ? walk(p) : [p]; }))).flat();
  for (const f of await walk(out)) {
    if (!COMPRESS.has(extname(f)) || /\.(br|gz)$/.test(f)) continue;
    const b = await readFile(f);
    if (b.length < 1024) continue;
    await writeFile(`${f}.br`, brotliCompressSync(b, { params: { [Z.BROTLI_PARAM_QUALITY]: 11, [Z.BROTLI_PARAM_SIZE_HINT]: b.length } }));
    await writeFile(`${f}.gz`, gzipSync(b, { level: 9 }));
  }
}

if (watch) {
  const ctx = await esbuild.context({ ...common, entryPoints: { app: here("./src/main.jsx") }, splitting: true, define: { ...defines, __HUMID_WORKER__: JSON.stringify(`/${WORKER}`) }, entryNames: "[name]", chunkNames: "chunks/[name]", metafile: false });
  await ctx.rebuild();
  await stampShell({ js: "assets/app.js", css: "assets/app.css" });
  await ctx.watch();
} else {
  await buildApp();
}
