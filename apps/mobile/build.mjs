// Build the HumID app into ./dist — used by both the native shells (Tauri:
// iOS, Android, desktop) and the installable web app the edge serves.
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
//
// A release build (neither flag) contains none of the demo or simulation code: the
// flags are esbuild `define`s, always a literal true/false, and the app tests them
// inline, so esbuild drops those branches at parse time and never emits the sim
// server chunk. tests/bundle.test.js builds a release and checks.
import * as esbuild from "esbuild";
import { copyFile, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const out = process.env.HUMID_OUT_DIR ? `${process.env.HUMID_OUT_DIR.replace(/\/$/, "")}/` : here("./dist/");
const watch = process.argv.includes("--watch");
const root = here("../../");

// Module versions are stamped into the bundle, and module contracts are checked
// so incompatible module releases can never ship together.
const mods = ["codec", "crypto", "gate", "store", "io", "htp", "audit", "recovery", "api", "emrtd", "idscan", "pass"];
const manifests = [];
const versions = {};
for (const m of mods) {
  const p = JSON.parse(await readFile(`${root}packages/${m}/package.json`, "utf8"));
  versions[p.name] = p.version;
  manifests.push(p);
}
const app = JSON.parse(await readFile(here("./package.json"), "utf8"));
versions[app.name] = app.version;

// The native plugin's major version is its contract (plugins/humid-gate/Cargo.toml).
const pluginToml = await readFile(`${root}plugins/humid-gate/Cargo.toml`, "utf8");
const pluginMajor = /^version\s*=\s*"(\d+)\./m.exec(pluginToml)?.[1];
const nfcToml = await readFile(`${root}plugins/humid-nfc/Cargo.toml`, "utf8");
const nfcMajor = /^version\s*=\s*"(\d+)\./m.exec(nfcToml)?.[1];
const scanToml = await readFile(`${root}plugins/humid-docscan/Cargo.toml`, "utf8");
const scanMajor = /^version\s*=\s*"(\d+)\./m.exec(scanToml)?.[1];
const provided = { "shell-command": "save_bytes@1", "native-plugin": `humid-gate@${pluginMajor}`, "nfc-plugin": `humid-nfc@${nfcMajor}`, "docscan-plugin": `humid-docscan@${scanMajor}` };
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

// Release builds don't contain the demo gate at all: its module is swapped for an empty stub.
const allowDemo = process.env.HUMID_ALLOW_DEMO === "1";
const simulate = process.env.HUMID_SIMULATE === "1";
if (simulate || allowDemo) console.log(`NOT a release build: ${[simulate && "simulation (server inside the app)", allowDemo && "demo mode (no sensor)"].filter(Boolean).join(", ")}`);
const noDemoGate = {
  name: "no-demo-gate",
  setup(b) {
    if (allowDemo) return;
    b.onResolve({ filter: /adapters\/demo\.js$/ }, () => ({ path: "demo-gate-removed", namespace: "humid-stub" }));
    b.onLoad({ filter: /.*/, namespace: "humid-stub" }, () => ({ contents: "export const demoAdapter = null;", loader: "js" }));
  },
};

const ctx = await esbuild.context({
  plugins: [noDemoGate],
  // The scan worker (document and barcode analysis off the main thread) is its own file,
  // next to app.js: src/core/analyzer.js starts it by that name.
  entryPoints: { app: here("./src/main.jsx"), scanworker: here("./src/core/scanworker.js") },
  bundle: true,
  format: "esm",
  target: ["safari16", "chrome110"],
  jsx: "automatic",
  jsxImportSource: "preact",
  minify: !watch && process.env.HUMID_NO_MINIFY !== "1", // HUMID_NO_MINIFY=1: readable function names, for profiling
  sourcemap: watch ? "inline" : false,
  outdir: `${out}assets`,
  // The scanning engines (Tesseract, zxing, JPEG 2000) load only when someone scans
  // an ID, so they're split into chunks the main bundle imports on demand.
  splitting: true,
  chunkNames: "chunks/[name]-[hash]",
  loader: { ".woff2": "file" },
  assetNames: "[name]-[hash]",
  define: {
    __HUMID_SERVER__: JSON.stringify(server),
    __HUMID_KID__: JSON.stringify(kid),
    __HUMID_VERSION__: JSON.stringify(app.version),
    __HUMID_MODULES__: JSON.stringify(versions),
    // Demo mode (no sensor) exists only in local development builds: HUMID_ALLOW_DEMO=1.
    __HUMID_ALLOW_DEMO__: JSON.stringify(allowDemo),
    // Simulation build: the vault server runs inside the app (src/sim). HUMID_SIMULATE=1.
    __HUMID_SIM__: JSON.stringify(simulate),
  },
  legalComments: "eof",
  logLevel: "info",
});

await copyFile(here("./src/index.html"), `${out}index.html`);
await copyFile(here("./src/boot-guard.js"), `${out}assets/boot-guard.js`);
await writeFile(`${out}sw.js`, (await readFile(here("./src/sw.js"), "utf8")).replace("__HUMID_VERSION__", `humid-${app.version}-${Date.now()}`));
await writeFile(`${out}modules.json`, JSON.stringify(versions, null, 2));
await writeFile(`${out}manifest.webmanifest`, JSON.stringify({
  name: "HumID", short_name: "HumID", description: "Your documents, sealed on your phone and opened only by you.",
  start_url: "/", scope: "/", display: "standalone", orientation: "portrait",
  background_color: "#040e0a", theme_color: "#0b1b15",
  icons: [
    { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
    { src: "/icons/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
  ],
}, null, 2));
// Document scanning engines, loaded by the app only when someone scans an ID
// (src/core/scan.js): Tesseract's worker and WebAssembly core with the MRZ model,
// and zxing-cpp's barcode reader. Copied as files so nothing is fetched at run time.
const MRZ_MODEL_SHA256 = "ece2a54f125a73792f9cec74e6f8e62f6e5e00c7f19153ba865af689be5b5f01";
// General printed text, for payment cards (both sides): tessdata_best_int English.
const ENG_MODEL_SHA256 = "5dc5d8d640a212c9d6184921ba103b186f50e0fed9ee716c53e6b312b400d747";
const mod = (p) => [here(`./node_modules/${p}`), `${root}node_modules/${p}`].find((x) => existsSync(x)) || (() => { throw new Error(`missing ${p}: run npm ci`); })();
const model = await readFile(here("./vendor/ocr/mrz.traineddata"));
if (createHash("sha256").update(model).digest("hex") !== MRZ_MODEL_SHA256) { console.error("vendor/ocr/mrz.traineddata doesn't match its recorded hash (see vendor/ocr/README.md)"); process.exit(1); }
await mkdir(`${out}assets/ocr`, { recursive: true });
await mkdir(`${out}assets/scan`, { recursive: true });
await writeFile(`${out}assets/ocr/mrz.traineddata`, model);
const eng = await readFile(here("./vendor/ocr/eng.traineddata"));
if (createHash("sha256").update(eng).digest("hex") !== ENG_MODEL_SHA256) { console.error("vendor/ocr/eng.traineddata doesn't match its recorded hash (see vendor/ocr/README.md)"); process.exit(1); }
await writeFile(`${out}assets/ocr/eng.traineddata`, eng);
await copyFile(mod("tesseract.js/dist/worker.min.js"), `${out}assets/ocr/worker.min.js`);
await copyFile(mod("tesseract.js-core/tesseract-core-lstm.js"), `${out}assets/ocr/tesseract-core-lstm.js`);
await copyFile(mod("tesseract.js-core/tesseract-core-lstm.wasm"), `${out}assets/ocr/tesseract-core-lstm.wasm`);
await copyFile(mod("zxing-wasm/dist/reader/zxing_reader.wasm"), `${out}assets/scan/zxing_reader.wasm`);
const notice = (name, p) => { try { return `== ${name} ==\n\n${readFileSync(mod(p), "utf8")}`; } catch { return `== ${name} ==\n(see the package's license)`; } };
await writeFile(`${out}assets/THIRD-PARTY-scan.txt`, [
  "Document scanning in HumID uses the following, under their licenses.",
  `== MRZ model: DoubangoTelecom/tesseractMRZ (tessdata_fast/mrz.traineddata) ==\n\n${await readFile(here("./vendor/ocr/LICENSE-tesseractMRZ.txt"), "utf8")}`,
  "== English model: tesseract-ocr/tessdata_best (integer build, via @tesseract.js-data/eng 1.0.0, 4.0.0_best_int) ==\n\nApache License 2.0. Copyright Google and the Tesseract contributors.",
  notice("Tesseract.js (worker)", "tesseract.js/LICENSE.md"),
  notice("Tesseract.js core (Tesseract OCR and Leptonica, compiled to WebAssembly)", "tesseract.js-core/LICENSE"),
  notice("zxing-wasm (zxing-cpp compiled to WebAssembly; zxing-cpp is Apache-2.0)", "zxing-wasm/LICENSE"),
  notice("jpeg2000 (JPEG 2000 decoder from Mozilla PDF.js)", "jpeg2000/LICENCE"),
].join("\n\n"));

// Web icons: the peace-sign HumID logo (src/favicon/). favicon.svg and the small
// PNG/ICO sizes are the hand without the wordmark, which turns to mush at tab size;
// 180 px and up use the full logo. The native app icons in src-tauri/icons are separate.
const fav = here("./src/favicon/");
for (const f of ["favicon.svg", "favicon-32.png", "apple-touch-icon.png", "icon-192.png", "icon-512.png", "icon-maskable-512.png"]) await copyFile(fav + f, `${out}icons/${f}`);
await copyFile(fav + "favicon.ico", `${out}favicon.ico`);

if (watch) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
