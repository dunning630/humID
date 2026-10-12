// Build the HumID app into ./dist — used by both the native shells (Tauri:
// iOS, Android, desktop) and the installable web app the edge serves.
//
//   node build.mjs                 production build
//   node build.mjs --watch         rebuild on change
//   HUMID_SERVER_URL=https://vault.humidsecure.ai HUMID_SERVER_KID=<hex> node build.mjs
//     → native apps: which server to talk to, and its pinned key id.
//       Leave HUMID_SERVER_URL empty for the web app (same origin).
import * as esbuild from "esbuild";
import { copyFile, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const out = here("./dist/");
const watch = process.argv.includes("--watch");
const root = here("../../");

// Module versions are stamped into the bundle, and module contracts are checked
// so incompatible module releases can never ship together.
const mods = ["codec", "crypto", "gate", "store", "io", "htp", "audit", "recovery", "api"];
const manifests = [];
const versions = {};
for (const m of mods) {
  const p = JSON.parse(await readFile(`${root}packages/${m}/package.json`, "utf8"));
  versions[p.name] = p.version;
  manifests.push(p);
}
const app = JSON.parse(await readFile(here("./package.json"), "utf8"));
versions[app.name] = app.version;

const provided = { "shell-command": "save_bytes@1", "native-plugin": "humid-gate@1" };
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

const ctx = await esbuild.context({
  entryPoints: { app: here("./src/main.jsx") },
  bundle: true,
  format: "esm",
  target: ["safari16", "chrome110"],
  jsx: "automatic",
  jsxImportSource: "preact",
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  outdir: `${out}assets`,
  loader: { ".woff2": "file" },
  assetNames: "[name]-[hash]",
  define: {
    __HUMID_SERVER__: JSON.stringify(server),
    __HUMID_KID__: JSON.stringify(kid),
    __HUMID_VERSION__: JSON.stringify(app.version),
    __HUMID_MODULES__: JSON.stringify(versions),
  },
  legalComments: "eof",
  logLevel: "info",
});

await copyFile(here("./src/index.html"), `${out}index.html`);
await writeFile(`${out}sw.js`, (await readFile(here("./src/sw.js"), "utf8")).replace("__HUMID_VERSION__", `humid-${app.version}-${Date.now()}`));
await writeFile(`${out}modules.json`, JSON.stringify(versions, null, 2));
await writeFile(`${out}manifest.webmanifest`, JSON.stringify({
  name: "HumID", short_name: "HumID", description: "Your documents, sealed on your phone and opened only by you.",
  start_url: "/", scope: "/", display: "standalone", orientation: "portrait",
  background_color: "#040e0a", theme_color: "#0b1b15",
  icons: [
    { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
    { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
  ],
}, null, 2));
const icons = here("./src-tauri/icons/");
const iconMap = { "icon-192.png": "128x128@2x.png", "icon-512.png": "icon.png", "apple-touch-icon.png": "128x128@2x.png" };
for (const [to, from] of Object.entries(iconMap)) if (existsSync(icons + from)) await copyFile(icons + from, `${out}icons/${to}`);

if (watch) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
