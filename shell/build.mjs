// Bundles @humid/ui and its modules into shell/dist for the native shells.
// Output: index.html, app.js, app.css and the font files. No CDN, no runtime
// network access; the Tauri CSP blocks it anyway.
import * as esbuild from "esbuild";
import { copyFile, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const uiDir = path.dirname(require.resolve("@humid/ui"));
// fileURLToPath, not .pathname: on Windows .pathname yields "/D:/..." which is not a valid path.
const out = fileURLToPath(new URL("./dist/", import.meta.url));
const watch = process.argv.includes("--watch");

// Each module's version is stamped into the bundle so the running app (and a
// bug report) says exactly which module releases it contains.
const versions = {};
const manifests = [];
for (const m of ["codec", "crypto", "gate", "store", "io", "ui"]) {
  const pkg = JSON.parse(await readFile(new URL(`../modules/${m}/package.json`, import.meta.url)));
  versions[pkg.name] = pkg.version;
  manifests.push(pkg);
}

// Contract check: every module's "humid.requires" must be met by another
// module's "humid.provides" (or by the shell / native plugin). This is what
// lets modules release on their own: an incompatible combination fails here,
// at build time, instead of on a user's device.
const SHELL_PROVIDES = { "shell-command": "save_bytes@1", "native-plugin": "humid-gate@1" };
const provided = { ...SHELL_PROVIDES };
for (const p of manifests) Object.assign(provided, p.humid?.provides || {});
const problems = [];
for (const p of manifests) {
  for (const [contract, want] of Object.entries(p.humid?.requires || {})) {
    if (JSON.stringify(provided[contract]) !== JSON.stringify(want)) {
      problems.push(`${p.name} needs ${contract}=${JSON.stringify(want)}, bundle provides ${JSON.stringify(provided[contract])}`);
    }
  }
}
if (problems.length) {
  console.error("Module contract mismatch:\n  " + problems.join("\n  "));
  process.exit(1);
}

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const ctx = await esbuild.context({
  entryPoints: { app: path.join(uiDir, "app.js") },
  bundle: true,
  format: "esm",
  target: ["safari15", "chrome105"],
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  outdir: out,
  loader: { ".woff2": "file" },
  assetNames: "fonts/[name]-[hash]",
  define: { __HUMID_MODULES__: JSON.stringify(versions) },
  legalComments: "eof",
  logLevel: "info",
});

await copyFile(path.join(uiDir, "index.html"), path.join(out, "index.html"));
await writeFile(path.join(out, "modules.json"), JSON.stringify(versions, null, 2));

if (watch) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
