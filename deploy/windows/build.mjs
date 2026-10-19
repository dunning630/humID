#!/usr/bin/env node
// Build "HumID Server for Windows":
//   node deploy/windows/build.mjs          -> deploy/windows/out/HumID-Server/
//   node deploy/windows/build.mjs --zip    -> also deploy/windows/out/HumID-Server-Windows-<version>.zip
//   --as-version X.Y.Z                      label the build with another version (CI uses it to test updates and rollback)
//   --out DIR                               build into DIR instead of deploy/windows/out
//
// The package holds the server as one JavaScript file, the web app, and the
// installer. The installer fetches the official Node.js runtime from
// nodejs.org (checksum verified), so the package stays small.
import * as esbuild from "esbuild";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = join(here, "..", "..");
const asVersion = process.argv.includes("--as-version") ? process.argv[process.argv.indexOf("--as-version") + 1] : null;
if (asVersion && !/^\d+\.\d+\.\d+$/.test(asVersion)) throw new Error("--as-version needs X.Y.Z");
const version = asVersion || JSON.parse(readFileSync(join(here, "package.json"), "utf8")).version;
const appVersion = JSON.parse(readFileSync(join(repo, "apps", "mobile", "package.json"), "utf8")).version;
const out = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : join(here, "out");
const pkg = join(out, "HumID-Server");

rmSync(out, { recursive: true, force: true });
mkdirSync(pkg, { recursive: true });

// 1. The web app (a release build: no demo mode).
const env = { ...process.env };
delete env.HUMID_ALLOW_DEMO;
execFileSync(process.execPath, [join(repo, "apps", "mobile", "build.mjs")], { stdio: "inherit", env: { ...env, HUMID_PRECOMPRESS: "1" } }); // the Windows edge serves the .br/.gz siblings
cpSync(join(repo, "apps", "mobile", "dist"), join(pkg, "app"), { recursive: true });

// 2. The server: the seven services + the local edge, one file.
await esbuild.build({
  entryPoints: [join(here, "src", "server.mjs")],
  outfile: join(pkg, "humid-server.mjs"),
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  minify: false, // readable stack traces in the log
  legalComments: "eof",
  define: { __HUMID_SERVER_VERSION__: JSON.stringify(version), __HUMID_APP_VERSION__: JSON.stringify(appVersion) },
  logLevel: "info",
});

// 2b. The admin console (HumID Admin), one file with its page inside.
await esbuild.build({
  entryPoints: [join(here, "admin", "admin.mjs")],
  outfile: join(pkg, "humid-admin.mjs"),
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  minify: false,
  legalComments: "eof",
  define: { __HUMID_SERVER_VERSION__: JSON.stringify(version), __HUMID_ADMIN_PAGE__: JSON.stringify(readFileSync(join(here, "admin", "page.html"), "utf8")) },
  logLevel: "info",
});

// 3. Installer and docs, with Windows line endings. PowerShell 5.1 reads a
// script without a byte-order mark as ANSI, so .ps1 gets a UTF-8 BOM.
const crlf = (s) => s.replace(/\r?\n/g, "\r\n");
for (const f of readdirSync(join(here, "scripts"))) {
  let text = crlf(readFileSync(join(here, "scripts", f), "utf8").replaceAll("__HUMID_SERVER_VERSION__", version));
  if (f.endsWith(".ps1")) text = "﻿" + text;
  writeFileSync(join(pkg, f), text);
}
writeFileSync(join(pkg, "VERSION.txt"), crlf(`HumID Server for Windows ${version}\nBuilt ${new Date().toISOString()}\n`));
console.log(`\nBuilt ${pkg}`);

// 4. Optional zip.
if (process.argv.includes("--zip")) {
  const zip = join(out, `HumID-Server-Windows-${version}.zip`);
  if (process.platform === "win32") {
    execFileSync("powershell.exe", ["-NoProfile", "-Command", `Compress-Archive -Path '${pkg}' -DestinationPath '${zip}' -Force`], { stdio: "inherit" });
  } else {
    execFileSync("zip", ["-qr", zip, "HumID-Server"], { cwd: out, stdio: "inherit" });
  }
  console.log(`Zipped ${zip}`);
}
