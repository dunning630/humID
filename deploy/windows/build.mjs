#!/usr/bin/env node
// Build "HumID Server for Windows":
//   node deploy/windows/build.mjs          -> deploy/windows/out/HumID-Server/
//   node deploy/windows/build.mjs --zip    -> also deploy/windows/out/HumID-Server-Windows-<version>.zip
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
const { version } = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
const out = join(here, "out");
const pkg = join(out, "HumID-Server");

rmSync(out, { recursive: true, force: true });
mkdirSync(pkg, { recursive: true });

// 1. The web app (a release build: no demo mode).
const env = { ...process.env };
delete env.HUMID_ALLOW_DEMO;
execFileSync(process.execPath, [join(repo, "apps", "mobile", "build.mjs")], { stdio: "inherit", env });
cpSync(join(repo, "apps", "mobile", "dist"), join(pkg, "app"), { recursive: true });

// 2. The server: five services + the local edge, one file.
await esbuild.build({
  entryPoints: [join(here, "src", "server.mjs")],
  outfile: join(pkg, "humid-server.mjs"),
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  minify: false, // readable stack traces in the log
  legalComments: "eof",
  define: { __HUMID_SERVER_VERSION__: JSON.stringify(version) },
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
