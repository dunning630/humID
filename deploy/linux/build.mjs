#!/usr/bin/env node
// Build "HumID Server for Linux":
//   node deploy/linux/build.mjs          -> deploy/linux/out/humid-server/
//   node deploy/linux/build.mjs --tar    -> also deploy/linux/out/HumID-Server-Linux-<version>.tar.gz
//
// The same server as HumID Server for Windows (one Node process: the seven services and a
// local edge), the web app, the self-test, the backup tool, and the `humid` command that
// installs it as a systemd service. The installer fetches the official Node.js 24 (LTS) runtime
// from nodejs.org (checksum verified), so the package stays small and works on x64 and arm64.
// The version is the Windows server's: one server, two packages.
import * as esbuild from "esbuild";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, readdirSync, chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = join(here, "..", "..");
const version = JSON.parse(readFileSync(join(repo, "deploy", "windows", "package.json"), "utf8")).version;
const appVersion = JSON.parse(readFileSync(join(repo, "apps", "mobile", "package.json"), "utf8")).version;
const out = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : join(here, "out");
const pkg = join(out, "humid-server");

rmSync(out, { recursive: true, force: true });
mkdirSync(join(pkg, "bin"), { recursive: true });

// 1. The web app (a release build: no demo mode).
const env = { ...process.env };
delete env.HUMID_ALLOW_DEMO;
execFileSync(process.execPath, [join(repo, "apps", "mobile", "build.mjs")], { stdio: "inherit", env: { ...env, HUMID_PRECOMPRESS: "1" } });
cpSync(join(repo, "apps", "mobile", "dist"), join(pkg, "app"), { recursive: true });

const common = { bundle: true, platform: "node", target: "node24", format: "esm", minify: false, legalComments: "eof", logLevel: "info" };

// 2. The server: the same entry point as on Windows.
await esbuild.build({
  ...common,
  entryPoints: [join(repo, "deploy", "windows", "src", "server.mjs")],
  outfile: join(pkg, "humid-server.mjs"),
  define: { __HUMID_SERVER_VERSION__: JSON.stringify(version), __HUMID_APP_VERSION__: JSON.stringify(appVersion) },
});

// 3. Backups (backup-key, backup, restore): the Windows admin program's backup commands. Its
// console and update jobs are Windows-only and aren't used here.
await esbuild.build({
  ...common,
  entryPoints: [join(repo, "deploy", "windows", "admin", "admin.mjs")],
  outfile: join(pkg, "humid-backup.mjs"),
  define: { __HUMID_SERVER_VERSION__: JSON.stringify(version), __HUMID_ADMIN_PAGE__: JSON.stringify("") },
});

// 4. The self-test (humid selftest).
await esbuild.build({
  ...common,
  entryPoints: [join(repo, "tests", "smoke.mjs")],
  outfile: join(pkg, "humid-selftest.mjs"),
  banner: { js: "// HumID self-test: node humid-selftest.mjs http://127.0.0.1:PORT [ACCESS-CODE]" },
});

// 5. The humid command, the systemd unit and the instructions.
for (const f of readdirSync(join(here, "scripts"))) {
  const text = readFileSync(join(here, "scripts", f), "utf8").replaceAll("__HUMID_SERVER_VERSION__", version);
  const dest = f === "humid" || f === "humid-node" ? join(pkg, "bin", f) : join(pkg, f);
  writeFileSync(dest, text);
  if (dest.includes("/bin/")) chmodSync(dest, 0o755);
}
writeFileSync(join(pkg, "VERSION.txt"), `HumID Server for Linux ${version}\nBuilt ${new Date().toISOString()}\n`);
console.log(`\nBuilt ${pkg}`);

if (process.argv.includes("--tar")) {
  const tar = join(out, `HumID-Server-Linux-${version}.tar.gz`);
  execFileSync("tar", ["--owner=0", "--group=0", "-czf", tar, "humid-server"], { cwd: out, stdio: "inherit" });
  console.log(`Packed ${tar}`);
}
