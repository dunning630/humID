#!/usr/bin/env node
// Lay out one release run's builds as one folder per version, one folder per app:
//
//   HumID 1.1.0/
//     README.txt          what's inside, which server the apps are pinned to, how to install
//     SHA256SUMS.txt
//     Android/            HumID-<version>-android.apk (release-signed), .aab
//     iPhone/  Mac/  Windows/  Linux/
//     Windows Server/     HumID-Server-Windows-<server version>.zip
//
//   node tools/bundle-release.mjs <downloaded-artifacts-dir> <out-dir>
// Writes name=<artifact name> to $GITHUB_OUTPUT when it is set.
import { readdirSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, statSync, existsSync, appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const [src, out] = process.argv.slice(2);
if (!src || !out) { console.error("usage: bundle-release.mjs <artifacts-dir> <out-dir>"); process.exit(2); }

const repo = fileURLToPath(new URL("..", import.meta.url));
const json = (p) => JSON.parse(readFileSync(join(repo, p), "utf8"));
const appVersion = json("apps/mobile/package.json").version;
const serverVersion = json("deploy/windows/package.json").version;
const serverUrl = process.env.HUMID_SERVER_URL || "";
const serverKid = process.env.HUMID_SERVER_KID || "";
let commit = process.env.GITHUB_SHA || "";
if (!commit) { try { commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim(); } catch {} }

// artifact name -> folder, and how to name what's in it
const APPS = [
  { artifact: "humid-android", folder: "Android", rename: (f) => /\.apk$/.test(f) ? `HumID-${appVersion}-android.apk` : /\.aab$/.test(f) ? `HumID-${appVersion}-android.aab` : f },
  { artifact: "humid-ios", folder: "iPhone", rename: (f) => /\.ipa$/.test(f) ? `HumID-${appVersion}-iphone.ipa` : f },
  { artifact: "humid-macos", folder: "Mac" },
  { artifact: "humid-windows", folder: "Windows" },
  { artifact: "humid-linux", folder: "Linux" },
  { artifact: "HumID-Server-Windows", folder: "Windows Server" },
];
const HOWTO = {
  "Android": [
    "Android 11 or later, with a fingerprint or face unlock set up.",
    "Copy the .apk to the phone and open it; allow installing from that source when Android asks.",
  ],
  "iPhone": ["Installs through TestFlight / App Store Connect (needs the Apple signing secrets)."],
  "Mac": ["Open the .dmg and drag HumID to Applications."],
  "Windows": ["Run the -setup.exe (or the .msi)."],
  "Linux": [".deb / .rpm for your distribution, or the .AppImage. Needs fprintd for the fingerprint reader."],
  "Windows Server": [
    "The vault server for one Windows PC. Unzip, then double-click \"Install HumID Server.cmd\".",
    "Step-by-step instructions are in README.txt inside the zip.",
  ],
};

const top = `HumID ${appVersion}`;
const root = join(out, top);
mkdirSync(root, { recursive: true });

const files = (dir) => readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? files(p) : [p]; });
const sha256 = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

const placed = [];
for (const app of APPS) {
  const dir = join(src, app.artifact);
  if (!existsSync(dir)) continue;
  const found = files(dir);
  if (!found.length) continue;
  mkdirSync(join(root, app.folder), { recursive: true });
  for (const f of found) {
    const name = (app.rename || ((x) => x))(basename(f));
    copyFileSync(f, join(root, app.folder, name));
    placed.push({ folder: app.folder, name, bytes: statSync(f).size, sha: sha256(f) });
  }
}
if (!placed.length) { console.error(`No app builds found in ${src}`); process.exit(1); }

const mb = (n) => `${(n / 1024 / 1024).toFixed(1)} MB`;
const folders = [...new Set(placed.map((p) => p.folder))];
const modules = readdirSync(join(repo, "packages")).filter((d) => existsSync(join(repo, "packages", d, "package.json")))
  .map((d) => json(`packages/${d}/package.json`)).map((p) => `  ${p.name.padEnd(18)} ${p.version}`);

const lines = [
  `HumID ${appVersion}`,
  "=".repeat(`HumID ${appVersion}`.length),
  "",
  `Built      ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`,
  commit ? `From       commit ${commit.slice(0, 12)} (github.com/dunning630/humID)` : null,
  serverUrl ? `Server     ${serverUrl}` : "Server     (none pinned: the app asks on first use)",
  serverUrl ? `Key id     ${serverKid || "(not pinned: trusted on first use)"}` : null,
  serverUrl ? "           The apps connect to this server only, and only if it presents this key." : null,
  "",
  "In this folder",
  "--------------",
  ...folders.flatMap((f) => [
    `${f}/`,
    ...placed.filter((p) => p.folder === f).map((p) => `    ${p.name}  (${mb(p.bytes)})`),
    ...(HOWTO[f] || []).map((h) => `    - ${h}`),
    "",
  ]),
  folders.includes("Windows Server") ? `Windows Server is version ${serverVersion}; it runs the vault the apps talk to.\n` : null,
  "Every check is a live face or fingerprint: no PIN or password ever unlocks HumID.",
  "Proof of concept: don't store real customer data before the independent security review (docs/SECURITY.md).",
  "",
  "Checksums are in SHA256SUMS.txt. Module versions in this build:",
  ...modules,
  "",
].filter((l) => l !== null);
writeFileSync(join(root, "README.txt"), lines.join("\r\n"));
writeFileSync(join(root, "SHA256SUMS.txt"), placed.map((p) => `${p.sha}  ${p.folder}/${p.name}`).join("\r\n") + "\r\n");

const host = serverUrl ? new URL(serverUrl).hostname.split(".")[0] : "";
const name = `HumID-${appVersion}${host ? `-${host}` : ""}`;
console.log(`${top}/ -> artifact ${name}`);
for (const p of placed) console.log(`  ${p.folder}/${p.name}  ${mb(p.bytes)}`);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `name=${name}\nfolder=${top}\n`);
