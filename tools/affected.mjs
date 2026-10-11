#!/usr/bin/env node
// Which modules and which platform apps does a change touch?
//
//   node tools/affected.mjs [baseRef]        (default base: origin/main)
//
// Prints JSON: { modules: [...], platforms: [...], matrix: {include: [...]} }.
// CI feeds `matrix` to the build job, so a fix in the Windows gate rebuilds
// and ships only the Windows app, and a docs change ships nothing.

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";

const ALL = ["ios", "android", "macos", "windows", "linux"];

// Most specific rule wins; first match in this list.
const RULES = [
  [/^plugins\/humid-gate\/src\/desktop\/windows\.rs$/, ["windows"]],
  [/^plugins\/humid-gate\/src\/desktop\/macos\.rs$/, ["macos"]],
  [/^plugins\/humid-gate\/src\/desktop\/linux\.rs$/, ["linux"]],
  [/^plugins\/humid-gate\/src\/desktop\//, ["macos", "windows", "linux"]],
  [/^plugins\/humid-gate\/src\/mobile\.rs$/, ["ios", "android"]],
  [/^plugins\/humid-gate\/ios\//, ["ios"]],
  [/^plugins\/humid-gate\/android\//, ["android"]],
  [/^plugins\/humid-gate\//, ALL],
  [/^shell\/src-tauri\/Entitlements\.plist$/, ["macos"]],
  [/^shell\/src-tauri\/Info\.ios\.plist$/, ["ios"]],
  [/^shell\/src-tauri\/icons\/android\//, ["android"]],
  [/^shell\/src-tauri\/icons\/ios\//, ["ios"]],
  [/^shell\//, ALL],
  [/^modules\//, ALL], // the web layer is bundled into every app
  [/^package(-lock)?\.json$/, ALL],
  // Changing how apps are built must rebuild them all.
  [/^\.github\/workflows\/|^tools\/ci-cargo\.sh$|^tools\/android-signing\.py$/, ALL],
  [/^(tests|tools|docs)\/|\.md$|^\.changeset\//, []],
  [/^\.github\//, []],
];

const RUNNERS = {
  ios: "macos-14", macos: "macos-14", windows: "windows-latest", linux: "ubuntu-22.04", android: "ubuntu-22.04",
};

const base = process.argv[2] || "origin/main";
let files;
try {
  files = execFileSync("git", ["diff", "--name-only", `${base}...HEAD`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean);
} catch {
  files = null; // no git history (first commit, shallow clone): build everything
}

const platforms = new Set(files ? [] : ALL);
const modules = new Set();
for (const f of files || []) {
  const m = f.match(/^modules\/([^/]+)\//);
  if (m) modules.add(`@humid/${m[1]}`);
  if (f.startsWith("plugins/humid-gate/")) modules.add("tauri-plugin-humid-gate");
  if (f.startsWith("shell/")) modules.add("@humid/shell");
  const rule = RULES.find(([re]) => re.test(f));
  for (const p of rule ? rule[1] : ALL) platforms.add(p);
}

// A module change also affects every module that depends on it.
const pkgs = Object.fromEntries(
  readdirSync("modules").map((d) => {
    const p = JSON.parse(readFileSync(`modules/${d}/package.json`, "utf8"));
    return [p.name, Object.keys(p.dependencies || {})];
  }),
);
let grew = true;
while (grew) {
  grew = false;
  for (const [name, deps] of Object.entries(pkgs)) {
    if (!modules.has(name) && deps.some((d) => modules.has(d))) { modules.add(name); grew = true; }
  }
}

const list = ALL.filter((p) => platforms.has(p));
console.log(JSON.stringify({
  modules: [...modules].sort(),
  platforms: list,
  matrix: { include: list.map((platform) => ({ platform, runner: RUNNERS[platform] })) },
}));
