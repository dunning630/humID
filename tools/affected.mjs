#!/usr/bin/env node
// What does a change touch? Decides which apps to rebuild and which service
// images to rebuild, so a fix ships as the smallest possible release.
//
//   node tools/affected.mjs [baseRef|none]      (default base: origin/main; "none" = everything)
//
// Prints JSON: { modules, platforms, services, appMatrix, serviceMatrix }.

import { execFileSync } from "node:child_process";

const APPS = ["ios", "android", "macos", "windows", "linux"];
const NODE_SERVICES = ["gateway", "identity", "vault", "ledger", "recovery", "access", "keyshare"];
const SERVICES = [...NODE_SERVICES, "edge"];

// Which shared package feeds which service image. Every package also feeds the
// app, except the server-only ones.
const SERVER_ONLY = new Set(["svc", "attest", "anchor"]);
const PKG_SERVICES = {
  svc: NODE_SERVICES,
  attest: ["identity", "vault", "gateway", "recovery"],
  anchor: ["recovery"],
  htp: NODE_SERVICES,
  crypto: ["vault", "recovery"],
  codec: ["vault", "recovery"],
  audit: ["ledger"],
  recovery: ["recovery"],
  pass: ["access"],
  api: [], gate: [], store: [], io: [], emrtd: [], idscan: [], cards: [], wallet: [],
};

// [pattern, apps, services] — first match wins.
const RULES = [
  [/^plugins\/humid-gate\/src\/desktop\/windows\.rs$/, ["windows"], []],
  [/^plugins\/humid-gate\/src\/desktop\/macos\.rs$/, ["macos"], []],
  [/^plugins\/humid-gate\/src\/desktop\/linux\.rs$/, ["linux"], []],
  [/^plugins\/humid-gate\/src\/desktop\//, ["macos", "windows", "linux"], []],
  [/^plugins\/humid-gate\/src\/mobile\.rs$/, ["ios", "android"], []],
  [/^plugins\/humid-gate\/ios\//, ["ios"], []],
  [/^plugins\/humid-gate\/android\//, ["android"], []],
  [/^plugins\/humid-gate\//, APPS, []],
  [/^plugins\/humid-nfc\/src\/desktop\.rs$/, ["macos", "windows", "linux"], []],
  [/^plugins\/humid-nfc\/src\/mobile\.rs$/, ["ios", "android"], []],
  [/^plugins\/humid-nfc\/ios\//, ["ios"], []],
  [/^plugins\/humid-nfc\/android\//, ["android"], []],
  [/^plugins\/humid-nfc\/examples\//, [], []],
  [/^plugins\/humid-nfc\//, APPS, []],
  [/^apps\/mobile\/src-tauri\/Entitlements\.plist$/, ["macos"], []],
  [/^apps\/mobile\/src-tauri\/Info\.ios\.plist$/, ["ios"], []],
  [/^apps\/mobile\/src-tauri\/Info\.plist$/, ["macos"], []],
  [/^apps\/mobile\/src-tauri\/icons\/android\//, ["android"], []],
  [/^apps\/mobile\/src-tauri\/icons\/ios\//, ["ios"], []],
  [/^apps\/mobile\/src-tauri\//, APPS, []],
  [/^apps\/mobile\//, APPS, ["edge"]], // the web app also ships inside the edge image
  [/^services\/(Dockerfile|build-service\.mjs)$/, [], NODE_SERVICES],
  [/^services\/edge\//, [], ["edge"]],
  [/^services\/([a-z]+)\//, [], (m) => [m[1]]],
  [/^package(-lock)?\.json$/, APPS, SERVICES],
  [/^\.github\/workflows\/|^tools\/ci-cargo\.sh$|^tools\/android-signing\.py$/, APPS, SERVICES],
  [/^deploy\//, [], SERVICES],
  [/^(tests|tools|docs)\/|\.md$|^\.changeset\/|^\.dockerignore$|^\.gitignore$/, [], []],
  [/^\.github\//, [], []],
];

const RUNNERS = { ios: "macos-14", macos: "macos-14", windows: "windows-latest", linux: "ubuntu-22.04", android: "ubuntu-22.04" };

const base = process.argv[2] || "origin/main";
let files = null;
if (base !== "none") {
  try {
    files = execFileSync("git", ["diff", "--name-only", `${base}...HEAD`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean);
  } catch { files = null; } // no usable history: rebuild everything
}

const apps = new Set(files ? [] : APPS);
const services = new Set(files ? [] : SERVICES);
const modules = new Set();
for (const f of files || []) {
  const pkg = f.match(/^packages\/([^/]+)\//);
  if (pkg) {
    modules.add(`@humid/${pkg[1]}`);
    if (!SERVER_ONLY.has(pkg[1])) {
      APPS.forEach((a) => apps.add(a));
      services.add("edge");
    }
    (PKG_SERVICES[pkg[1]] ?? NODE_SERVICES).forEach((s) => services.add(s));
    continue;
  }
  if (f.startsWith("plugins/humid-gate/")) modules.add("tauri-plugin-humid-gate");
  if (f.startsWith("plugins/humid-nfc/")) modules.add("tauri-plugin-humid-nfc");
  if (f.startsWith("apps/mobile/")) modules.add("@humid/mobile");
  const svc = f.match(/^services\/([a-z]+)\//);
  if (svc && SERVICES.includes(svc[1])) modules.add(`@humid/${svc[1]}-service`);
  const rule = RULES.find(([re]) => re.test(f));
  if (!rule) { APPS.forEach((a) => apps.add(a)); SERVICES.forEach((s) => services.add(s)); continue; }
  rule[1].forEach((a) => apps.add(a));
  (typeof rule[2] === "function" ? rule[2](f.match(rule[0])) : rule[2]).filter((s) => SERVICES.includes(s)).forEach((s) => services.add(s));
}

const platforms = APPS.filter((p) => apps.has(p));
const svcList = SERVICES.filter((s) => services.has(s));
console.log(JSON.stringify({
  modules: [...modules].sort(),
  platforms,
  services: svcList,
  appMatrix: { include: platforms.map((platform) => ({ platform, runner: RUNNERS[platform] })) },
  serviceMatrix: { include: svcList.map((service) => ({ service })) },
}));
