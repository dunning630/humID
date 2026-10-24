// The release chain's guard rails (pre-certification findings PC-05, PC-06, PC-11):
// the workflows that build, sign and publish HumID keep these properties.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { parse } from "yaml";
import { REVOKED_ANDROID_CERTS, HUMID_ANDROID_RELEASE_CERT } from "@humid/attest";

const repo = new URL("../", import.meta.url);
const WF = new URL(".github/workflows/", repo);
const files = readdirSync(WF).filter((f) => /\.ya?ml$/.test(f));
const text = (f) => readFileSync(new URL(f, WF), "utf8");
const wf = (f) => parse(text(f));
const steps = (job) => job.steps || [];

test("every external action is pinned to a full commit SHA, with its version in a comment", () => {
  const bad = [];
  for (const f of files) {
    for (const [i, line] of text(f).split(/\r?\n/).entries()) {
      const m = line.match(/^\s*(?:-\s+)?uses:\s*(\S+)(.*)$/);
      if (!m || m[1].startsWith("./")) continue;
      if (!/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(m[1]) || !/^\s+#\s*\S/.test(m[2])) bad.push(`${f}:${i + 1} ${m[1]}`);
    }
  }
  assert.deepEqual(bad, []);
});

test("no secret, input, event field or job output is expanded inside a run: script", () => {
  const bad = [];
  for (const f of files) {
    for (const [name, job] of Object.entries(wf(f).jobs)) {
      for (const s of steps(job)) {
        for (const e of String(s.run || "").match(/\$\{\{[^}]*\}\}/g) || []) {
          if (/\b(secrets|inputs|github\.event|needs\.[\w-]+\.outputs)\b/.test(e)) bad.push(`${f} ${name} "${s.name || s.run.slice(0, 40)}": ${e}`);
        }
      }
    }
  }
  assert.deepEqual(bad, []);
});

test("release.yml: least privilege, the guard, and the release environment", () => {
  const r = wf("release.yml");
  assert.deepEqual(r.permissions, {}, "workflow-level permissions are empty");
  const jobs = r.jobs;
  for (const [name, job] of Object.entries(jobs)) {
    assert.ok(job.permissions !== undefined, `${name} states its permissions`);
    const write = Object.entries(job.permissions || {}).filter(([, v]) => v === "write").map(([k]) => k);
    if (name === "publish" || name === "server-windows" || name === "server-linux") assert.deepEqual(write, ["contents"], `${name} may write contents only`);
    else assert.deepEqual(write, [], `${name} has no write permission`);
    if (name !== "plan" && name !== "guard") assert.ok([].concat(job.needs).includes("guard"), `${name} needs the guard`);
  }
  for (const name of ["build", "publish"]) assert.equal(jobs[name].environment, "release", `${name} runs in the release environment`);
  for (const name of ["bundle", "publish"]) assert.match(jobs[name].if, /needs\.guard\.result == 'success'/, `${name} can't run past a failed guard`);
  const guard = steps(jobs.guard).map((s) => s.run || "").join("\n");
  assert.match(guard, /refs\/heads\/main \| refs\/tags\/app-v\*/);
  assert.match(guard, /git merge-base --is-ancestor "\$SHA" refs\/remotes\/origin\/main/);
  assert.equal(steps(jobs.guard).find((s) => s.uses?.startsWith("actions/checkout@")).with["fetch-depth"], 0);
});

test("release.yml: the signing job uses no caches and cleans up its keys", () => {
  const build = wf("release.yml").jobs.build;
  for (const s of steps(build)) {
    if (s.uses?.startsWith("actions/setup-node@")) assert.equal(s.with?.cache, undefined, "no npm cache");
    assert.ok(!s.uses?.startsWith("Swatinem/rust-cache@"), "no rust-cache");
    if (s.uses?.startsWith("dtolnay/rust-toolchain@")) assert.match(String(s.with?.toolchain), /^1\.\d+\.\d+$/);
  }
  const cleanup = steps(build).filter((s) => /Remove decoded signing keys/.test(s.name || ""));
  assert.ok(cleanup.length >= 1 && cleanup.every((s) => /^always\(\)/.test(s.if)));
  const all = cleanup.map((s) => s.run).join("\n");
  for (const f of ["release.jks", "keystore.properties", "private_keys", "sign.pfx"]) assert.ok(all.includes(f), `removes ${f}`);
  const toml = readFileSync(new URL("rust-toolchain.toml", repo), "utf8");
  const channel = toml.match(/channel\s*=\s*"([^"]+)"/)?.[1];
  for (const s of steps(build).filter((s) => s.uses?.startsWith("dtolnay/rust-toolchain@"))) assert.equal(String(s.with.toolchain), channel, "workflow and rust-toolchain.toml agree");
});

test("release.yml: every published APK and AAB is checked against the release and revoked certificates", () => {
  assert.ok(!REVOKED_ANDROID_CERTS.includes(HUMID_ANDROID_RELEASE_CERT));
  const build = wf("release.yml").jobs.build;
  const verify = steps(build).find((s) => /prove every APK and AAB/.test(s.name || "")).run;
  assert.match(verify, /REVOKED_ANDROID_CERTS/);
  assert.match(verify, /HUMID_ANDROID_RELEASE_CERT/);
  assert.match(verify, /apksigner" verify --print-certs/);
  assert.match(verify, /jarsigner -verify/);
  assert.match(verify, /keytool -printcert -jarfile/);
  assert.match(verify, /while read -r f; do/, "every file, not just the first");
  assert.doesNotMatch(verify, /head -1\)/);
  const collect = steps(build).find((s) => s.name === "Collect artifacts").run;
  assert.doesNotMatch(collect, /-name '\*\.(apk|aab)'/, "Android files come only from the verified list");
  assert.match(collect, /android-release-files\.txt/);
});

test("release.yml: a published build pins its server key from a repository variable only", () => {
  const plan = wf("release.yml").jobs.plan;
  const pin = steps(plan).find((s) => s.id === "pin");
  assert.equal(pin.env.KID_VAR, "${{ vars.HUMID_SERVER_KID }}");
  assert.match(pin.run, /if \[ -n "\$KID_INPUT" \]; then echo "::error::/);
  assert.match(pin.run, /\^\[0-9a-fA-F\]\{64\}\$/);
});

test("CI runs the Rust checks, zizmor and CodeQL, and compiles Kotlin and Swift on PRs (V5 build rules)", () => {
  const ci = wf("ci.yml");
  const run = (job) => steps(ci.jobs[job]).map((s) => s.run || "").join("\n");
  assert.match(run("rust"), /cargo fmt --all --check/);
  assert.match(run("rust"), /clippy --workspace --all-targets.* -- -D warnings/);
  assert.match(run("rust"), /ci-cargo\.sh test --workspace/);
  assert.ok(steps(ci.jobs.rust).some((s) => s.uses?.startsWith("EmbarkStudios/cargo-deny-action@")), "cargo-deny");
  assert.ok(existsSync(new URL("deny.toml", repo)));
  assert.ok(steps(ci.jobs.zizmor).some((s) => s.uses?.startsWith("zizmorcore/zizmor-action@")), "zizmor");
  // Android: the whole Gradle build (the plugins' Kotlin), not just the Rust library
  assert.match(run("app"), /tauri -- android build/);
  assert.match(run("app"), /--target aarch64-apple-ios/);
  const codeql = wf("codeql.yml");
  assert.deepEqual(codeql.permissions, { contents: "read" });
  assert.deepEqual(codeql.jobs.analyze.strategy.matrix.language, ["javascript-typescript", "rust"]);
  assert.ok(codeql.on.pull_request !== undefined && codeql.on.schedule);
});

test("ci.yml and images.yml: read-only tokens; only image publishing may write packages", () => {
  assert.deepEqual(wf("ci.yml").permissions, { contents: "read" });
  const images = wf("images.yml");
  assert.deepEqual(images.permissions, { contents: "read" });
  for (const [name, job] of Object.entries(images.jobs)) {
    const p = job.permissions || {};
    assert.equal(p.packages === "write", name === "publish", `${name}: packages write only on publish`);
  }
});

test("secret material stays out of git and every new commit is scanned", () => {
  const gi = readFileSync(new URL(".gitignore", repo), "utf8").split("\n").map((l) => l.trim());
  for (const p of ["*.keystore", "*.jks", "*.p12", "*.pfx", "*.p8", "keystore.properties", "**/.env"]) assert.ok(gi.includes(p), `.gitignore has ${p}`);
  assert.ok(!existsSync(new URL("tools/android-test.keystore", repo)), "the leaked test keystore is not in the tree");
  const scan = wf("secret-scan.yml");
  assert.ok(scan.on.pull_request !== undefined && scan.on.push !== undefined);
  const run = steps(scan.jobs.gitleaks).map((s) => s.run || "").join("\n");
  assert.match(run, /sha256sum -c/);
  assert.match(run, /gitleaks" git \. --config \.gitleaks\.toml/);
});

for (const file of ["server-windows.yml", "server-linux.yml"]) test(`${file}: install scripts never run next to a token that can write (PC-20 / SRV-35)`, () => {
  const w = wf(file);
  assert.deepEqual(w.permissions, {}, "workflow-level permissions are empty");
  for (const [name, job] of Object.entries(w.jobs)) {
    const write = Object.entries(job.permissions || {}).filter(([, v]) => v === "write").map(([k]) => k);
    const installs = steps(job).some((s) => /\bnpm (ci|install|i)\b/.test(s.run || ""));
    for (const s of steps(job).filter((s) => s.uses?.startsWith("actions/checkout@"))) assert.equal(s.with?.["persist-credentials"], false, `${name}: checkout keeps no credentials`);
    for (const s of steps(job).filter((s) => /\bnpm ci\b/.test(s.run || ""))) assert.match(s.run, /--ignore-scripts/, `${name}: no dependency install scripts`);
    if (installs) assert.deepEqual(write, [], `${name} installs dependencies, so it can't write`);
    if (name === "publish") assert.deepEqual(write, ["contents"], "publish may write contents only");
  }
  assert.equal(w.jobs.publish.needs, "build");
});
