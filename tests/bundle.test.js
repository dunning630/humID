// A release build of the app (apps/mobile/build.mjs with no HUMID_ALLOW_DEMO and no
// HUMID_SIMULATE) contains none of the development or simulation code: no demo gate,
// no simulated vault server, no /dev endpoints. Builds into a temporary directory and
// reads every script that came out.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const app = fileURLToPath(new URL("../apps/mobile/", import.meta.url));

function scripts(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) scripts(p, out);
    else if (/\.js$/.test(name)) out.push(p);
  }
  return out;
}

function build(env) {
  const out = mkdtempSync(join(tmpdir(), "humid-bundle-"));
  const clean = { ...process.env, HUMID_OUT_DIR: out };
  delete clean.HUMID_ALLOW_DEMO; delete clean.HUMID_SIMULATE; delete clean.HUMID_SERVER_URL; delete clean.HUMID_SERVER_KID;
  execFileSync(process.execPath, [join(app, "build.mjs")], { cwd: app, env: { ...clean, ...env }, stdio: "pipe" });
  const files = scripts(join(out, "assets"));
  return { out, files, text: Object.fromEntries(files.map((f) => [f.slice(out.length), readFileSync(f, "utf8")])) };
}

// What a release build must not contain: each is a name or path that only the
// development or simulation code uses.
const FORBIDDEN = ["createSimServer", "/dev/access-code", "/dev/passport", "/dev/chip", "demoAdapter", "../sim/server", "demoAccessCode()"];

test("a release build has no simulated server, demo gate or /dev endpoints", { timeout: 300_000 }, () => {
  const b = build({});
  try {
    assert.ok(b.files.length > 1, "the app and its chunks were built");
    for (const [file, text] of Object.entries(b.text)) {
      for (const word of FORBIDDEN) assert.ok(!text.includes(word), `${word} is in ${file}`);
    }
    assert.ok(!b.files.some((f) => /chunks[\\/]server-/.test(f)), "no sim server chunk was emitted");
    // and the real code is still there
    const all = Object.values(b.text).join("");
    assert.ok(all.includes("HUMID-LOCAL-v1"), "the controller is in the bundle");
  } finally { rmSync(b.out, { recursive: true, force: true }); }
});

test("a simulation build, by contrast, carries the server inside the app", { timeout: 300_000 }, () => {
  const b = build({ HUMID_SIMULATE: "1" });
  try {
    assert.ok(b.files.some((f) => /chunks[\\/]server-/.test(f)), "the sim server chunk exists");
    assert.ok(Object.values(b.text).some((t) => t.includes("createSimServer")));
  } finally { rmSync(b.out, { recursive: true, force: true }); }
});
