#!/usr/bin/env node
// HumID computer backup — DEVELOPMENT CLI (HumID 3.0, provisional).
//
// Stands in for the app: it uses a local demo identity file in place of a live
// biometric check and keeps the keyshare release in a local file in place of the
// keyshare service. Good for trying the format and demoing a restore; never for
// real data. The real flow runs the vault part through the app's live check.
//
//   node tools/humid-backup.mjs init    <repo-folder> [--label "Parker's PC"]
//   node tools/humid-backup.mjs backup  <repo-folder> <folder-to-back-up> [--parent latest]
//   node tools/humid-backup.mjs list    <repo-folder>
//   node tools/humid-backup.mjs restore <repo-folder> <snapshot|latest> <empty-target-folder>
//                                       [--with humid,sheet|humid,contact|sheet,contact] [--sensitive]
//
// Demo files live next to the repository in <repo-folder>.dev/: the demo identity,
// the keyshare release, the contact part, and the device key. The device key is
// what the app keeps in the computer's secure storage so scheduled backups run
// without anyone present; that computer already holds the files themselves, so
// it gains nothing it didn't have. A NEW computer has no device key and must
// unlock with two parts. The sheet code is printed once at init; restore asks for it.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { hostname } from "node:os";
import { suite } from "@humid/crypto";
import { createRepo, describe, unlock, backup, listSnapshots, restore, wipe } from "@humid/backup";
import { dirStore, fsSource, fsTarget } from "@humid/backup/fs";

const [cmd, repo, ...rest] = process.argv.slice(2);
const flag = (name, dflt = null) => { const i = rest.indexOf(`--${name}`); return i < 0 ? dflt : rest[i + 1] ?? true; };
const has = (name) => rest.includes(`--${name}`);
const VALUED = new Set(["--label", "--parent", "--with"]);
const args = rest.filter((a, i) => !a.startsWith("--") && !(i > 0 && VALUED.has(rest[i - 1])));
const dev = (f) => `${repo}.dev/${f}`;
const mb = (n) => `${(n / 1048576).toFixed(1)} MB`;

async function demoIdentity() {
  let seed;
  if (existsSync(dev("identity.seed"))) seed = new Uint8Array(await readFile(dev("identity.seed")));
  else { seed = crypto.getRandomValues(new Uint8Array(64)); await mkdir(`${repo}.dev`, { recursive: true }); await writeFile(dev("identity.seed"), seed); }
  const keys = suite().deriveKeys(seed);
  wipe(seed);
  return { keys, vault: { signer: keys, recipient: keys, ctx: { identityCommit: "dev", interrupt: { purpose: "backup", assurance: "none", demo: true } } } };
}

async function key(withParts) {
  const want = new Set(String(withParts || "humid,sheet").split(","));
  const parts = {};
  if (want.has("humid")) parts.vault = { keys: (await demoIdentity()).keys, keyshare: new Uint8Array(await readFile(dev("keyshare.bin"))) };
  if (want.has("contact")) parts.contact = new Uint8Array(await readFile(dev("contact-part.json")));
  if (want.has("sheet")) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    parts.sheet = await rl.question("Backup sheet code: ");
    rl.close();
  }
  return unlock(dirStore(repo), parts);
}

const deviceKey = async () => new Uint8Array(await readFile(dev("device-key.bin")));

const usage = () => { console.error("usage: humid-backup.mjs init|backup|list|restore <repo-folder> … (see the top of this file)"); process.exit(2); };
if (!cmd || !repo) usage();
console.error("HumID backup — development CLI: demo identity, no live check. Not for real data.\n");

if (cmd === "init") {
  const { vault } = await demoIdentity();
  const made = await createRepo(dirStore(repo), { vault, label: flag("label", hostname()) });
  await writeFile(dev("keyshare.bin"), made.keyshare);
  await writeFile(dev("contact-part.json"), made.contactPart);
  await writeFile(dev("device-key.bin"), made.key);
  wipe(made.key);
  console.log(`Backup ${made.repoId} created in ${repo}\n\nPrint this backup sheet and keep it offline:\n\n  ${made.sheet}\n`);
  console.log(`Contact part (give to someone you trust): ${dev("contact-part.json")}`);
} else if (cmd === "backup") {
  const [src] = args;
  if (!src) usage();
  const k = await deviceKey();
  let parent = flag("parent");
  if (parent === "latest") parent = (await listSnapshots(dirStore(repo), k))[0]?.id ?? null;
  const s = await backup(dirStore(repo), k, fsSource(src, { onSkip: (p, e) => console.error(`  skipped ${p}: ${e.code || e.message}`) }), { parent, host: hostname() });
  wipe(k);
  console.log(`Snapshot ${s.id}: ${s.files} files, ${mb(s.bytes)}; ${s.sensitive} sensitive, ${s.excluded} left out; stored ${mb(s.storedBytes)} new (${s.reusedChunks} pieces reused).`);
} else if (cmd === "list") {
  const k = await deviceKey();
  const d = await describe(dirStore(repo));
  console.log(`${d.label || d.repoId} (${d.suite})`);
  for (const s of await listSnapshots(dirStore(repo), k)) console.log(`  ${s.id}  ${s.host.padEnd(16)} ${String(s.files).padStart(7)} files  ${mb(s.bytes).padStart(10)}  ${s.sensitive} sensitive`);
  wipe(k);
} else if (cmd === "restore") {
  const [which, dst] = args;
  if (!which || !dst) usage();
  const k = await key(flag("with"));
  const id = which === "latest" ? (await listSnapshots(dirStore(repo), k))[0]?.id : which;
  const r = await restore(dirStore(repo), k, id, fsTarget(dst), { includeSensitive: has("sensitive") });
  wipe(k);
  console.log(`Restored ${r.files} files (${mb(r.bytes)}) to ${dst}.`);
  if (r.held.length) console.log(`${r.held.length} sensitive files held back; restore them with --sensitive.`);
} else usage();
