// @humid/backup (HumID 3.0, provisional): computer backups opened by any two
// of three parts — the HumID vault part, the printed sheet, a contact's part.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { suite } from "@humid/crypto";
import {
  memoryStore, createRepo, describe, unlock, replaceParts, backup, listSnapshots, readSnapshot, restore, unusedChunks,
  newBackupKey, splitBackupKey, combineParts, formatSheet, parseSheet, sealVaultPart, openVaultPart, PART,
  classifier, makePolicy, safePath, DEFAULT_POLICY,
} from "@humid/backup";
import { dirStore, fsSource, fsTarget } from "@humid/backup/fs";

import { randomBytes } from "node:crypto";
const rnd = (n) => new Uint8Array(randomBytes(n));
const te = new TextEncoder();
const td = new TextDecoder();

function identity() {
  const keys = suite().deriveKeys(rnd(64));
  return { keys, vault: { signer: keys, recipient: keys, ctx: { identityCommit: "test", interrupt: { purpose: "backup", assurance: "test" } } } };
}

/** A source made of { path: string | Uint8Array | null (a folder) }. */
function memSource(tree, mtimes = {}) {
  return {
    reads: 0,
    async *entries() {
      for (const [path, v] of Object.entries(tree)) {
        if (v === null) { yield { path, kind: "dir", mode: 0o755 }; continue; }
        const bytes = typeof v === "string" ? te.encode(v) : v;
        yield { path, kind: "file", size: bytes.length, mode: 0o644, mtime: mtimes[path] ?? 1_700_000_000_000 };
      }
    },
    async *read(e, chunkSize) {
      this.reads++;
      const v = tree[e.path];
      const bytes = typeof v === "string" ? te.encode(v) : v;
      for (let i = 0; i < bytes.length; i += chunkSize) yield bytes.subarray(i, i + chunkSize);
    },
  };
}

function memTarget() {
  const files = new Map(), dirs = new Set();
  return {
    files, dirs,
    async mkdir(p) { dirs.add(p); },
    async write(p, chunks) { const parts = []; for await (const c of chunks) parts.push(c); files.set(p, Buffer.concat(parts)); },
  };
}

const TREE = {
  "Documents": null,
  "Documents/taxes-2025.pdf": rnd(200_000),
  "Documents/notes.txt": "the quick brown fox",
  "Pictures/big.raw": rnd(300_000),
  "Pictures/copy.raw": null, // filled below: same bytes as big.raw
  "AppData/Local/Temp/junk.bin": rnd(5000),
  "pagefile.sys": rnd(5000),
  ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----",
  "empty.txt": "",
};
TREE["Pictures/copy.raw"] = TREE["Pictures/big.raw"];

async function newRepo(opts = {}) {
  const store = memoryStore();
  const id = identity();
  const made = await createRepo(store, { vault: id.vault, chunkSize: 64 << 10, label: "Parker's PC", ...opts });
  return { store, id, ...made };
}

test("the backup key splits 2-of-3: any two parts rebuild it, one reveals nothing usable", () => {
  const key = newBackupKey();
  const p = splitBackupKey(key);
  assert.deepEqual([p.vault.x, p.sheet.x, p.contact.x], [PART.vault, PART.sheet, PART.contact]);
  for (const pair of [[p.vault, p.sheet], [p.vault, p.contact], [p.sheet, p.contact]]) assert.deepEqual(combineParts(pair), key);
  assert.throws(() => combineParts([p.sheet]), /two different parts/);
  assert.throws(() => combineParts([p.sheet, p.sheet]), /two different parts/);
  assert.notDeepEqual(p.sheet.y, key);
});

test("backup sheet: prints in groups, forgives case and look-alikes, catches typos and other backups' sheets", () => {
  const p = splitBackupKey(newBackupKey());
  const code = formatSheet(p.sheet, "repo-a");
  assert.match(code, /^HUMIDBK(-[0-9A-HJKMNP-TV-Z]{6}){9}$/);
  assert.deepEqual(parseSheet(code.toLowerCase().replace(/-/g, " "), "repo-a").y, p.sheet.y);
  assert.throws(() => parseSheet(code, "repo-b"), /typo, or it belongs to a different backup/);
  const i = 12, ch = code[i] === "A" ? "B" : "A";
  assert.throws(() => parseSheet(code.slice(0, i) + ch + code.slice(i + 1), "repo-a"), /typo|different backup/);
  assert.throws(() => parseSheet("HUMIDBK-ABC", "repo-a"), /54 characters/);
});

test("vault part opens only with the identity's keys AND the keyshare release", async () => {
  const { keys, vault } = identity();
  const p = splitBackupKey(newBackupKey());
  const { envelope, keyshare } = await sealVaultPart(p.vault, { ...vault, repoId: "r1" });
  assert.deepEqual((await openVaultPart(envelope, keys, keyshare, "r1")).y, p.vault.y);
  await assert.rejects(openVaultPart(envelope, keys, rnd(32), "r1"), /doesn't fit/);
  await assert.rejects(openVaultPart(envelope, identity().keys, keyshare, "r1"), /not sealed to this identity/);
  await assert.rejects(openVaultPart(envelope, keys, keyshare, "r2"), /different backup/);
});

test("a new computer restores with HumID + sheet; without HumID, sheet + contact still work", async () => {
  const { store, id, key, sheet, contactPart, keyshare, repoId } = await newRepo();
  const snap = await backup(store, key, memSource(TREE), { host: "OLD-PC" });
  assert.equal(snap.files, 6);
  assert.equal(snap.excluded, 2); // pagefile.sys and the Temp folder
  assert.equal(snap.sensitive, 1);

  // The repository on its own (what a new PC sees) says nothing secret.
  const info = await describe(store);
  assert.equal(info.repoId, repoId);
  assert.equal(info.label, "Parker's PC");

  for (const parts of [
    { vault: { keys: id.keys, keyshare }, sheet },
    { vault: { keys: id.keys, keyshare }, contact: contactPart },
    { sheet, contact: contactPart },
  ]) {
    const k = await unlock(store, parts);
    assert.deepEqual(k, key);
    const t = memTarget();
    const r = await restore(store, k, snap.id, t);
    assert.deepEqual(t.files.get("Documents/taxes-2025.pdf"), Buffer.from(TREE["Documents/taxes-2025.pdf"]));
    assert.equal(td.decode(t.files.get("Documents/notes.txt")), "the quick brown fox");
    assert.deepEqual(t.files.get("Pictures/copy.raw"), Buffer.from(TREE["Pictures/big.raw"]));
    assert.equal(t.files.get("empty.txt").length, 0);
    assert.equal(t.files.has("pagefile.sys"), false);
    assert.deepEqual(r.held, [".ssh/id_ed25519"]); // sensitive: held back unless asked for
    assert.equal(t.files.has(".ssh/id_ed25519"), false);
  }
  await assert.rejects(unlock(store, { sheet }), /two different parts/);
});

test("sensitive files come back only when asked for, by name or all together", async () => {
  const { store, key } = await newRepo();
  const snap = await backup(store, key, memSource(TREE));
  const t1 = memTarget();
  await restore(store, key, snap.id, t1, { includeSensitive: (p) => p.startsWith(".ssh/") });
  assert.equal(td.decode(t1.files.get(".ssh/id_ed25519")), TREE[".ssh/id_ed25519"]);
  const t2 = memTarget();
  const r = await restore(store, key, snap.id, t2, { includeSensitive: true, only: (p) => p.startsWith(".ssh") });
  assert.equal(r.files, 1);
  assert.deepEqual(r.held, []);
});

test("the store can't read names or test for a known file: chunk ids are keyed per backup", async () => {
  const a = await newRepo(), b = await newRepo();
  await backup(a.store, a.key, memSource(TREE));
  await backup(b.store, b.key, memSource(TREE));
  const idsA = (await a.store.list("chunks/")), idsB = (await b.store.list("chunks/"));
  assert.ok(idsA.length > 0);
  assert.equal(idsA.filter((n) => idsB.includes(n)).length, 0, "same files, different chunk ids");
  for (const [name, blob] of a.store.blobs) {
    if (name === "config.json") continue;
    const text = Buffer.from(blob).toString("latin1");
    for (const word of ["taxes-2025", "notes.txt", "quick brown", "OPENSSH", "Documents"]) assert.equal(text.includes(word), false, `${word} leaked into ${name}`);
  }
});

test("incremental: unchanged files aren't re-read, identical content is stored once", async () => {
  const { store, key } = await newRepo();
  const s1 = await backup(store, key, memSource(TREE));
  assert.ok(s1.reusedChunks >= 5, "copy.raw reuses big.raw's chunks");
  const stored = (await store.list("chunks/")).length;

  const src = memSource(TREE);
  const s2 = await backup(store, key, src, { parent: s1.id });
  assert.equal(src.reads, 0, "nothing re-read when size and mtime match");
  assert.equal(s2.newChunks, 0);
  assert.equal((await store.list("chunks/")).length, stored);

  const changed = { ...TREE, "Documents/notes.txt": "the quick brown fox jumps" };
  const s3 = await backup(store, key, memSource(changed, { "Documents/notes.txt": 1_800_000_000_000 }), { parent: s2.id });
  assert.equal(s3.newChunks, 1);

  const list = await listSnapshots(store, key);
  assert.deepEqual(list.map((s) => s.id), [s3.id, s2.id, s1.id].sort().reverse());
  assert.deepEqual(await unusedChunks(store, key), []);
});

test("tampering is caught: a changed chunk, a swapped snapshot, a wrong key", async () => {
  const { store, key } = await newRepo();
  const snap = await backup(store, key, memSource(TREE));
  const [first] = await store.list("chunks/");
  const blob = await store.get(first);
  blob[20] ^= 1;
  await store.put(first, blob);
  // restore everything: chunk names are keyed, so the first may belong to a sensitive file a default restore leaves alone
  await assert.rejects(restore(store, key, snap.id, memTarget(), { includeSensitive: true }), /damaged or was changed/);

  const other = await newRepo();
  const os = await backup(other.store, other.key, memSource({ "a.txt": "a" }));
  await store.put(`snapshots/${os.id}`, await other.store.get(`snapshots/${os.id}`));
  await assert.rejects(readSnapshot(store, key, os.id), /damaged or was changed/);

  await assert.rejects(backup(store, newBackupKey(), memSource(TREE)), /does not open this backup/);
});

test("replacing the parts (new HumID account, lost sheet): old parts stop opening it, data stays put", async () => {
  const { store, key, sheet, contactPart } = await newRepo();
  const snap = await backup(store, key, memSource({ "a.txt": "kept" }));
  const chunksBefore = await store.list("chunks/");
  const fresh = identity();
  const next = await replaceParts(store, key, fresh.vault);
  assert.deepEqual(await unlock(store, { vault: { keys: fresh.keys, keyshare: next.keyshare }, sheet: next.sheet }), key);
  assert.deepEqual(await unlock(store, { sheet: next.sheet, contact: next.contactPart }), key);
  await assert.rejects(unlock(store, { sheet, contact: contactPart }), /don't open this backup/);
  assert.deepEqual(await store.list("chunks/"), chunksBefore, "no data re-encrypted");
  const t = memTarget();
  await restore(store, key, snap.id, t);
  assert.equal(td.decode(t.files.get("a.txt")), "kept");
});

test("policy: defaults leave out swap, trash and temp; mark keys and browser logins sensitive; paths can't escape", () => {
  const c = classifier(DEFAULT_POLICY);
  assert.equal(c("pagefile.sys"), "exclude");
  assert.equal(c("$Recycle.Bin", true), "exclude");
  assert.equal(c("Users/p/AppData/Local/Temp", true), "exclude");
  assert.equal(c("Users/p/.ssh/id_rsa"), "sensitive");
  assert.equal(c("Users/p/AppData/Local/Google/Chrome/User Data/Default/Login Data"), "sensitive");
  assert.equal(c("Users/p/vault.kdbx"), "sensitive");
  assert.equal(c("Users/p/Documents/report.docx"), "keep");
  const mine = classifier(makePolicy({ exclude: [String.raw`/node_modules/`] }));
  assert.equal(mine("code/app/node_modules", true), "exclude");
  assert.throws(() => makePolicy({ exclude: ["("] }));
  for (const bad of ["../etc/passwd", "/etc/passwd", "C:/Windows", "a//b", "a/./b", "a\u0000b", ""]) assert.throws(() => safePath(bad), /Unsafe path/);
  assert.equal(safePath("a\\b\\c.txt"), "a/b/c.txt");
});

test("restore can scan each file first and quarantine what fails", async () => {
  const { store, key } = await newRepo();
  const snap = await backup(store, key, memSource({ "ok.txt": "fine", "bad.exe": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" }));
  const t = memTarget();
  const r = await restore(store, key, snap.id, t, { scan: async (_e, bytes) => !td.decode(bytes).includes("EICAR") });
  assert.deepEqual(r.quarantined, ["bad.exe"]);
  assert.equal(t.files.has("bad.exe"), false);
  assert.equal(td.decode(t.files.get("ok.txt")), "fine");
});

test("folders on disk: back up a tree to a backup folder and restore it on 'another computer'", async () => {
  const base = await mkdtemp(join(tmpdir(), "humid-backup-"));
  try {
    const src = join(base, "old-pc"), repo = join(base, "usb-drive"), dst = join(base, "new-pc");
    await mkdir(join(src, "Documents", "deep"), { recursive: true });
    await mkdir(join(src, "Temp"), { recursive: true });
    const big = rnd(150_000);
    await writeFile(join(src, "Documents", "deep", "big.bin"), big);
    await writeFile(join(src, "Documents", "a.txt"), "hello");
    await writeFile(join(src, "Temp", "x.tmp"), "junk");
    const when = new Date("2026-01-02T03:04:05Z");
    await utimes(join(src, "Documents", "a.txt"), when, when);

    const id = identity();
    const store = dirStore(repo);
    const made = await createRepo(store, { vault: id.vault, chunkSize: 64 << 10 });
    const snap = await backup(store, made.key, fsSource(src));
    assert.equal(snap.files, 2);
    assert.equal(snap.excluded, 1);

    const key = await unlock(dirStore(repo), { vault: { keys: id.keys, keyshare: made.keyshare }, sheet: made.sheet });
    const r = await restore(dirStore(repo), key, snap.id, fsTarget(dst));
    assert.equal(r.files, 2);
    assert.deepEqual(new Uint8Array(await readFile(join(dst, "Documents", "deep", "big.bin"))), big);
    assert.equal(await readFile(join(dst, "Documents", "a.txt"), "utf8"), "hello");
    await assert.rejects(restore(dirStore(repo), key, snap.id, fsTarget(dst)), /already exists/);
  } finally { await rm(base, { recursive: true, force: true }); }
});
