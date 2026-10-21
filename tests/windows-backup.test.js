// HumID Server for Windows backups (docs/ADMIN.md, "Backups"), without Windows: every
// backup is encrypted to a backup key whose private half is kept off the server; keyshare's
// data goes to a separate file; restoring needs the key file, the matching keyshare file,
// and refuses anything damaged, swapped or linked. The local rollback copy an update takes
// restores without the key. CI does the same round trip on a real Windows install.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, symlinkSync, statSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import {
  newBackupKey, readBackupKey, publicKeyOf, writeBackup, restoreBackup, readHeader, allowedPath, backupNames, prune, isInside,
} from "../deploy/windows/admin/backups.mjs";

const tmp = (p = "humid-bak-") => mkdtempSync(join(tmpdir(), p));
const SK_MARK = "HUMID_INTERNAL_SK=do-not-leak-1b7c9e";

/** A data root as the server leaves it: settings, every service's data, the console's mailbox. */
function dataRoot() {
  const root = tmp("humid-root-");
  const put = (rel, data) => { const p = join(root, ...rel.split("/")); mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, data); };
  put("humid.env", `${SK_MARK}\r\nHUMID_PORT=8480\r\n`);
  put("data/vault/vault.db", "vault database");
  put("data/vault/blobs/ab/abcdef", randomBytes(2_500_000)); // more than two chunks
  put("data/vault/blobs/cd/empty", "");
  put("data/ledger/ledger-key.json", '{"sk":"ledger"}');
  put("data/gateway/htp-keys.json", '{"sk":"htp"}');
  put("data/keyshare/share-key.bin", randomBytes(32));
  put("data/keyshare/keyshare.db", "keyshare database");
  put("data/admin/requests/AAAA.json", "{}");
  return root;
}

const tree = (dir, base = "") => {
  const out = {};
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${e.name}` : e.name;
    if (e.isDirectory()) Object.assign(out, tree(join(dir, e.name), rel));
    else out[rel] = readFileSync(join(dir, e.name)).toString("base64");
  }
  return out;
};

async function backupOf(root, key, dir = tmp(), set = "0011223344556677") {
  const data = join(dir, "HumID-backup-x.humidbak"), keyshare = join(dir, "HumID-keyshare-x.humidbak");
  await writeBackup({ root, out: data, kind: "data", publicKey: key.publicKey, set });
  await writeBackup({ root, out: keyshare, kind: "keyshare", publicKey: key.publicKey, set });
  return { data, keyshare, dir };
}

test("backup round trip: encrypted to the backup key, restored exactly with its key file", async () => {
  const root = dataRoot();
  const key = newBackupKey();
  const { data, keyshare, dir } = await backupOf(root, key);
  for (const f of [data, keyshare]) {
    const bytes = readFileSync(f);
    assert.equal(bytes.includes(Buffer.from("do-not-leak")), false, "no settings or keys in the clear");
    assert.equal(bytes.includes(Buffer.from("vault database")), false);
    assert.equal(bytes.includes(Buffer.from("keyshare database")), false);
    assert.equal(bytes.includes(readFileSync(join(root, "data/keyshare/share-key.bin"))), false);
  }
  assert.equal(readHeader(data).key, key.fingerprint, "the header names which key opens it (public)");
  const into = join(dir, "restored");
  const r = await restoreBackup({ file: data, keyshareFile: keyshare, keyText: key.file, into });
  assert.equal(r.kind, "data");
  const want = tree(root);
  delete want["data/admin/requests/AAAA.json"]; // the console's mailbox isn't kept
  assert.deepEqual(tree(into), want);
});

test("keyshare's half is a separate file: the main file holds none of it", async () => {
  const root = dataRoot();
  const key = newBackupKey();
  const { data, dir } = await backupOf(root, key);
  // keyshare's half of the "same" backup, from a different keyshare: what comes back is only that
  const other = dataRoot();
  writeFileSync(join(other, "data/keyshare/share-key.bin"), "another share key");
  const ks2 = join(dir, "other-keyshare.humidbak");
  await writeBackup({ root: other, out: ks2, kind: "keyshare", publicKey: key.publicKey, set: "0011223344556677" });
  const into = join(dir, "r");
  await restoreBackup({ file: data, keyshareFile: ks2, keyText: key.file, into });
  assert.equal(readFileSync(join(into, "data/keyshare/share-key.bin"), "utf8"), "another share key");
  assert.equal(readFileSync(join(into, "data/vault/vault.db"), "utf8"), "vault database");
  assert.equal(allowedPath("data/keyshare/share-key.bin", "data"), false, "a main file can't carry keyshare's data");
  assert.equal(allowedPath("data/vault/vault.db", "keyshare"), false, "and keyshare's file nothing else");
  assert.equal(allowedPath("humid.env", "keyshare"), false);
});

test("restore refuses a wrong or missing key, a missing or mismatched keyshare file, and swapped files", async () => {
  const root = dataRoot();
  const key = newBackupKey(), wrong = newBackupKey();
  const { data, keyshare, dir } = await backupOf(root, key);
  let n = 0;
  const refuse = async (args, re) => {
    const into = join(dir, `x${n++}`);
    await assert.rejects(restoreBackup({ file: data, keyshareFile: keyshare, keyText: key.file, into, ...args }), re);
    assert.equal(existsSync(into), false, `nothing left behind (${re})`);
  };
  await refuse({ keyText: wrong.file }, /doesn't open/);
  await refuse({ keyText: null }, /needs that key file/);
  await refuse({ keyText: "not a key" }, /isn't a HumID backup key file/);
  await refuse({ keyshareFile: null }, /also needs keyshare's half/);
  const other = await backupOf(root, key, tmp(), "8899aabbccddeeff");
  await refuse({ keyshareFile: other.keyshare }, /made by a different backup/);
  await refuse({ file: keyshare, keyshareFile: data }, /keyshare's half of a backup/);
  await refuse({ keyshareFile: data }, /isn't keyshare's half/);
  // the key file says which key it is; the backup says which it needs
  assert.equal(readBackupKey(key.file).fingerprint, key.fingerprint);
  assert.equal(publicKeyOf(key.publicKey).fingerprint, key.fingerprint);
});

test("restore refuses a backup that was changed or cut short, anywhere", async () => {
  const root = dataRoot();
  const key = newBackupKey();
  const { data, keyshare, dir } = await backupOf(root, key);
  const orig = readFileSync(data);
  let n = 0;
  const tryWith = async (bytes, re) => {
    const f = join(dir, `t${n}.humidbak`);
    writeFileSync(f, bytes);
    const into = join(dir, `t${n++}`);
    await assert.rejects(restoreBackup({ file: f, keyshareFile: keyshare, keyText: key.file, into }), re);
    assert.equal(existsSync(into), false);
  };
  const flip = (at) => { const b = Buffer.from(orig); b[at] ^= 1; return b; };
  await tryWith(flip(orig.length - 100), /damaged or was changed/);   // the last piece
  await tryWith(flip(Math.floor(orig.length / 2)), /damaged or was changed/);
  await tryWith(orig.subarray(0, orig.length - 1), /cut short/);
  await tryWith(orig.subarray(0, Math.floor(orig.length / 2)), /cut short/);
  await tryWith(Buffer.concat([orig, Buffer.from("x")]), /more in it than it should/);
  await tryWith(Buffer.from("PK\x03\x04 a zip"), /isn't a HumID Server backup/);
  // the public header is bound to the contents: relabelling it breaks every piece
  const relabelled = Buffer.from(orig.toString("latin1").replace(/"created":"[^"]+"/, '"created":"2020-01-01T00:00:00.000Z"'), "latin1");
  await tryWith(relabelled, /damaged or was changed|doesn't open/);
});

test("the local rollback copy restores without the backup key, keyshare included", async () => {
  const root = dataRoot();
  const dir = tmp();
  const file = join(dir, "pre-update.humidbak");
  await writeBackup({ root, out: file, kind: "local" });
  assert.equal(readHeader(file).key, null);
  const into = join(dir, "r");
  const r = await restoreBackup({ file, into });
  assert.equal(r.kind, "local");
  assert.equal(readFileSync(join(into, "data/keyshare/keyshare.db"), "utf8"), "keyshare database");
  assert.equal(readFileSync(join(into, "humid.env"), "utf8"), readFileSync(join(root, "humid.env"), "utf8"));
});

test("backups refuse without a backup key, and refuse a link anywhere in the data", async () => {
  const root = dataRoot();
  const dir = tmp();
  await assert.rejects(writeBackup({ root, out: join(dir, "a.humidbak"), kind: "data", publicKey: null }), /No backup key is set/);
  const elsewhere = tmp("humid-elsewhere-");
  writeFileSync(join(elsewhere, "secret"), "not HumID's");
  symlinkSync(elsewhere, join(root, "data", "vault", "planted"), "junction");
  const out = join(dir, "b.humidbak");
  await assert.rejects(writeBackup({ root, out, kind: "data", publicKey: newBackupKey().publicKey }), /is a link/);
  assert.deepEqual(readdirSync(dir), [], "no file, not even a partial one");
  await assert.rejects(writeBackup({ root, out: join(dir, "c.humidbak"), kind: "local" }), /is a link/);
});

test("restored paths stay inside the restore folder", () => {
  for (const bad of ["../x", "data/../../x", "/etc/passwd", "data//x", "data/./x", "C:\\x", "data\\vault", "data/admin/requests/A.json", ""]) {
    assert.equal(allowedPath(bad, "local"), false, bad);
  }
  assert.equal(allowedPath("data/vault/blobs/ab/abc", "local"), true);
  assert.equal(allowedPath("humid.env", "data"), true);
});

test("humid backup-key new: the private key never goes inside the data or program folders, and is never overwritten", () => {
  const program = fileURLToPath(new URL("../deploy/windows/admin/admin.mjs", import.meta.url));
  const root = dataRoot();
  const usb = tmp("humid-usb-");
  const run = (...a) => spawnSync(process.execPath, ["--no-warnings", program, ...a, "--root", root], { encoding: "utf8" });
  let r = run("backup-key-new", "--out", join(root, "data", "k.key"));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /inside the server's data folder/);
  r = run("backup-key-new", "--out", join(fileURLToPath(new URL("../deploy/windows/admin/", import.meta.url)), "k.key"));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /inside the program folder/);
  // through a link that resolves into the data folder: still refused
  symlinkSync(join(root, "data"), join(usb, "sneaky"), "junction");
  r = run("backup-key-new", "--out", join(usb, "sneaky", "k.key"));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /inside the server's data folder/);
  writeFileSync(join(usb, "taken.key"), "something else");
  r = run("backup-key-new", "--out", join(usb, "taken.key"));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /already exists/);
  assert.equal(readFileSync(join(usb, "taken.key"), "utf8"), "something else");
  r = run("backup-key-new", "--out", join(usb, "humid-backup.key"));
  assert.equal(r.status, 0, r.stdout);
  const fp = /Backup key ([0-9A-F-]{19}) is set/.exec(r.stdout)[1];
  assert.match(readFileSync(join(root, "admin", "admin.env"), "utf8"), /^HUMID_BACKUP_KEY=[A-Za-z0-9_-]{2000,}\r$/m, "only the public half is kept on the server");
  assert.equal(readBackupKey(readFileSync(join(usb, "humid-backup.key"), "utf8")).fingerprint, fp);
  if (process.platform !== "win32") assert.equal(statSync(join(usb, "humid-backup.key")).mode & 0o777, 0o600);
  r = run("backup-key-new", "--out", join(usb, "second.key"));
  assert.equal(r.status, 1, "replacing a key needs --replace");
  assert.match(r.stdout, /already set/);
  assert.equal(isInside(join(usb, "sneaky", "x"), root), true);

  // and the console's backups use it, keyshare's half in its own folder
  r = run("backup", "--console");
  assert.equal(r.status, 0, r.stdout);
  const made = JSON.parse(r.stdout.trim().split("\n").at(-1));
  assert.equal(made.key, fp);
  assert.ok(existsSync(join(root, "backups", made.file)));
  assert.match(made.keyshare, /backups[\\/]keyshare[\\/]HumID-keyshare-/);
  assert.match(r.stdout, /^Warning: keyshare's half .* same disk/m);
  r = run("backup-keyshare-dir", "--dir", join(root, "data", "ks"));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /inside the server's data folder/);
});

test("console backups: named by date, the newest 10 of each kind kept", () => {
  const n = backupNames(new Date(2026, 9, 21, 9, 5, 7));
  assert.equal(n.data, "HumID-backup-20261021-090507.humidbak");
  assert.equal(n.keyshare, "HumID-keyshare-20261021-090507.humidbak");
  const dir = tmp();
  for (let i = 0; i < 13; i++) {
    const f = join(dir, `HumID-backup-${i}.humidbak`);
    writeFileSync(f, "x");
    utimesSync(f, new Date(2026, 0, 1 + i), new Date(2026, 0, 1 + i));
  }
  writeFileSync(join(dir, "HumID-backup-old.zip"), "legacy");
  prune(dir, "HumID-backup-", 10);
  const left = readdirSync(dir).sort();
  assert.equal(left.length, 11);
  assert.ok(left.includes("HumID-backup-old.zip"), "old plain zips are left for the administrator to delete");
  assert.ok(!left.includes("HumID-backup-0.humidbak") && left.includes("HumID-backup-12.humidbak"));
  rmSync(dir, { recursive: true, force: true });
});
