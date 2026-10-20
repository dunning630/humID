// Encrypted backups of HumID Server (server 3.0): one .humidbak file per part.
//
//   all    everything a restore needs (the console's scheduled and pre-update backups)
//   main   everything but the key-share data          } humid backup writes these two, to be
//   keys   the key-share data only                     } kept in different places
//
// What's inside: humid.env, data\<service>, pki\, csca\, and this server's seal key in raw
// form (so the backup restores on a new machine, which seals it again under its own DPAPI).
// Logs, old backups and the console's records stay out, as before.
//
// Format (all integers big-endian):
//   header   "HUMIDBAK" · version 1 · part ('a' | 'm' | 'k') · key id (8: SHA-256 of the backup key)
//            · nonce base (8) · 6 zero bytes                                              = 32 bytes
//   chunks   u32 length · AES-256-GCM(ciphertext + 16-byte tag), 1 MiB of plaintext each; nonce =
//            nonce base · u32 counter; associated data = the header · 1 if it is the last chunk else 0
//   key      HKDF-SHA256(backup key, salt = nonce base, "HUMID-BACKUP-v1")
// Plaintext: records of u32 length · JSON {"p": path, "n": size} · the file's bytes, then {"end": count}.
// A cut, reordered or altered file fails to open; nothing is written from a backup that doesn't.

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { openSync, readSync, writeSync, closeSync, fsyncSync, readdirSync, statSync, existsSync, mkdirSync, rmSync, renameSync } from "node:fs";
import { join, relative, sep, dirname } from "node:path";

const MAGIC = Buffer.from("HUMIDBAK");
const CHUNK = 1 << 20;
const PARTS = { all: "a", main: "m", keys: "k" };
export const BACKUP_EXT = ".humidbak";

export const keyIdOf = (key) => createHash("sha256").update(key).digest().subarray(0, 8);

/** The files a part holds, relative to root (forward slashes), and their sizes. */
export function filesFor(root, part) {
  if (!PARTS[part]) throw new Error("part must be all, main or keys");
  const out = [];
  const walk = (dir) => {
    if (!existsSync(dir)) return;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && !/\.tmp$/.test(e.name)) out.push(relative(root, full).split(sep).join("/"));
    }
  };
  const keyshare = (p) => p.startsWith("data/keyshare/");
  if (part !== "keys") {
    if (existsSync(join(root, "humid.env"))) out.push("humid.env");
    for (const d of ["data", "pki", "csca"]) walk(join(root, d));
  } else walk(join(root, "data", "keyshare"));
  return out.filter((p) => (part === "main" ? !keyshare(p) : true)).sort();
}

class Writer {
  constructor(fd, key, part) {
    this.fd = fd; this.n = 0; this.buf = [];
    this.size = 0;
    this.nonceBase = randomBytes(8);
    this.header = Buffer.concat([MAGIC, Buffer.from([1, PARTS[part].charCodeAt(0)]), keyIdOf(key), this.nonceBase, Buffer.alloc(6)]);
    this.k = Buffer.from(hkdfSync("sha256", key, this.nonceBase, "HUMID-BACKUP-v1", 32));
    writeSync(fd, this.header);
  }
  push(data) {
    this.buf.push(Buffer.from(data)); this.size += data.length;
    while (this.size >= CHUNK) { const all = Buffer.concat(this.buf); this.emit(all.subarray(0, CHUNK), false); this.buf = [all.subarray(CHUNK)]; this.size = this.buf[0].length; }
  }
  emit(plain, last) {
    const iv = Buffer.concat([this.nonceBase, Buffer.alloc(4)]); iv.writeUInt32BE(this.n++, 8);
    const c = createCipheriv("aes-256-gcm", this.k, iv);
    c.setAAD(Buffer.concat([this.header, Buffer.from([last ? 1 : 0])]));
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    const len = Buffer.alloc(4); len.writeUInt32BE(ct.length);
    writeSync(this.fd, len); writeSync(this.fd, ct);
  }
  end() { this.emit(Buffer.concat(this.buf), true); this.buf = []; }
}

const record = (meta) => { const j = Buffer.from(JSON.stringify(meta)); const l = Buffer.alloc(4); l.writeUInt32BE(j.length); return Buffer.concat([l, j]); };

/**
 * Write one part to `out` (a temporary file, renamed when complete). `sealKey`: the server's raw
 * seal key, kept inside so a restore elsewhere can open the sealed secrets. Returns { file, bytes, files }.
 */
export function writeBackup({ root, out, part = "all", backupKey, sealKey = null }) {
  const files = filesFor(root, part);
  mkdirSync(dirname(out), { recursive: true });
  const tmp = `${out}.partial`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    const w = new Writer(fd, backupKey, part);
    if (sealKey) { w.push(record({ p: "keys/seal.raw", n: 32 })); w.push(Buffer.from(sealKey)); }
    const chunk = Buffer.alloc(CHUNK);
    for (const p of files) {
      const full = join(root, ...p.split("/"));
      const size = statSync(full).size;
      w.push(record({ p, n: size }));
      const f = openSync(full, "r");
      try {
        let left = size;
        while (left > 0) { const got = readSync(f, chunk, 0, Math.min(CHUNK, left), null); if (!got) throw new Error(`${p} changed while it was read: stop the server first`); w.push(chunk.subarray(0, got)); left -= got; }
      } finally { closeSync(f); }
    }
    w.push(record({ end: files.length + (sealKey ? 1 : 0) }));
    w.end();
    fsyncSync(fd);
  } catch (e) { closeSync(fd); rmSync(tmp, { force: true }); throw e; }
  closeSync(fd);
  renameSync(tmp, out);
  return { file: out, bytes: statSync(out).size, files: files.length };
}

/** The header of a backup file: { part, keyId (hex) } — to tell which key it needs before asking for one. */
export function readHeader(file) {
  const fd = openSync(file, "r");
  try {
    const h = Buffer.alloc(32);
    if (readSync(fd, h, 0, 32, 0) !== 32 || !h.subarray(0, 8).equals(MAGIC)) throw new Error(`${file} isn't a HumID backup`);
    if (h[8] !== 1) throw new Error(`${file} is a newer backup format (${h[8]})`);
    const part = Object.keys(PARTS).find((k) => PARTS[k].charCodeAt(0) === h[9]);
    return { part, keyId: h.subarray(10, 18).toString("hex"), header: h };
  } finally { closeSync(fd); }
}

/**
 * Open a backup and hand each file to onFile(path, Buffer) as it is decrypted, and the seal key to
 * onSealKey. Every chunk is authenticated before its bytes are handed on, and a file that ends
 * early (cut) throws. Returns { part, files }.
 */
export function readBackup(file, backupKey, { onFile, onSealKey }) {
  const { part, keyId, header } = readHeader(file);
  if (keyId !== keyIdOf(backupKey).toString("hex")) throw Object.assign(new Error("This backup was made with another backup key"), { code: "wrong_backup_key" });
  const nonceBase = header.subarray(18, 26);
  const k = Buffer.from(hkdfSync("sha256", backupKey, nonceBase, "HUMID-BACKUP-v1", 32));
  const fd = openSync(file, "r");
  let pos = 32, n = 0, done = false, ended = false, count = 0;
  let pending = Buffer.alloc(0);
  let cur = null; // { p, n, parts: [], got }
  const take = (plain) => {
    pending = pending.length ? Buffer.concat([pending, plain]) : plain;
    for (;;) {
      if (cur) {
        const need = cur.n - cur.got;
        const piece = pending.subarray(0, Math.min(need, pending.length));
        cur.parts.push(piece); cur.got += piece.length; pending = pending.subarray(piece.length);
        if (cur.got < cur.n) return;
        const data = Buffer.concat(cur.parts);
        if (cur.p === "keys/seal.raw") onSealKey?.(new Uint8Array(data)); else { onFile(cur.p, data); count++; }
        cur = null;
        continue;
      }
      if (pending.length < 4) return;
      const l = pending.readUInt32BE(0);
      if (pending.length < 4 + l) return;
      const meta = JSON.parse(pending.subarray(4, 4 + l).toString("utf8"));
      pending = pending.subarray(4 + l);
      if (meta.end !== undefined) { ended = true; return; }
      if (typeof meta.p !== "string" || !Number.isSafeInteger(meta.n) || meta.n < 0) throw new Error("A backup record is malformed");
      const safe = meta.p.split("/");
      if (meta.p.startsWith("/") || safe.some((s) => s === ".." || s === "" || /[:\\]/.test(s))) throw new Error(`A backup path is unsafe: ${meta.p}`);
      cur = { p: meta.p, n: meta.n, parts: [], got: 0 };
    }
  };
  try {
    const lenBuf = Buffer.alloc(4);
    while (!done) {
      if (readSync(fd, lenBuf, 0, 4, pos) !== 4) throw new Error("The backup is cut short");
      const l = lenBuf.readUInt32BE(0); pos += 4;
      if (l < 16 || l > CHUNK + 16) throw new Error("The backup is damaged");
      const ct = Buffer.alloc(l);
      if (readSync(fd, ct, 0, l, pos) !== l) throw new Error("The backup is cut short");
      pos += l;
      const iv = Buffer.concat([nonceBase, Buffer.alloc(4)]); iv.writeUInt32BE(n++, 8);
      const tryOpen = (last) => {
        const d = createDecipheriv("aes-256-gcm", k, iv);
        d.setAAD(Buffer.concat([header, Buffer.from([last ? 1 : 0])]));
        d.setAuthTag(ct.subarray(l - 16));
        return Buffer.concat([d.update(ct.subarray(0, l - 16)), d.final()]);
      };
      let plain;
      try { plain = tryOpen(false); } catch { try { plain = tryOpen(true); done = true; } catch { throw new Error("The backup is damaged or was changed"); } }
      take(plain);
    }
    if (!ended || cur) throw new Error("The backup is incomplete");
    const extra = Buffer.alloc(1);
    if (readSync(fd, extra, 0, 1, pos) !== 0) throw new Error("The backup has data after its end");
  } finally { closeSync(fd); }
  return { part, files: count };
}

/** Restore one or more backup files into `to` (a new, empty folder). Returns { files, sealKey, parts }. */
export function restoreInto({ files, to, backupKey }) {
  if (existsSync(to) && readdirSync(to).length) throw new Error(`${to} isn't empty`);
  mkdirSync(to, { recursive: true });
  let sealKey = null, total = 0;
  const parts = [];
  try {
    for (const f of files) {
      const r = readBackup(f, backupKey, {
        onFile: (p, data) => {
          const full = join(to, ...p.split("/"));
          mkdirSync(dirname(full), { recursive: true });
          const fd = openSync(full, "w", 0o600);
          try { writeSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
        },
        onSealKey: (k) => { if (sealKey && !Buffer.from(sealKey).equals(Buffer.from(k))) throw new Error("These backups come from different servers (different seal keys)"); sealKey = k; },
      });
      total += r.files; parts.push(r.part);
    }
  } catch (e) { rmSync(to, { recursive: true, force: true }); throw e; }
  return { files: total, sealKey, parts };
}
