// Backups of HumID Server for Windows (docs/ADMIN.md, "Backups").
//
// A backup used to be one plain zip of humid.env and data\ on the server's own disk: the
// vault, keyshare's share-key.bin and every server key together, which is exactly what
// split keys keep apart. Now:
//
//   - Every backup is encrypted to the BACKUP KEY, a key pair the administrator makes with
//     `humid backup-key new`. Its private half is a file the administrator keeps off this
//     computer (a USB drive); the server keeps only the public half (HUMID_BACKUP_KEY in
//     admin\admin.env). HumID never uses passwords or PINs, so there's no passphrase.
//   - Keyshare's data (data\keyshare: share-key.bin and its database) goes to a SEPARATE
//     file from the vault and everything else, and can go to another disk.
//   - The one copy that isn't encrypted to the backup key is the local rollback copy an
//     update takes (kind "local"): the update job must be able to put it back by itself,
//     without the key that's off the computer. It lives in admin\rollback (SYSTEM and
//     Administrators only) and is deleted once the update has worked.
//   - Server 3.0 seals the server's secrets under a machine-bound seal key (DPAPI,
//     src/keyguard.mjs). An encrypted backup carries that seal key inside its encrypted
//     stream, so a restore on a new computer can open them (it is sealed again under the new
//     machine's DPAPI). The local copy carries only keys\ as it is (a DPAPI blob that opens on
//     this machine alone), never the raw seal key: its file key is in its own header.
//
// File format (.humidbak), all integers big-endian:
//   "HUMID-SERVER-BACKUP-v1\n" | u32 headerLen | header JSON | u32 envLen | envelope | chunks…
//   header    { format, v, kind: data|keyshare|local, set, created, key, chunk } (public; bound below)
//   envelope  the 32-byte file key sealed to the backup key with HUMID-PQ1 (@humid/crypto:
//             ML-KEM-1024 + X25519, HKDF-SHA3-256, AES-256-GCM), the suite every HumID document
//             uses. Its ML-DSA-87 signature is by a one-time key: it shows the envelope is intact,
//             not who made it. A local copy has no envelope; its file key is in the header.
//   chunk     u8 last | u32 len | AES-256-GCM(chunk key, nonce = 0⁴ ‖ u64 index,
//             aad = SHA3-256(everything before the chunks) ‖ u64 index ‖ last)
//             chunk key = HKDF-SHA3-256(file key, salt = that hash, "HUMID-SERVER-BACKUP-v1 chunks")
//             so pieces can't be reordered, dropped, cut short or moved between backups.
// Inside the chunks, a simple archive: per entry u8 type (1 folder, 2 file, 0 end) | u16 len |
// path ("data/vault/vault.db") | for a file u64 size and its bytes; or u8 3 | the 32-byte seal
// key (data and keyshare files only, first if present; header "seal": true).
import { createCipheriv, createDecipheriv } from "node:crypto";
import { openSync, readSync, writeSync, closeSync, fstatSync, lstatSync, readdirSync, mkdirSync, renameSync, rmSync, existsSync, statSync, realpathSync } from "node:fs";
import { join, dirname, resolve, sep, basename } from "node:path";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { suite, random } from "@humid/crypto";
import { b64u, unb64u, toHex } from "@humid/htp";

export const EXT = ".humidbak";
export const KEY_FORMAT = "humid-server-backup-key";
const FORMAT = "humid-server-backup";
const MAGIC = Buffer.from("HUMID-SERVER-BACKUP-v1\n");
const CHUNK = 1 << 20;
const KINDS = ["data", "keyshare", "local"];
const KEM_PK = 1568, X_PK = 32;
const FILE_KEY_TYPE = "application/vnd.humid.server-backup-key+v1";

/** What each kind holds, as paths relative to the data root. */
const CONTENTS = {
  // pki\ (role certificates, their keys sealed) and csca\ (country signing certificates) since 3.0
  data: { top: ["humid.env", "data", "pki", "csca"], skip: ["data/keyshare", "data/admin"] },
  keyshare: { top: ["data/keyshare"], skip: [] },
  // data\admin is the console's mailbox: nothing to keep. keys\ is this machine's DPAPI blob of the seal key.
  local: { top: ["humid.env", "data", "pki", "csca", "keys"], skip: ["data/admin"] },
};
const SEAL_KEY_BYTES = 32;

export class BackupError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const no = (code, msg) => { throw new BackupError(code, msg); };

/* ---------------------------------------------------------------- the backup key */

const fingerprintOf = (kemPk, xPk) => toHex(sha3_256(Buffer.concat([kemPk, xPk]))).slice(0, 16).toUpperCase().match(/.{4}/g).join("-");

/** A new backup key: the private key file's text, and the public half for the settings. */
export function newBackupKey() {
  const seed = random(64);
  const k = suite().deriveKeys(seed);
  const fingerprint = fingerprintOf(k.kemPk, k.xPk);
  const file = JSON.stringify({
    format: KEY_FORMAT, v: 1, suite: "HUMID-PQ1", created: new Date().toISOString(), fingerprint,
    note: "HumID Server backup key. Restoring a backup needs this file. Keep it off the server (a USB drive in a drawer, a second copy somewhere safe); anyone with it and a backup can read the backup.",
    seed: b64u(seed),
  }, null, 1) + "\n";
  const publicKey = b64u(Buffer.concat([k.kemPk, k.xPk]));
  suite().wipeKeys(k);
  seed.fill(0);
  return { file, publicKey, fingerprint };
}

/** The public half as stored in the settings → { kemPk, xPk, fingerprint }. */
export function publicKeyOf(setting) {
  let raw;
  try { raw = unb64u(String(setting || "")); } catch { raw = null; }
  if (!raw || raw.length !== KEM_PK + X_PK) no("bad_key", "HUMID_BACKUP_KEY in admin\\admin.env isn't a HumID backup key. Make a new one: humid backup-key new.");
  const kemPk = raw.subarray(0, KEM_PK), xPk = raw.subarray(KEM_PK);
  return { kemPk, xPk, fingerprint: fingerprintOf(kemPk, xPk) };
}

/** The private key file's text → { keys, fingerprint }. */
export function readBackupKey(text) {
  let o;
  try { o = JSON.parse(String(text)); } catch { o = null; }
  let seed = null;
  try { seed = o?.format === KEY_FORMAT && o.v === 1 ? unb64u(String(o.seed)) : null; } catch {}
  if (!seed || seed.length !== 64) no("bad_key_file", "That isn't a HumID backup key file (the one humid backup-key new wrote).");
  const keys = suite().deriveKeys(seed);
  seed.fill(0);
  return { keys, fingerprint: fingerprintOf(keys.kemPk, keys.xPk) };
}

/* ---------------------------------------------------------------- where a file may go */

/** The real path of `p`: links in the part that exists are resolved. */
function realish(p) {
  let head = resolve(p);
  const tail = [];
  for (;;) {
    try { return join(realpathSync.native(head), ...tail.reverse()); }
    catch { const up = dirname(head); if (up === head) return resolve(p); tail.push(basename(head)); head = up; }
  }
}
const norm = (p) => (process.platform === "win32" ? realish(p).toLowerCase() : realish(p));
/** Is `p` inside (or equal to) `dir`, links resolved? */
export function isInside(p, dir) {
  const a = norm(p), d = norm(dir).replace(/[\\/]+$/, "");
  return a === d || a.startsWith(d + sep);
}

/** The disk a path is on (or would be): the nearest existing folder's device. */
function deviceOf(p) {
  let d = resolve(p);
  for (;;) {
    try { return statSync(d).dev; } catch { const up = dirname(d); if (up === d) return null; d = up; }
  }
}
export const sameDisk = (a, b) => { const x = deviceOf(a), y = deviceOf(b); return x !== null && x === y; };

/* ---------------------------------------------------------------- reading the data root */

/**
 * Every folder and file of one kind, never following a link: a junction or symbolic link
 * anywhere in the data means something planted it (docs/ADMIN.md, "Separate rights").
 */
function* entries(root, kind) {
  const { top, skip } = CONTENTS[kind];
  const skipped = (rel) => skip.some((s) => rel === s || rel.startsWith(`${s}/`));
  const stack = [...top].reverse();
  while (stack.length) {
    const rel = stack.pop();
    if (skipped(rel)) continue;
    const abs = join(root, ...rel.split("/"));
    let st;
    try { st = lstatSync(abs); } catch (e) { if (e.code === "ENOENT") continue; throw e; }
    if (st.isSymbolicLink()) no("link", `${abs} is a link (a junction or symbolic link). HumID never makes one; nothing was backed up. Run humid install again to remove it, and check this computer.`);
    if (st.isDirectory()) {
      yield { type: 1, rel };
      for (const name of readdirSync(abs).sort().reverse()) stack.push(`${rel}/${name}`);
    } else if (st.isFile()) yield { type: 2, rel, abs };
    else no("odd_file", `${abs} isn't a file or a folder; nothing was backed up.`);
  }
}

/* ---------------------------------------------------------------- the encrypted stream */

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const chunkKey = (fileKey, bound) => Buffer.from(hkdf(sha3_256, fileKey, bound, Buffer.from("HUMID-SERVER-BACKUP-v1 chunks"), 32));
const nonceOf = (i) => Buffer.concat([Buffer.alloc(4), u64(i)]);
const aadOf = (bound, i, last) => Buffer.concat([bound, u64(i), Buffer.from([last ? 1 : 0])]);

function chunkWriter(fd, key, bound) {
  const buf = Buffer.alloc(CHUNK);
  let fill = 0, index = 0, bytes = 0;
  const emit = (last) => {
    const c = createCipheriv("aes-256-gcm", key, nonceOf(index));
    c.setAAD(aadOf(bound, index, last));
    const ct = Buffer.concat([c.update(buf.subarray(0, fill)), c.final(), c.getAuthTag()]);
    writeSync(fd, Buffer.concat([Buffer.from([last ? 1 : 0]), u32(ct.length), ct]));
    index++; fill = 0;
  };
  return {
    push(data) {
      bytes += data.length;
      for (let o = 0; o < data.length;) {
        const n = Math.min(CHUNK - fill, data.length - o);
        data.copy(buf, fill, o, o + n);
        fill += n; o += n;
        if (fill === CHUNK) emit(false);
      }
    },
    close() { emit(true); return bytes; },
  };
}

function readExactly(fd, n, what) {
  const b = Buffer.alloc(n);
  let got = 0;
  while (got < n) { const r = readSync(fd, b, got, n - got, null); if (!r) break; got += r; }
  if (got !== n) no("truncated", `${what} is cut short. Nothing was restored.`);
  return b;
}

function chunkReader(fd, key, bound, name) {
  let index = 0, done = false, cur = Buffer.alloc(0), pos = 0;
  const next = () => {
    if (done) no("damaged", `${name} has more in it than it should. Nothing was restored.`);
    const head = readExactly(fd, 5, name);
    const last = head[0] === 1, len = head.readUInt32BE(1);
    if (head[0] > 1 || len < 16 || len > CHUNK + 16) no("damaged", `${name} is damaged or was changed. Nothing was restored.`);
    const ct = readExactly(fd, len, name);
    const d = createDecipheriv("aes-256-gcm", key, nonceOf(index));
    d.setAAD(aadOf(bound, index, last));
    d.setAuthTag(ct.subarray(len - 16));
    try { cur = Buffer.concat([d.update(ct.subarray(0, len - 16)), d.final()]); }
    catch { no("damaged", `${name} is damaged or was changed (piece ${index + 1} doesn't check out). Nothing was restored.`); }
    pos = 0; index++; done = last;
  };
  return {
    /** Exactly n bytes of the archive. */
    take(n) {
      const parts = [];
      while (n > 0) {
        if (pos === cur.length) { if (done) no("truncated", `${name} is cut short. Nothing was restored.`); next(); continue; }
        const k = Math.min(n, cur.length - pos);
        parts.push(cur.subarray(pos, pos + k));
        pos += k; n -= k;
      }
      return parts.length === 1 ? parts[0] : Buffer.concat(parts);
    },
    /** After the end marker: nothing may follow. */
    end() {
      while (!done || pos !== cur.length) {
        if (pos !== cur.length) no("damaged", `${name} has more in it than it should. Nothing was restored.`);
        next();
      }
      if (readSync(fd, Buffer.alloc(1), 0, 1, null)) no("damaged", `${name} has more in it than it should. Nothing was restored.`);
    },
  };
}

/* ---------------------------------------------------------------- writing a backup */

/**
 * Write one backup file.
 *   root       the data root (C:\ProgramData\HumID)
 *   out        the file to write; it must not exist yet
 *   kind       data | keyshare | local
 *   publicKey  HUMID_BACKUP_KEY (not for local)
 *   set        an id shared by the data and keyshare files of one backup
 *   sealKey    this server's raw seal key (src/keyguard.mjs), or null when sealing is off;
 *              kept inside the encrypted stream (never in a local copy)
 * → { file, bytes, kind, set }
 */
export async function writeBackup({ root, out, kind, publicKey, set = toHex(random(8)), created = new Date().toISOString(), sealKey = null }) {
  if (!KINDS.includes(kind)) throw new Error(`unknown backup kind ${kind}`);
  if (kind === "local") sealKey = null; // its file key is in its header: the raw seal key never goes in
  if (sealKey && sealKey.length !== SEAL_KEY_BYTES) throw new Error("A seal key is 32 bytes");
  if (existsSync(out)) no("exists", `${out} already exists. Nothing was written.`);
  const fileKey = Buffer.from(random(32));
  let header, envelope = Buffer.alloc(0);
  if (kind === "local") header = { format: FORMAT, v: 1, kind, set, created, key: null, chunk: CHUNK, fileKey: b64u(fileKey) };
  else {
    if (!publicKey) no("no_backup_key", "No backup key is set, so nothing was backed up: backups are always encrypted. In Terminal (Admin): humid backup-key new -Path E:\\humid-backup.key (a USB drive), then keep that file off this computer.");
    const pub = publicKeyOf(publicKey);
    header = { format: FORMAT, v: 1, kind, set, created, key: pub.fingerprint, chunk: CHUNK, seal: !!sealKey };
    // A one-time signing key: HUMID-PQ1 envelopes are signed, and the server holds no key
    // that should vouch for a backup.
    const signer = suite().deriveKeys(random(64));
    const sealed = await suite().seal({ bytes: fileKey, name: `${kind}-file-key`, type: FILE_KEY_TYPE }, signer, pub,
      { identityCommit: "humid-server-backup", interrupt: { purpose: "server-backup", kind, set } });
    suite().wipeKeys(signer);
    envelope = Buffer.from(sealed.envelope);
  }
  const headerBytes = Buffer.from(JSON.stringify(header));
  const prefix = Buffer.concat([MAGIC, u32(headerBytes.length), headerBytes, u32(envelope.length), envelope]);
  const bound = Buffer.from(sha3_256(prefix));
  const part = `${out}.part`;
  mkdirSync(dirname(out), { recursive: true });
  const fd = openSync(part, "wx", 0o600);
  let bytes;
  try {
    writeSync(fd, prefix);
    const w = chunkWriter(fd, chunkKey(fileKey, bound), bound);
    if (sealKey) w.push(Buffer.concat([Buffer.from([3]), Buffer.from(sealKey)]));
    for (const e of entries(root, kind)) {
      const path = Buffer.from(e.rel);
      w.push(Buffer.concat([Buffer.from([e.type]), Buffer.from([path.length >> 8, path.length & 255]), path]));
      if (e.type !== 2) continue;
      const f = openSync(e.abs, "r");
      try {
        const size = fstatSync(f).size;
        w.push(u64(size));
        const buf = Buffer.alloc(Math.min(CHUNK, Math.max(size, 1)));
        let left = size;
        while (left > 0) {
          const r = readSync(f, buf, 0, Math.min(buf.length, left), null);
          if (!r) no("changed", `${e.abs} changed while it was being backed up. Nothing was backed up.`);
          w.push(buf.subarray(0, r));
          left -= r;
        }
      } finally { closeSync(f); }
    }
    w.push(Buffer.from([0]));
    w.close();
    bytes = fstatSync(fd).size;
  } catch (e) {
    closeSync(fd);
    rmSync(part, { force: true });
    throw e;
  }
  closeSync(fd);
  fileKey.fill(0);
  renameSync(part, out);
  return { file: out, bytes, kind, set };
}

/* ---------------------------------------------------------------- reading a backup */

/** The public header of a backup file (no key needed). */
export function readHeader(file) {
  const fd = openSync(file, "r");
  try { return parseHead(fd, basename(file)).header; } finally { closeSync(fd); }
}

function parseHead(fd, name) {
  let magic = null;
  try { magic = readExactly(fd, MAGIC.length, name); } catch {}
  if (!magic || !magic.equals(MAGIC)) no("not_backup", `${name} isn't a HumID Server backup.`);
  const hlen = readExactly(fd, 4, name).readUInt32BE(0);
  if (hlen > 64 * 1024) no("not_backup", `${name} isn't a HumID Server backup.`);
  const headerBytes = readExactly(fd, hlen, name);
  let header;
  try { header = JSON.parse(headerBytes.toString("utf8")); } catch { no("not_backup", `${name} isn't a HumID Server backup.`); }
  if (header?.format !== FORMAT) no("not_backup", `${name} isn't a HumID Server backup.`);
  if (header.v !== 1) no("not_backup", `${name} is from a newer HumID Server (format v${header.v}). Update HumID to restore it.`);
  if (!KINDS.includes(header.kind)) no("not_backup", `${name} isn't a HumID Server backup.`);
  const elen = readExactly(fd, 4, name).readUInt32BE(0);
  if (elen > 64 * 1024) no("not_backup", `${name} isn't a HumID Server backup.`);
  const envelope = readExactly(fd, elen, name);
  const prefix = Buffer.concat([MAGIC, u32(hlen), headerBytes, u32(elen), envelope]);
  return { header, envelope, bound: Buffer.from(sha3_256(prefix)) };
}

/** Is `rel` a path this kind of backup may hold? Never absolute, never "..". */
export function allowedPath(rel, kind) {
  if (typeof rel !== "string" || !rel || rel.length > 1024) return false;
  const parts = rel.split("/");
  if (parts.some((p) => !p || p === "." || p === ".." || /[\\:\0]/.test(p))) return false;
  const { top, skip } = CONTENTS[kind];
  if (skip.some((s) => rel === s || rel.startsWith(`${s}/`))) return false;
  return top.some((t) => rel === t || rel.startsWith(`${t}/`));
}

function openHead(fd, file, expectKind) {
  const name = basename(file);
  const { header, envelope, bound } = parseHead(fd, name);
  if (expectKind && header.kind !== expectKind) no("wrong_kind", `${name} isn't the file expected here.`);
  return { header, envelope, bound, name };
}

async function fileKeyOf({ header, envelope, name }, keys) {
  if (header.kind === "local") return Buffer.from(unb64u(String(header.fileKey)));
  if (!keys) no("no_key", `${name} is encrypted to backup key ${header.key}. Restoring it needs that key file (made by humid backup-key new, kept off this computer): add -Key <file>.`);
  if (keys.fingerprint !== header.key) no("wrong_key", `That backup key (${keys.fingerprint}) doesn't open ${name}: it was made for backup key ${header.key}. Nothing was restored.`);
  let opened;
  try { opened = await suite().open(new Uint8Array(envelope), keys.keys); }
  catch { no("wrong_key", `That backup key doesn't open ${name}, or the file was changed. Nothing was restored.`); }
  if (opened.meta.type !== FILE_KEY_TYPE || opened.bytes.length !== 32) no("damaged", `${name} is damaged or was changed. Nothing was restored.`);
  return Buffer.from(opened.bytes);
}

/** Unpack one backup file's archive into `into` (which already exists, and is empty of its paths). */
async function unpack(file, keys, into, expectKind) {
  const fd = openSync(file, "r");
  try {
    const head = openHead(fd, file, expectKind);
    const fileKey = await fileKeyOf(head, keys);
    const r = chunkReader(fd, chunkKey(fileKey, head.bound), head.bound, head.name);
    fileKey.fill(0);
    let files = 0, bytes = 0, sealKey = null, first = true;
    for (;;) {
      const type = r.take(1)[0];
      if (type === 0) break;
      if (type === 3) {
        if (!first || head.header.kind === "local" || head.header.seal !== true) no("damaged", `${head.name} holds something a HumID backup never does (a seal key out of place). Nothing was restored.`);
        sealKey = new Uint8Array(r.take(SEAL_KEY_BYTES));
        first = false;
        continue;
      }
      first = false;
      const len = r.take(2).readUInt16BE(0);
      const rel = r.take(len).toString("utf8");
      if ((type !== 1 && type !== 2) || !allowedPath(rel, head.header.kind)) no("damaged", `${head.name} holds something a HumID backup never does (${JSON.stringify(rel).slice(0, 80)}). Nothing was restored.`);
      const abs = join(into, ...rel.split("/"));
      if (type === 1) { mkdirSync(abs, { recursive: true }); continue; }
      const size = Number(r.take(8).readBigUInt64BE(0));
      mkdirSync(dirname(abs), { recursive: true });
      const out = openSync(abs, "wx", 0o600);
      try {
        for (let left = size; left > 0;) { const n = Math.min(left, CHUNK); writeSync(out, r.take(n)); left -= n; }
      } finally { closeSync(out); }
      files++; bytes += size;
    }
    r.end();
    if (head.header.seal === true && !sealKey) no("damaged", `${head.name} is damaged or was changed (its seal key is missing). Nothing was restored.`);
    return { header: head.header, files, bytes, sealKey };
  } finally { closeSync(fd); }
}

/**
 * Restore into `into`, a new folder (it must not exist; its parent must).
 *   file          the main backup (data), or a local rollback copy; null to restore keyshare's
 *                 half alone (moving the key-share data to a keys machine, docs/DEPLOY-VMS.md)
 *   keyshareFile  keyshare's half (needed with a data backup)
 *   keyText       the backup key file's contents (needed unless it's a local copy)
 * Everything is checked as it's unpacked; on any problem `into` is removed and nothing is left.
 * → { kind, created, set, files, bytes, sealKey }   kind "keyshare" for keyshare's half alone;
 *   sealKey: the raw seal key the backup carried (null for a local copy, or a server without sealing)
 */
export async function restoreBackup({ file = null, keyshareFile = null, keyText = null, into }) {
  if (!file && !keyshareFile) throw new Error("Nothing to restore: give a backup file.");
  const header = file ? readHeader(file) : null;
  if (header?.kind === "keyshare") no("wrong_kind", `${basename(file)} is keyshare's half of a backup: give it as the keyshare file (-KeysharePath), and the main file (HumID-backup-….humidbak) as the backup. To restore keyshare's half alone (a keys machine), give only -KeysharePath.`);
  let ksHeader = null;
  if (!header || header.kind === "data") {
    if (!keyshareFile) no("no_keyshare", `Restoring ${basename(file)} also needs keyshare's half, made by the same backup (HumID-keyshare-….humidbak): add -KeysharePath <file>. Without it, documents sealed with split keys can't be opened.`);
    ksHeader = readHeader(keyshareFile);
    if (ksHeader.kind !== "keyshare") no("wrong_kind", `${basename(keyshareFile)} isn't keyshare's half of a backup.`);
    if (header && ksHeader.set !== header.set) no("wrong_set", `${basename(keyshareFile)} was made by a different backup than ${basename(file)} (${ksHeader.created} and ${header.created}). Use the two files made together.`);
  }
  const main = header || ksHeader;
  const name = basename(file || keyshareFile);
  if (main.kind !== "local" && !keyText) no("no_key", `${name} is encrypted to backup key ${main.key}. Restoring it needs that key file (made by humid backup-key new, kept off this computer): add -Key <file>. Nothing was restored.`);
  const keys = main.kind === "local" ? null : readBackupKey(keyText);
  mkdirSync(into); // a new folder only; fails if it exists
  try {
    let files = 0, bytes = 0, sealKey = null;
    const take = (r) => {
      files += r.files; bytes += r.bytes;
      if (r.sealKey) {
        if (sealKey && !Buffer.from(sealKey).equals(Buffer.from(r.sealKey))) no("wrong_set", "These two files come from different servers (different seal keys). Nothing was restored.");
        sealKey = r.sealKey;
      }
    };
    if (header) take(await unpack(file, keys, into, header.kind));
    if (ksHeader) take(await unpack(keyshareFile, keys, into, "keyshare"));
    if (header && (!existsSync(join(into, "humid.env")) || !existsSync(join(into, "data")))) no("damaged", `${name} has no humid.env or data folder in it. Nothing was restored.`);
    if (!header && !existsSync(join(into, "data", "keyshare"))) no("damaged", `${name} holds no key-share data. Nothing was restored.`);
    if (keys) suite().wipeKeys(keys.keys);
    return { kind: main.kind, created: main.created, set: main.set, files, bytes, sealKey };
  } catch (e) {
    rmSync(into, { recursive: true, force: true });
    throw e;
  }
}

/* ---------------------------------------------------------------- the console's backups */

/** File names for one backup made now. */
export function backupNames(now = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`; // local time
  return { data: `HumID-backup-${stamp}${EXT}`, keyshare: `HumID-keyshare-${stamp}${EXT}` };
}

/** Keep the newest `keep` backups of each kind in a folder. */
export function prune(dir, prefix, keep = 10) {
  let files = [];
  try { files = readdirSync(dir).filter((f) => f.startsWith(prefix) && f.endsWith(EXT)).map((f) => ({ f, t: statSync(join(dir, f)).mtimeMs })); } catch { return; }
  for (const { f } of files.sort((a, b) => b.t - a.t).slice(keep)) rmSync(join(dir, f), { force: true });
}
