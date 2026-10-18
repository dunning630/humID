// A backup repository: a flat set of named blobs in any store (a folder, a USB
// drive, a HumID vault bucket, S3 — anything with put/get/has/list).
//
//   config.json            format, repo id, chunk size, policy, the wrapped backup key, a key check
//   vault-part.humid       the HumID-gated part of the backup key (a PQ1 envelope)
//   chunks/ab/<id>         nonce ‖ AES-256-GCM(chunk key, chunk) — content, deduplicated
//   snapshots/<id>         nonce ‖ AES-256-GCM(snapshot key, snapshot JSON)
//
// What the store learns: how many chunks and snapshots there are and their
// sizes. Not file names, folder structure, sizes of individual files, or
// whether two people have the same file: chunk ids are a KEYED hash (the key
// comes from the backup key), so the store can't test for a known file.
//
// Format v1 is fixed-size chunking (1 MiB default). Content-defined chunking
// (better deduplication when bytes are inserted mid-file) would be format v2,
// with its own parse branch, as the envelope format does.

import { sha3_256 } from "@noble/hashes/sha3.js";
import { hmac } from "@noble/hashes/hmac.js";
import { concat, toHex, encodeJSON, decodeJSON, utf8 } from "@humid/codec";
import { suite } from "@humid/crypto";
import {
  newBackupKey, splitBackupKey, combineParts, derive, keyCheck, verifyKey, wrapKey, unwrapKey, wipe,
  formatSheet, parseSheet, encodeContactPart, decodeContactPart, sealVaultPart, openVaultPart,
} from "./keys.js";
import { DEFAULT_POLICY, classifier, safePath } from "./policy.js";

export const FORMAT = "humid-backup";
export const FORMAT_VERSION = 1;
export const DEFAULT_CHUNK = 1 << 20;
const MIN_CHUNK = 64 << 10;
const MAX_CHUNK = 16 << 20;

const subtle = globalThis.crypto.subtle;
const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

const CONFIG = "config.json";
const VAULT_PART = "vault-part.humid";
const chunkName = (id) => `chunks/${id.slice(0, 2)}/${id}`;
const snapName = (id) => `snapshots/${id}`;

async function aead(key, plain, aad) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const nonce = random(12);
  return concat(nonce, new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, k, plain)));
}

async function unaead(key, blob, aad, what) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: aad }, k, blob.subarray(12)));
  } catch { throw new Error(`${what} is damaged or was changed.`); }
}

/** An in-memory store, for tests and previews. */
export function memoryStore() {
  const m = new Map();
  return {
    blobs: m,
    async put(name, bytes) { m.set(name, Uint8Array.from(bytes)); },
    async get(name) { return m.has(name) ? Uint8Array.from(m.get(name)) : null; },
    async has(name) { return m.has(name); },
    async list(prefix = "") { return [...m.keys()].filter((k) => k.startsWith(prefix)).sort(); },
  };
}

async function readConfig(store) {
  const raw = await store.get(CONFIG);
  if (!raw) throw new Error("This is not a HumID backup (no config.json).");
  const c = decodeJSON(raw);
  if (c.format !== FORMAT) throw new Error("This is not a HumID backup.");
  if (c.v !== FORMAT_VERSION) throw new Error(`This backup uses format v${c.v}. Update HumID to open it.`);
  return c;
}

/* ---------------- create ---------------- */

/**
 * Create a repository. The HumID side (signer, recipient, ctx) comes from a live
 * check in the app; see sealVaultPart.
 * @returns { repoId, key, sheet, contactPart, keyshare }
 *   key          the backup key, for the first backup now; wipe it afterwards
 *   sheet        the code to print (HUMIDBK-…)
 *   contactPart  bytes to give the trusted contact (seal it to them like a recovery share)
 *   keyshare     send to the keyshare service; never store it next to the repository
 */
export async function createRepo(store, { vault, chunkSize = DEFAULT_CHUNK, policy = DEFAULT_POLICY, label = "" }) {
  if (await store.has(CONFIG)) throw new Error("There is already a backup here.");
  if (!(Number.isInteger(chunkSize) && chunkSize >= MIN_CHUNK && chunkSize <= MAX_CHUNK)) throw new Error("Chunk size must be between 64 KiB and 16 MiB.");
  const repoId = toHex(random(16));
  const key = newBackupKey();
  const made = await newParts(key, repoId, vault);
  const config = {
    format: FORMAT, v: FORMAT_VERSION, repoId, label: String(label).slice(0, 80),
    created: new Date().toISOString(), suite: suite().ID, chunkSize,
    policy, wrapped: made.wrapped, check: await keyCheck(key, repoId),
  };
  await store.put(VAULT_PART, made.envelope);
  await store.put(CONFIG, encodeJSON(config));
  return { repoId, key, sheet: made.sheet, contactPart: made.contactPart, keyshare: made.keyshare };
}

/** A new part key for `key`: wrap, split, seal the vault part, format the other two. */
async function newParts(key, repoId, vault) {
  const partKey = newBackupKey();
  const parts = splitBackupKey(partKey);
  const wrapped = await wrapKey(partKey, key, repoId);
  const { envelope, keyshare } = await sealVaultPart(parts.vault, { ...vault, repoId });
  const out = { wrapped, envelope, keyshare, sheet: formatSheet(parts.sheet, repoId), contactPart: encodeContactPart(parts.contact, repoId) };
  wipe(partKey, parts.vault.y, parts.sheet.y, parts.contact.y);
  return out;
}

/** Public facts about a repository, readable without any key. */
export async function describe(store) {
  const { repoId, label, created, suite: s, chunkSize, policy } = await readConfig(store);
  return { repoId, label, created, suite: s, chunkSize, policy };
}

/** The HumID-gated part, for the app to open inside a live check. */
export const vaultPartEnvelope = (store) => store.get(VAULT_PART);

/**
 * Rebuild the backup key from any two parts.
 * @param vault   { keys, keyshare } — the identity's keys and the keyshare service's release
 * @param sheet   what the person typed from the printed sheet
 * @param contact the bytes the contact sent back
 */
export async function unlock(store, { vault, sheet, contact } = {}) {
  const { repoId, check, wrapped } = await readConfig(store);
  const parts = [];
  if (vault) parts.push(await openVaultPart(await store.get(VAULT_PART), vault.keys, vault.keyshare, repoId));
  if (sheet) parts.push(parseSheet(sheet, repoId));
  if (contact) parts.push(decodeContactPart(contact, repoId));
  const partKey = combineParts(parts);
  parts.forEach((p) => wipe(p.y));
  const key = await unwrapKey(partKey, wrapped, repoId);
  wipe(partKey);
  if (!key || !(await verifyKey(key, repoId, check))) { if (key) wipe(key); throw new Error("Those parts don't open this backup."); }
  return key;
}

/**
 * Replace all three parts: a lost sheet, a contact you no longer trust, or a
 * new HumID account (a RECOVERED account keeps the same seed and needs nothing
 * here). Makes a new part key that wraps the same backup key, so the old
 * parts stop opening this repository and no data is re-encrypted. Needs the
 * backup key, so it runs after an unlock.
 * @returns { sheet, contactPart, keyshare } — hand out and store as at creation
 */
export async function replaceParts(store, key, vault) {
  const config = await readConfig(store);
  if (!(await verifyKey(key, config.repoId, config.check))) throw new Error("That key does not open this backup.");
  const made = await newParts(key, config.repoId, vault);
  await store.put(VAULT_PART, made.envelope);
  await store.put(CONFIG, encodeJSON({ ...config, wrapped: made.wrapped, partsReplaced: new Date().toISOString() }));
  return { sheet: made.sheet, contactPart: made.contactPart, keyshare: made.keyshare };
}

/* ---------------- back up ---------------- */

const keysFor = (key) => ({ id: derive(key, "chunk-id"), snap: derive(key, "snapshot") });

const snapshotId = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z") + "-" + toHex(random(4));

async function putChunk(store, key, ids, bytes, stats) {
  const id = toHex(hmac(sha3_256, ids.id, bytes));
  if (!(await store.has(chunkName(id)))) {
    const ck = derive(key, "chunk-key", utf8(id));
    await store.put(chunkName(id), await aead(ck, bytes, utf8(`HUMID-BACKUP-CHUNK-v1|${id}`)));
    wipe(ck);
    stats.newChunks++; stats.storedBytes += bytes.length;
  } else stats.reusedChunks++;
  return id;
}

/**
 * Back up a source into a new snapshot.
 * @param source { entries({ exclude }) → async iterable of {path, kind: "file"|"dir"|"symlink", size, mode, mtime, target},
 *                 read(entry, chunkSize) → async iterable of Uint8Array of at most chunkSize bytes }
 * @param parent a snapshot id; files with the same path, size and mtime reuse its chunks without being read
 * @returns { id, files, dirs, bytes, excluded, sensitive, newChunks, reusedChunks, storedBytes }
 */
export async function backup(store, key, source, { parent = null, host = "", label = "", onProgress } = {}) {
  const config = await readConfig(store);
  if (!(await verifyKey(key, config.repoId, config.check))) throw new Error("That key does not open this backup.");
  const ids = keysFor(key);
  const classify = classifier(config.policy);
  const prior = new Map();
  if (parent) for (const f of (await readSnapshot(store, key, parent)).files) prior.set(f.path, f);

  const stats = { files: 0, dirs: 0, bytes: 0, excluded: 0, sensitive: 0, newChunks: 0, reusedChunks: 0, storedBytes: 0 };
  const files = [], dirs = [], links = [];
  const exclude = (path, isDir) => classify(path, isDir) === "exclude";

  for await (const e of source.entries({ exclude })) {
    const path = safePath(e.path);
    const cls = classify(path, e.kind === "dir");
    if (cls === "exclude") { stats.excluded++; continue; }
    const sensitive = cls === "sensitive";
    if (e.kind === "dir") { dirs.push({ path, mode: e.mode ?? null, sensitive }); stats.dirs++; continue; }
    if (e.kind === "symlink") { links.push({ path, target: String(e.target), sensitive }); continue; }
    const mtime = e.mtime ?? null;
    const was = prior.get(path);
    let chunks;
    if (was && was.size === e.size && was.mtime === mtime && mtime !== null) {
      chunks = was.chunks;
      stats.reusedChunks += chunks.length;
    } else {
      chunks = [];
      let size = 0;
      for await (const piece of source.read(e, config.chunkSize)) {
        if (piece.length > config.chunkSize) throw new Error("Source returned a chunk larger than the chunk size.");
        size += piece.length;
        chunks.push(await putChunk(store, key, ids, piece, stats));
      }
      if (size !== e.size) e.size = size; // the file changed while being read; record what was read
    }
    files.push({ path, size: e.size, mode: e.mode ?? null, mtime, sensitive, chunks });
    stats.files++; stats.bytes += e.size;
    if (sensitive) stats.sensitive++;
    onProgress?.({ path, ...stats });
  }

  const id = snapshotId();
  const snapshot = {
    v: 1, id, repoId: config.repoId, created: new Date().toISOString(),
    host: String(host).slice(0, 120), label: String(label).slice(0, 120), parent,
    chunkSize: config.chunkSize, stats, dirs, files, links,
  };
  await store.put(snapName(id), await aead(ids.snap, encodeJSON(snapshot), utf8(`HUMID-BACKUP-SNAP-v1|${config.repoId}|${id}`)));
  wipe(ids.id, ids.snap);
  return { id, ...stats };
}

/* ---------------- read ---------------- */

export async function readSnapshot(store, key, id) {
  const { repoId } = await readConfig(store);
  if (!/^[0-9TZ]+-[0-9a-f]{8}$/.test(id)) throw new Error("Not a snapshot id.");
  const blob = await store.get(snapName(id));
  if (!blob) throw new Error(`No snapshot ${id} in this backup.`);
  const snap = decodeJSON(await unaead(derive(key, "snapshot"), blob, utf8(`HUMID-BACKUP-SNAP-v1|${repoId}|${id}`), "Snapshot"));
  if (snap.id !== id || snap.repoId !== repoId) throw new Error("Snapshot doesn't belong here.");
  return snap;
}

/** Every snapshot, newest first: { id, created, host, label, files, bytes, sensitive }. */
export async function listSnapshots(store, key) {
  const names = await store.list("snapshots/");
  const out = [];
  for (const n of names) {
    const s = await readSnapshot(store, key, n.slice("snapshots/".length));
    out.push({ id: s.id, created: s.created, host: s.host, label: s.label, files: s.stats.files, bytes: s.stats.bytes, sensitive: s.stats.sensitive });
  }
  return out.sort((a, b) => (a.id < b.id ? 1 : -1));
}

async function* readChunks(store, key, ids, chunkIds) {
  for (const id of chunkIds) {
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error("Snapshot names a chunk that can't exist.");
    const blob = await store.get(chunkName(id));
    if (!blob) throw new Error(`A piece of this backup is missing (${id.slice(0, 12)}…).`);
    const ck = derive(key, "chunk-key", utf8(id));
    const bytes = await unaead(ck, blob, utf8(`HUMID-BACKUP-CHUNK-v1|${id}`), "A piece of this backup");
    wipe(ck);
    if (toHex(hmac(sha3_256, ids.id, bytes)) !== id) throw new Error("A piece of this backup doesn't match its id.");
    yield bytes;
  }
}

/* ---------------- restore ---------------- */

/**
 * Restore a snapshot into a target.
 * @param target { mkdir(path, entry), write(path, chunks: async iterable, entry), symlink?(path, target, entry) }
 * @param includeSensitive false (default): sensitive files are listed in `held`, not written.
 *                         true, or a function (path) → bool: restore those (ask for a second check first)
 * @param only   (path) → bool: restore part of a snapshot
 * @param scan   async (entry, bytes) → true to restore, false to quarantine; runs on each
 *               file before it's written (e.g. a malware scanner). Files over scanLimit
 *               bytes skip the scan and are listed in `unscanned`.
 * @returns { files, bytes, held, quarantined, unscanned }
 */
export async function restore(store, key, id, target, { includeSensitive = false, only = null, scan = null, scanLimit = 256 << 20, onProgress } = {}) {
  const snap = await readSnapshot(store, key, id);
  const ids = keysFor(key);
  const wantSensitive = typeof includeSensitive === "function" ? includeSensitive : () => includeSensitive === true;
  const pick = (p) => !only || only(p);
  const result = { files: 0, bytes: 0, held: [], quarantined: [], unscanned: [] };

  for (const d of snap.dirs) {
    const path = safePath(d.path);
    if (!pick(path) || (d.sensitive && !wantSensitive(path))) continue;
    await target.mkdir(path, d);
  }
  for (const f of snap.files) {
    const path = safePath(f.path);
    if (!pick(path)) continue;
    if (f.sensitive && !wantSensitive(path)) { result.held.push(path); continue; }
    let chunks = readChunks(store, key, ids, f.chunks);
    if (scan && f.size <= scanLimit) {
      const parts = [];
      for await (const c of chunks) parts.push(c);
      const bytes = concat(...parts);
      if (!(await scan({ ...f, path }, bytes))) { result.quarantined.push(path); continue; }
      chunks = (async function* () { yield bytes; })();
    } else if (scan) result.unscanned.push(path);
    await target.write(path, chunks, f);
    result.files++; result.bytes += f.size;
    onProgress?.({ path, ...result });
  }
  for (const l of snap.links) {
    const path = safePath(l.path);
    if (!pick(path) || (l.sensitive && !wantSensitive(path)) || !target.symlink) continue;
    await target.symlink(path, l.target, l);
  }
  wipe(ids.id, ids.snap);
  return result;
}

/* ---------------- maintenance ---------------- */

/** Chunks no snapshot uses (after snapshots are deleted). Returns their names; delete them with the store. */
export async function unusedChunks(store, key) {
  const used = new Set();
  for (const n of await store.list("snapshots/")) for (const f of (await readSnapshot(store, key, n.slice(10))).files) f.chunks.forEach((c) => used.add(chunkName(c)));
  return (await store.list("chunks/")).filter((n) => !used.has(n));
}

