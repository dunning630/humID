// @humid/creds/server — keeping the trust store current: fetch the signed
// lists (safeFetch), check them against pinned providers, apply them, and
// save the result atomically. One failing source never touches the others,
// and a failed refresh keeps the last good store.
//
// Config (deploy/trust/trust-config.example.json):
//   {
//     "vical": { "id": "aamva", "url": "https://…", "providerPins": ["<sha256>"] },
//     "masterLists": [{ "source": "icao", "url": "https://…", "publisherCerts": ["<file>"], "publisherPins": ["<sha256>"] }],
//     "allowHosts": ["vical.dts.aamva.org", ".icao.int", ".bsi.bund.de"]
//   }
// A source can name a local "file" instead of a "url" (for lists that must be
// downloaded by hand after accepting terms, such as ICAO's).

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, openSync, fsyncSync, closeSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { inflateRawSync } from "node:zlib";
import { createTrustStore, loadTrustStore } from "./trust.js";
import { applyMasterList } from "./server.js";
import { safeFetch } from "./fetch.js";
import { CredsError, fail } from "./request.js";

const MiB = 1 << 20;

/**
 * The one *.ml (or *.der, *.cms) file inside a zip, or the bytes themselves if
 * they aren't a zip. Master lists are often published zipped. Caps the size
 * and refuses anything but a single list.
 */
export function unzipMasterList(bytes, { maxBytes = 32 * MiB } = {}) {
  const b = Buffer.from(bytes);
  if (b.length < 4 || b.readUInt32LE(0) !== 0x04034b50) return new Uint8Array(b);
  const found = [];
  let p = 0;
  while (p + 30 <= b.length && b.readUInt32LE(p) === 0x04034b50) {
    const flags = b.readUInt16LE(p + 6), method = b.readUInt16LE(p + 8);
    const csize = b.readUInt32LE(p + 18), usize = b.readUInt32LE(p + 22);
    const nlen = b.readUInt16LE(p + 26), xlen = b.readUInt16LE(p + 28);
    const name = b.subarray(p + 30, p + 30 + nlen).toString("utf8");
    const start = p + 30 + nlen + xlen;
    if (flags & 0x08) fail("bad_master_list", "This zip format isn't supported; unzip the master list first.");
    if (start + csize > b.length) fail("bad_master_list", "The zip file is cut short.");
    if (usize > maxBytes) fail("too_large", "The master list is too large.");
    if (/\.(ml|der|cms|bin)$/i.test(name) && !name.includes("..")) {
      const data = b.subarray(start, start + csize);
      let out;
      if (method === 0) out = data;
      else if (method === 8) { try { out = inflateRawSync(data, { maxOutputLength: maxBytes }); } catch { fail("bad_master_list", "The zip file can't be decompressed."); } }
      else fail("bad_master_list", "This zip compression isn't supported.");
      if (out.length !== usize) fail("bad_master_list", "The zip file is damaged.");
      found.push(out);
    }
    p = start + csize;
  }
  if (found.length !== 1) fail("bad_master_list", found.length ? "The zip holds more than one master list." : "The zip holds no master list.");
  return new Uint8Array(found[0]);
}

/** Read a saved store; a missing file is an empty store. minRev: refuse anything older (rollback). */
export function readTrustStoreFile(path, { minRev = 0 } = {}) {
  if (!existsSync(path)) return createTrustStore();
  let snap;
  try { snap = JSON.parse(readFileSync(path, "utf8")); } catch { fail("bad_trust_store", "The trust store file is damaged."); }
  return loadTrustStore(snap, { minRev });
}

/** Save atomically (write, flush, rename), readable only by this account. */
export function saveTrustStoreFile(path, store) {
  mkdirSync(dirname(resolvePath(path)), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(store.toJSON()), { mode: 0o600 });
  const fd = openSync(tmp, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, path);
}

async function bytesOf(src, { allowHosts, fetch = safeFetch, baseDir = process.cwd(), maxBytes }) {
  if (src.file) return new Uint8Array(readFileSync(resolvePath(baseDir, src.file)));
  if (src.url) return (await fetch(src.url, { allowHosts, maxBytes, accept: "application/octet-stream, application/cbor, application/zip, */*" })).bytes;
  fail("bad_config", "A trust source needs a url or a file.");
}

/**
 * Refresh every configured source into `store`. Returns a report:
 *   { changed, sources: { [name]: { ok, ...details } | { ok: false, code, error } } }
 * Never throws for one source's failure; the store keeps that source's last good data.
 */
export async function refreshTrust(store, config, { now = new Date(), fetch, baseDir } = {}) {
  const report = { changed: false, sources: {} };
  const rev = store.rev;
  if (config.vical) {
    const v = config.vical, name = `vical:${v.id || "aamva"}`;
    try {
      const bytes = await bytesOf(v, { allowHosts: config.allowHosts, fetch, baseDir, maxBytes: 16 * MiB });
      report.sources[name] = { ok: true, ...store.applyVical(bytes, { providerPins: v.providerPins, id: v.id || "aamva", now, maxAgeDays: v.maxAgeDays, graceDays: v.graceDays }) };
    } catch (e) { report.sources[name] = { ok: false, code: e.code || "error", error: e.message }; }
  }
  for (const m of config.masterLists || []) {
    const name = m.source;
    try {
      const raw = await bytesOf(m, { allowHosts: config.allowHosts, fetch, baseDir, maxBytes: 32 * MiB });
      const publisherCscas = (m.publisherCerts || []).map((f) => readFileSync(resolvePath(baseDir || process.cwd(), f)));
      report.sources[name] = { ok: true, ...applyMasterList(store, unzipMasterList(raw), { source: name, publisherCscas, publisherPins: m.publisherPins, now }) };
    } catch (e) { report.sources[name] = { ok: false, code: e.code || "error", error: e.message }; }
  }
  report.changed = store.rev !== rev;
  report.status = store.status({ now });
  return report;
}

/**
 * Keep a trust store file current: refresh now and then every `everyMs`
 * (default 6 hours), saving only when something changed. The recovery service
 * picks up a saved file on its next request. Returns { stop, runOnce }.
 */
export function startTrustRefresh({ path, config, everyMs = 6 * 3600_000, onReport = () => {}, baseDir } = {}) {
  if (!path || !config) throw new CredsError("bad_config", "Say where the trust store lives and what to refresh it from.");
  // The highest revision ever saved is kept beside the store, so a restart doesn't
  // accept an older trust.json put back in its place. (Someone who can rewrite both
  // files on this disk already controls the server.)
  const revFile = `${path}.rev`;
  const readRev = () => { try { return Number(readFileSync(revFile, "utf8")) || 0; } catch { return 0; } };
  let lastRev = readRev();
  const runOnce = async () => {
    const store = readTrustStoreFile(path, { minRev: Math.max(lastRev, readRev()) });
    const report = await refreshTrust(store, config, { baseDir });
    if (report.changed) { saveTrustStoreFile(path, store); writeFileSync(revFile, String(store.rev), { mode: 0o600 }); }
    lastRev = store.rev;
    onReport(report);
    return report;
  };
  const timer = setInterval(() => { runOnce().catch((e) => onReport({ changed: false, error: e.message })); }, everyMs);
  timer.unref?.();
  const first = runOnce().catch((e) => { onReport({ changed: false, error: e.message }); return null; });
  return { stop: () => clearInterval(timer), runOnce, first };
}
