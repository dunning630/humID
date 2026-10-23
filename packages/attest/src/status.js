// Google's attestation status list: certificates in Android attestation chains that
// Google has revoked or suspended (leaked device keys, compromised factory keys).
// https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
//
// The identity service keeps a copy, from one of two sources:
//   url   it fetches the list itself (a host with outbound HTTPS: Windows, a VM)
//   file  a copy another process fetched (Docker: identity has no route to the
//         internet, so the attestation-status sidecar fetches it and writes it to
//         a volume identity reads; fetchStatusToFile below)
// A chain with a listed certificate is refused. If the list can't be refreshed, the last
// copy is used. With `required`, a copy that is missing or older than `maxAgeMs` refuses
// the chain instead (status_unavailable / status_stale): revocation fails closed.

import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { serialKey, AttestationError } from "./android.js";

export const STATUS_URL = "https://android.googleapis.com/attestation/status";
/** A copy older than this is stale: Google updates the list as keys leak, and it is refreshed every 6 hours. */
export const STATUS_MAX_AGE_MS = 48 * 3600_000;

/** { entries: { "<serial hex>": { status: "REVOKED" | "SUSPENDED", reason } } } → Set of serials. */
export function parseStatusList(json) {
  const entries = json?.entries;
  if (!entries || typeof entries !== "object") throw new Error("Not an attestation status list");
  const out = new Set();
  for (const [serial, e] of Object.entries(entries)) {
    if (e?.status === "REVOKED" || e?.status === "SUSPENDED") out.add(serialKey(serial));
  }
  return out;
}

/** The file a fetcher writes: when Google's list was fetched, and the list as Google sent it. */
export function readStatusFile(text, now = Date.now()) {
  const j = JSON.parse(text);
  const at = Date.parse(j?.fetchedAt);
  if (!Number.isFinite(at) || at > now + 5 * 60_000) throw new Error("The status file has no believable fetch time");
  return { set: parseStatusList(j.status), at };
}

async function fetchList(url, fetch) {
  const r = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const json = await r.json();
  parseStatusList(json); // refuse anything that isn't a status list before keeping it
  return json;
}

/**
 * Fetch Google's list once and write it to `file` (atomically: a reader sees the old copy
 * or the new one, never half of one). Anything that isn't a status list is refused and
 * the previous copy stays.
 */
export async function fetchStatusToFile({ url = STATUS_URL, file, fetch = globalThis.fetch, now = Date.now } = {}) {
  const status = await fetchList(url, fetch);
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify({ fetchedAt: new Date(now()).toISOString(), url, status }), { mode: 0o644 });
  await rename(tmp, file);
  return { entries: Object.keys(status.entries).length };
}

/** The sidecar: fetch now, then every refreshMs, sooner after a failure. Runs until stopped. */
export function runStatusFetcher({ url = STATUS_URL, file, refreshMs = 6 * 3600_000, retryMs = 10 * 60_000, fetch = globalThis.fetch, log = () => {} } = {}) {
  let timer = null, stopped = false;
  const tick = async () => {
    let wait = refreshMs;
    try { log("attestation_status_fetched", { file, ...(await fetchStatusToFile({ url, file, fetch })) }); }
    catch (e) { log("attestation_status_unavailable", { error: e.message }); wait = Math.min(retryMs, refreshMs); }
    if (!stopped) timer = setTimeout(tick, wait);
  };
  tick();
  return { stop() { stopped = true; clearTimeout(timer); } };
}

/**
 * A self-refreshing copy of the list.
 *   url ("" to turn off) or file (a fetcher's copy; wins over url), refreshMs, retryMs,
 *   required, maxAgeMs, fetch (injectable), now (injectable), log
 * Returns { serials({ required }?), ready, fetchedAt, source, refresh(), stop() }.
 * serials() throws when required and the copy is missing or stale; a caller can pass
 * { required: false } to take whatever copy there is (a non-attested policy).
 */
export function revocationList({ url = STATUS_URL, file = "", refreshMs = 6 * 3600_000, retryMs = 10 * 60_000, fetch = globalThis.fetch, required = false, maxAgeMs = STATUS_MAX_AGE_MS, now = Date.now, log = () => {} } = {}) {
  let set = null, timer = null, at = 0, stopped = false;
  const source = file ? "file" : url ? "url" : "off";
  // a file is re-read often (it's local and the fetcher replaces it when it likes)
  const every = file ? Math.min(retryMs, refreshMs) : refreshMs;
  async function refresh() {
    if (source === "off") return false;
    try {
      if (file) ({ set, at } = readStatusFile(await readFile(file, "utf8"), now()));
      else { set = parseStatusList(await fetchList(url, fetch)); at = now(); }
      return true;
    } catch (e) {
      log("attestation_status_unavailable", { source, error: e.code === "ENOENT" ? "no status file yet" : e.message, lastFetched: at ? new Date(at).toISOString() : null });
      return false;
    }
  }
  if (source !== "off") {
    const tick = async () => {
      const ok = await refresh();
      if (!stopped) { timer = setTimeout(tick, ok ? every : Math.min(retryMs, every)); timer.unref?.(); }
    };
    tick();
  }
  return {
    serials({ required: need = required } = {}) {
      if (need && source !== "off") {
        if (!set) throw new AttestationError("status_unavailable", "Google's attestation status list hasn't been fetched yet, so phones can't be checked. Try again shortly.");
        if (now() - at > maxAgeMs) throw new AttestationError("status_stale", "Google's attestation status list is out of date, so phones can't be checked. The server's operator needs to restore its fetch.");
      }
      return set || new Set();
    },
    get ready() { return !!set; },
    get fetchedAt() { return at; },
    source,
    refresh,
    stop() { stopped = true; clearTimeout(timer); },
  };
}
