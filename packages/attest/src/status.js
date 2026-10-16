// Google's attestation status list: certificates in Android attestation chains that
// Google has revoked or suspended (leaked device keys, compromised factory keys).
// https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
//
// The identity service keeps a copy and refreshes it every few hours. A chain with a
// listed certificate is refused. If the list can't be fetched, the last copy is used;
// with `required`, enrolment is refused until a copy has been fetched at all.

import { serialKey, AttestationError } from "./android.js";

export const STATUS_URL = "https://android.googleapis.com/attestation/status";

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

/**
 * A self-refreshing copy of the list.
 *   url ("" to turn off), refreshMs, fetch (injectable), required, log
 * Returns { serials(), ready, refresh(), stop() }. serials() throws when `required`
 * and no copy has ever been fetched.
 */
export function revocationList({ url = STATUS_URL, refreshMs = 6 * 3600_000, fetch = globalThis.fetch, required = false, log = () => {} } = {}) {
  let set = null, timer = null, at = 0;
  async function refresh() {
    if (!url) return;
    try {
      const r = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      set = parseStatusList(await r.json());
      at = Date.now();
    } catch (e) {
      log("attestation_status_unavailable", { error: e.message, lastFetched: at ? new Date(at).toISOString() : null });
    }
  }
  if (url) {
    refresh();
    timer = setInterval(refresh, refreshMs);
    timer.unref?.();
  }
  return {
    serials() {
      if (set) return set;
      if (required && url) {
        throw new AttestationError("status_unavailable", "Google's attestation status list hasn't been fetched yet, so phones can't be checked. Try again shortly.");
      }
      return new Set();
    },
    get ready() { return !!set; },
    get fetchedAt() { return at; },
    refresh,
    stop() { clearInterval(timer); },
  };
}
