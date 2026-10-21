// @humid/creds/server — fetching what credential checks need from the
// internet: revocation status lists, and the trust lists (AAMVA's VICAL, ICAO
// master lists). Node only.
//
// A status list's address comes from inside the credential, which the
// presenter controls, so every fetch is treated as hostile (precert finding
// CRD-02, server-side request forgery):
//
//   - https only, port 443 only, no user name or password in the URL
//   - the host name is resolved here, every address it resolves to is checked
//     against private, loopback, link-local, carrier-grade NAT, multicast,
//     documentation and other reserved ranges (IPv4, IPv6, and IPv4 embedded
//     in IPv6), and the connection is made to the address that was checked,
//     so DNS can't answer one thing to the check and another to the connect
//   - no redirects: a 3xx is a failure, not a hop
//   - a deadline for the whole request, and a byte limit enforced while
//     reading (a declared Content-Length over the limit fails before reading)
//   - no cookies, no credentials, nothing about the person in the request
//   - an optional list of allowed hosts
//
// Nothing here decides whether what came back is trustworthy: the signature
// and freshness checks in @humid/sdjwt and the trust store do that.

import { request } from "node:https";
import { lookup as dnsLookup } from "node:dns";
import { BlockList, isIP } from "node:net";
import { CredsError, fail } from "./request.js";

const MiB = 1 << 20;

/** Every range a server-side fetch must never reach. */
export function strictBlockList() {
  const b = new BlockList();
  for (const [net, bits] of [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
    ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
    ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ]) b.addSubnet(net, bits, "ipv4");
  for (const [net, bits] of [
    ["::", 128], ["::1", 128], ["100::", 64], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
    ["2001::", 23], // IETF protocol assignments, incl. Teredo (2001::/32) and ORCHIDs
  ]) b.addSubnet(net, bits, "ipv6");
  return b;
}
const STRICT = strictBlockList();

/** IPv4 carried inside an IPv6 address (mapped, compatible, NAT64, 6to4), or null. */
function embeddedV4(v6) {
  const words = expand(v6);
  if (!words) return null;
  const v4 = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  if (words.slice(0, 5).every((w) => w === 0) && (words[5] === 0xffff || words[5] === 0)) return v4(words[6], words[7]); // ::ffff:a.b.c.d, ::a.b.c.d
  if (words[0] === 0x64 && words[1] === 0xff9b) return v4(words[6], words[7]); // 64:ff9b::/96 NAT64
  if (words[0] === 0x2002) return v4(words[1], words[2]); // 6to4
  return null;
}
function expand(v6) {
  let s = v6.toLowerCase().replace(/%.*$/, "");
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) { const p = tail[1].split(".").map(Number); s = s.slice(0, -tail[1].length) + ((p[0] << 8) | p[1]).toString(16) + ":" + ((p[2] << 8) | p[3]).toString(16); }
  const [a, b] = s.split("::");
  if (s.split("::").length > 2) return null;
  const head = a ? a.split(":") : [], rest = b !== undefined ? (b ? b.split(":") : []) : [];
  const fill = b !== undefined ? 8 - head.length - rest.length : 0;
  const all = [...head, ...Array(Math.max(fill, 0)).fill("0"), ...rest];
  if (all.length !== 8) return null;
  return all.map((x) => parseInt(x || "0", 16));
}

/** Is this address one a server-side fetch may connect to? */
export function publicAddress(address, blockList = STRICT) {
  const family = isIP(address);
  if (family === 4) return !blockList.check(address, "ipv4");
  if (family === 6) {
    if (blockList.check(address, "ipv6")) return false;
    const v4 = embeddedV4(address);
    return v4 ? !blockList.check(v4, "ipv4") : true;
  }
  return false;
}

/** The checked URL, or a CredsError. */
export function checkUrl(input, { allowHosts } = {}) {
  let u;
  try { u = new URL(input); } catch { fail("bad_url", "That address isn't a URL."); }
  if (u.protocol !== "https:") fail("bad_url", "Only https addresses are fetched.");
  if (u.username || u.password) fail("bad_url", "Addresses with a user name or password aren't fetched.");
  if (u.port && u.port !== "443") fail("bad_url", "Only the standard https port is fetched.");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || host.endsWith(".")) fail("bad_url", "That address has no usable host name.");
  if (isIP(host) && !publicAddress(host)) fail("blocked_address", "That address points inside a private network.");
  if (/(^|\.)(localhost|local|internal|home\.arpa|localdomain)$/.test(host)) fail("blocked_address", "That address points inside a private network.");
  if (allowHosts && !allowHosts.some((h) => (h.startsWith(".") ? host.endsWith(h) : host === h.toLowerCase()))) fail("blocked_host", "That host isn't on the list of places HumID fetches from.");
  return u;
}

/**
 * GET an https URL safely. Returns { bytes, contentType, url }.
 *   maxBytes     default 8 MiB
 *   timeoutMs    whole request, default 10 s
 *   accept       Accept header
 *   allowHosts   ["exact.host", ".suffix.example"], optional
 * Test-only knobs (never set them in production): resolve(host) → [address],
 * blockList, ca, connectPort.
 */
export function safeFetch(input, { maxBytes = 8 * MiB, timeoutMs = 10_000, accept = "*/*", allowHosts, resolve, blockList = STRICT, ca, connectPort = 443 } = {}) {
  const u = checkUrl(input, { allowHosts });
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const resolveAll = resolve || ((h) => new Promise((ok, no) => dnsLookup(h, { all: true, verbatim: true }, (e, list) => (e ? no(e) : ok(list.map((x) => x.address))))));

  return new Promise((done, failed) => {
    let finished = false;
    const finish = (fn, v) => { if (!finished) { finished = true; clearTimeout(timer); fn(v); } };
    const timer = setTimeout(() => { req?.destroy(); finish(failed, new CredsError("timeout", "The server took too long to answer.")); }, timeoutMs);
    let req;

    (async () => {
      let addresses;
      if (isIP(host)) addresses = [host];
      else {
        try { addresses = await resolveAll(host); } catch { throw new CredsError("dns_failed", "The host name couldn't be found."); }
      }
      if (!addresses?.length) throw new CredsError("dns_failed", "The host name couldn't be found.");
      // Every answer must be public: a name that also resolves to a private
      // address is refused outright, rather than hoping the public one is used.
      if (!addresses.every((a) => publicAddress(a, blockList))) throw new CredsError("blocked_address", "That address points inside a private network.");
      const pinned = addresses[0];
      const family = isIP(pinned);

      req = request({
        host, servername: isIP(host) ? undefined : host, port: connectPort, path: `${u.pathname}${u.search}`, method: "GET",
        headers: { accept, "user-agent": "HumID-credential-check/1", "accept-encoding": "identity" },
        // Connect to the address that was checked, whatever DNS says next.
        lookup: (_h, opts, cb) => (opts?.all ? cb(null, [{ address: pinned, family }]) : cb(null, pinned, family)),
        minVersion: "TLSv1.2", agent: false, ...(ca ? { ca } : {}),
      }, (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400) { res.resume(); return finish(failed, new CredsError("redirect_refused", "The server answered with a redirect, which isn't followed.")); }
        if (status !== 200) { res.resume(); return finish(failed, new CredsError("http_error", `The server answered ${status}.`)); }
        const declared = Number(res.headers["content-length"]);
        if (Number.isFinite(declared) && declared > maxBytes) { res.destroy(); return finish(failed, new CredsError("too_large", "The server's answer is too large.")); }
        const chunks = [];
        let n = 0;
        res.on("data", (c) => {
          n += c.length;
          if (n > maxBytes) { res.destroy(); finish(failed, new CredsError("too_large", "The server's answer is too large.")); return; }
          chunks.push(c);
        });
        res.on("end", () => finish(done, { bytes: new Uint8Array(Buffer.concat(chunks)), contentType: String(res.headers["content-type"] || "").split(";")[0].trim().toLowerCase(), url: u.href }));
        res.on("error", () => finish(failed, new CredsError("network", "The connection broke while reading.")));
      });
      req.on("error", (e) => finish(failed, e instanceof CredsError ? e : new CredsError("network", "The server couldn't be reached securely.")));
      req.end();
    })().catch((e) => finish(failed, e instanceof CredsError ? e : new CredsError("network", "The server couldn't be reached.")));
  });
}

/**
 * fetchList for checkStatus: fetches a Token Status List safely and returns a
 * statuslist+jwt as text or a statuslist+cwt as bytes. Lists are cached for
 * cacheMs (default 10 minutes) and concurrent requests for one list share a
 * fetch. Freshness and signatures are still checked by checkStatus.
 */
export function statusListFetcher({ cacheMs = 10 * 60_000, maxEntries = 500, maxBytes = 8 * MiB, ...opts } = {}) {
  const cache = new Map(); // uri → { at, value } or { pending }
  return async function fetchList(uri) {
    const now = Date.now();
    const hit = cache.get(uri);
    if (hit?.pending) return hit.pending;
    if (hit && now - hit.at < cacheMs) return hit.value;
    const pending = (async () => {
      const r = await safeFetch(uri, { ...opts, maxBytes, accept: "application/statuslist+jwt, application/statuslist+cwt" });
      if (r.contentType === "application/statuslist+jwt") {
        let text;
        try { text = new TextDecoder("utf-8", { fatal: true }).decode(r.bytes).trim(); } catch { fail("bad_status_list", "The status list isn't text."); }
        return text;
      }
      if (r.contentType === "application/statuslist+cwt") return r.bytes;
      fail("bad_status_list", "The server didn't answer with a status list.");
    })();
    cache.set(uri, { pending });
    try {
      const value = await pending;
      if (cache.size >= maxEntries) cache.delete(cache.keys().next().value);
      cache.set(uri, { at: Date.now(), value });
      return value;
    } catch (e) { cache.delete(uri); throw e; }
  };
}
