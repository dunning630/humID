// relay — the mailbox service for person-to-person messaging (HumID 4.0, docs/MESSAGING.md).
//
// The same rules as the reference relay in @humid/msg (memoryRelay), kept on disk:
//
//   - No accounts and no senders. A deposit is (mailbox id, wire object, optional unsend tag).
//     The gateway forwards relay calls only from sessions that have NOT signed in, so this
//     service, and the gateway's own logs, never learn who wrote to whom.
//   - Only wire objects of the fixed sizes (@humid/msg wire.js), kept at most 14 days.
//   - No cryptography and no keys: nothing to steal, nothing to time, nothing worth forging.
//   - An empty mailbox and one that never existed answer identically (audit SEC-S-13).
//   - Unsend: an object posted with a tag (SHA3 of a token only the sender holds) is removed
//     when the sender shows the token, if it hasn't been fetched yet.
//   - Caps on every dimension (audit SEC-S-02, -03, -08, precert PC-27, review MSG-05): objects
//     and bytes per mailbox; bytes per day per address (IPv6 /64), per site (IPv6 /48) and per
//     block (IPv4 /24, IPv6 /32), so a few dozen addresses can't fill the relay for everyone;
//     near full, a fair share per block; total bytes; and calls per network per minute. Every
//     counter is a fixed-size sketch, so none of them can fill up and lock new networks out.
//
// What it stores: mailbox id, arrival time (to the minute), the object, the unsend tag. What
// it is told about the caller: a rate key (an IPv4 address or an IPv6 /64), used for limits
// in memory and never written down.

import { createHash } from "node:crypto";
import { createService, serviceTlsFromEnv, openDb, env, json, parseJson, verifyAssertion, HttpError, isMain, b64u, unb64u } from "@humid/svc";
import { isBox, isWireSize, retractTag, MAX_WIRE, TAG_RE, RETRACT_BYTES, RELAY_DEFAULTS } from "@humid/msg/relay-rules";

const MINUTE = 60_000;
const DAY = 86_400_000;
export const MAX_TAKE_BOXES = 64;         // mailboxes one poll may empty
export const MAX_TAKE_BYTES = 8 * 1024 * 1024; // what one poll may hand back; the rest waits for the next poll

export function createRelay({
  tls = serviceTlsFromEnv(),
  port = Number(env("PORT", "8087")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  ttlMs = Number(env("HUMID_RELAY_TTL_MS", String(RELAY_DEFAULTS.ttlMs))),
  maxPerBox = Number(env("HUMID_RELAY_MAX_PER_BOX", String(RELAY_DEFAULTS.maxPerBox))),
  maxBoxBytes = Number(env("HUMID_RELAY_MAX_BOX_BYTES", String(RELAY_DEFAULTS.maxBoxBytes))),
  maxTotalBytes = Number(env("HUMID_RELAY_MAX_TOTAL_BYTES", String(RELAY_DEFAULTS.maxTotalBytes))),
  /** Bytes one network may deposit per day (PC-27: one address must not fill the relay for everyone). */
  // well under maxTotalBytes / 8, counted per IPv4 address or IPv6 /48 (security review M1)
  maxNetBytesPerDay = Number(env("HUMID_RELAY_MAX_NET_BYTES_DAY", String(48 * 1024 * 1024))),
  /** Bytes one IPv4 /24 or IPv6 /32 may deposit per day, all its addresses together (MSG-05). */
  maxBlockBytesPerDay = Number(env("HUMID_RELAY_MAX_BLOCK_BYTES_DAY", String(128 * 1024 * 1024))),
  /** Past this fraction of maxTotalBytes, only blocks under a fair share of today's deposits may add more. */
  fairAboveFraction = Number(env("HUMID_RELAY_FAIR_ABOVE", "0.75")),
  depositsPerMinute = Number(env("HUMID_RELAY_DEPOSITS_PER_MIN", String(RELAY_DEFAULTS.depositsPerMinute))),
  fetchesPerMinute = Number(env("HUMID_RELAY_FETCHES_PER_MIN", String(RELAY_DEFAULTS.fetchesPerMinute))),
  maxRateKeys = RELAY_DEFAULTS.maxRateKeys,
  now = () => Date.now(),
} = {}) {
  const db = openDb(dataDir, "relay.db", [
    `CREATE TABLE objects (id INTEGER PRIMARY KEY, box TEXT NOT NULL, at INTEGER NOT NULL, tag TEXT, size INTEGER NOT NULL, wire BLOB NOT NULL)`,
    `CREATE INDEX objects_box ON objects (box)`,
    `CREATE INDEX objects_at ON objects (at)`,
  ]);
  const q = {
    expire: db.prepare("DELETE FROM objects WHERE at < ?"),
    total: db.prepare("SELECT COALESCE(SUM(size), 0) AS n FROM objects"),
    boxUse: db.prepare("SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS n FROM objects WHERE box = ?"),
    insert: db.prepare("INSERT INTO objects (box, at, tag, size, wire) VALUES (?, ?, ?, ?, ?)"),
    list: db.prepare("SELECT id, size, wire FROM objects WHERE box = ? ORDER BY id"),
    del: db.prepare("DELETE FROM objects WHERE id = ?"),
    byTag: db.prepare("SELECT id, size FROM objects WHERE box = ? AND tag = ?"),
  };
  let total = Number(q.total.get().n);
  let lastExpire = 0;
  function expire() {
    const t = now();
    if (t - lastExpire < MINUTE) return;
    lastExpire = t;
    if (q.expire.run(t - ttlMs).changes) total = Number(q.total.get().n);
  }

  /**
   * A count-min sketch per fixed window (security review M1, MSG-05): fixed memory, so it never
   * fills up, never forgets a heavy sender within its window, and never refuses a NEW key for lack
   * of room (the old per-minute table failed closed once 100,000 keys were live, and one IPv6 /48
   * holds 65,536 /64s). It can only over-count: a rare false "slow down" for a key that shares
   * every cell with busy ones.
   *   take(key, cost) → true and counted, or false (over the limit, nothing counted)
   *   peek(key)       → the current estimate
   */
  function sketch(limit, windowMs, rows = 4, width = 1 << 15) {
    let win = -1, t = null;
    const idx = (key) => { const h = createHash("sha256").update(key).digest(); return Array.from({ length: rows }, (_, r) => h.readUInt32BE(r * 4) % width); };
    const roll = () => {
      const w = Math.floor(now() / windowMs);
      if (w !== win || !t) { win = w; t = Array.from({ length: rows }, () => new Float64Array(width)); }
    };
    const est = (ix) => Math.min(...ix.map((i, r) => t[r][i]));
    return {
      take(key, cost = 1, max = limit) {
        roll();
        const ix = idx(key);
        if (est(ix) + cost > max) return false;
        ix.forEach((i, r) => { t[r][i] += cost; });
        return true;
      },
      peek(key) { roll(); return est(idx(key)); },
    };
  }
  // maxRateKeys is kept as an option for compatibility; the sketches don't need it.
  void maxRateKeys;
  const deposits = sketch(depositsPerMinute, MINUTE);
  const fetches = sketch(fetchesPerMinute, MINUTE);
  const canDeposit = (key) => deposits.take(key);
  const canFetch = (key) => fetches.take(key);

  /*
   * Bytes per network per day, at three sizes of "network" (MSG-05): the rate key itself (an IPv4
   * address or IPv6 /64), its site (IPv6 /48), and its provider-sized block (IPv4 /24, IPv6 /32),
   * each with its own daily quota. A few dozen addresses or /48s spread over one /24 or /32 now
   * count together. And when the relay is nearly full, it stops taking from whoever already holds
   * more than a fair share of today's deposits, instead of refusing everyone.
   */
  const netBytes = sketch(maxNetBytesPerDay, DAY);
  const siteBytes = sketch(maxNetBytesPerDay, DAY);
  const blockBytes = sketch(maxBlockBytesPerDay, DAY);
  const siteKey = (k) => (k.startsWith("v6:") ? `${k.split(":").slice(0, 4).join(":")}::/48` : k);
  const blockKey = (k) => {
    if (k.startsWith("v4:")) return `${k.split(".").slice(0, 3).join(".")}.0/24`;
    if (k.startsWith("v6:")) return `${k.split(":").slice(0, 3).join(":")}::/32`;
    return k;
  };
  // how many distinct blocks deposited today, for the fair share (a small daily set, bounded)
  let activeDay = -1;
  const active = new Set();
  const MAX_ACTIVE = 200_000;
  function noteActive(block) {
    const d = Math.floor(now() / DAY);
    if (d !== activeDay) { activeDay = d; active.clear(); }
    if (active.size < MAX_ACTIVE) active.add(block);
  }
  /** Near full (over fairAboveFraction of the total), a block may hold at most total / active blocks of today's deposits. */
  function overFairShare(block, bytes) {
    if (total + bytes <= maxTotalBytes * fairAboveFraction) return false;
    const share = maxTotalBytes / Math.max(1, active.size + (active.has(block) ? 0 : 1));
    return blockBytes.peek(block) + bytes > share;
  }

  const gatewayOnly = (claims) => { if (claims?.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const rk = (claims) => (typeof claims.rk === "string" && claims.rk.length <= 64 ? claims.rk : "unknown");
  const box = (s) => { if (!isBox(s)) throw new HttpError(400, "bad_box", "Bad mailbox id"); return s; };
  const minute = () => Math.floor(now() / MINUTE) * MINUTE; // arrival to the minute: no finer timing kept

  const routes = [
    // Deposit one object. Body: the wire object. Headers: x-humid-box, x-humid-tag (optional).
    ["POST", "/internal/put", ({ body, claims, headers }) => {
      gatewayOnly(claims);
      const b = box(String(headers["x-humid-box"] || ""));
      const tag = headers["x-humid-tag"] ? String(headers["x-humid-tag"]) : null;
      if (tag !== null && !TAG_RE.test(tag)) throw new HttpError(400, "bad_tag", "Bad unsend tag");
      if (!(body instanceof Uint8Array) || body.length > MAX_WIRE || !isWireSize(body.length)) throw new HttpError(400, "bad_size", "Not a wire object");
      const key = rk(claims);
      if (!canDeposit(key)) throw new HttpError(429, "rate_limited", "Too many deposits");
      expire();
      const use = q.boxUse.get(b);
      if (Number(use.c) >= maxPerBox || Number(use.n) + body.length > maxBoxBytes) throw new HttpError(507, "box_full", "Mailbox is full");
      if (total + body.length > maxTotalBytes) throw new HttpError(507, "relay_full", "Relay is full");
      const site = siteKey(key), block = blockKey(key);
      // all three quotas checked before any is counted, so a refusal costs the sender nothing
      if (netBytes.peek(key) + body.length > maxNetBytesPerDay || siteBytes.peek(site) + body.length > maxNetBytesPerDay
        || blockBytes.peek(block) + body.length > maxBlockBytesPerDay) throw new HttpError(429, "quota", "This network has sent too much today");
      if (overFairShare(block, body.length)) throw new HttpError(429, "quota", "The relay is nearly full; this network has sent its share today");
      netBytes.take(key, body.length); siteBytes.take(site, body.length); blockBytes.take(block, body.length);
      noteActive(block);
      q.insert.run(b, minute(), tag, body.length, Buffer.from(body));
      total += body.length;
      return json(201, { ok: true });
    }, { bodyLimit: MAX_WIRE + 1024 }],

    // Fetch and remove everything in up to 64 mailboxes. keep: read without removing (invite
    // bundles, which the invitee may fetch again). Unknown and empty mailboxes look the same.
    ["POST", "/internal/take", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const boxes = Array.isArray(r.boxes) ? r.boxes : [];
      if (!boxes.length || boxes.length > MAX_TAKE_BOXES) throw new HttpError(400, "bad_request", `Ask for 1 to ${MAX_TAKE_BOXES} mailboxes`);
      for (const b of boxes) box(b);
      if (!canFetch(rk(claims))) throw new HttpError(429, "rate_limited", "Too many requests");
      expire();
      const got = {};
      let bytes = 0, more = false;
      db.exec("BEGIN");
      try {
        for (const b of [...new Set(boxes)]) {
          const list = [];
          for (const row of q.list.all(b)) {
            if (bytes + Number(row.size) > MAX_TAKE_BYTES && bytes > 0) { more = true; break; }
            list.push(b64u(row.wire));
            bytes += Number(row.size);
            if (!r.keep) { q.del.run(row.id); total -= Number(row.size); }
          }
          if (list.length) got[b] = list;
        }
        db.exec("COMMIT");
      } catch (e) { db.exec("ROLLBACK"); total = Number(q.total.get().n); throw e; }
      return json(200, { got, more });
    }, { bodyLimit: 8 * 1024 }],

    // Unsend: remove the object whose tag is SHA3(token), if it's still there.
    // removed: false for "already fetched", "expired" and "no such object" alike.
    ["POST", "/internal/retract", ({ body, claims }) => {
      gatewayOnly(claims);
      const r = parseJson(body) || {};
      const b = box(String(r.box || ""));
      let token;
      try { token = unb64u(String(r.token || "")); } catch { token = null; }
      if (!token || token.length !== RETRACT_BYTES) throw new HttpError(400, "bad_tag", "Bad unsend token");
      if (!canDeposit(rk(claims))) throw new HttpError(429, "rate_limited", "Too many requests");
      expire();
      const row = q.byTag.get(b, retractTag(token));
      if (!row) return json(200, { removed: false });
      q.del.run(row.id);
      total -= Number(row.size);
      return json(200, { removed: true });
    }, { bodyLimit: 4 * 1024 }],
  ];

  const svc = createService({ tls, name: "relay", port, routes, bodyLimit: 8 * 1024, verify: (t) => verifyAssertion(internalPk, t, "relay") });
  return { ...svc, close: () => db.close(), get totalBytes() { return total; } };
}

if (isMain(import.meta.url)) createRelay().start();
