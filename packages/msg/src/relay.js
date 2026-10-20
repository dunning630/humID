// The relay contract, and an in-memory reference used by tests and the
// development server. The future `services/relay` implements the same rules.
//
// The relay is deliberately dumb:
//   - No accounts, no sign-in, no sender. A deposit is (box id, wire object).
//     Nobody — not the relay, not someone who breaches it — learns who wrote to whom.
//   - It stores only wire objects of the fixed sizes (wire.js) for at most `ttlMs`.
//   - It runs no cryptography at all, so it has no keys to steal and nothing to
//     time (audit: timing leaks; SEC-S-01: nothing it does is worth forging).
//   - Fetching a box that is empty and a box that never existed give exactly the
//     same answer (audit SEC-S-13: never reveal whether something exists).
//   - Caps on every dimension (audit SEC-S-02, -03, -08): objects per box, bytes
//     per box, total bytes, deposits per network per minute, with IPv6 keyed by
//     its /64 so cycling addresses inside one allocation doesn't escape the limit.

import { MsgError } from "./util.js";
import { isBox, isWireSize, MAX_WIRE } from "./wire.js";

export const RELAY_DEFAULTS = Object.freeze({
  ttlMs: 14 * 24 * 3600_000,
  maxPerBox: 500,
  maxBoxBytes: 64 * 1024 * 1024,
  maxTotalBytes: 2 * 1024 * 1024 * 1024,
  depositsPerMinute: 120,
  fetchesPerMinute: 600,
});

/**
 * The key a rate limit counts against. IPv4: the address. IPv6: its /64
 * (one home or phone gets a whole /64, so per-address limits are trivially
 * escaped). IPv4-mapped IPv6 counts as the IPv4 address.
 */
export function rateKey(ip) {
  const s = String(ip || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return `v4:${mapped[1]}`;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return `v4:${s}`;
  if (!s.includes(":")) return `other:${s}`;
  const [head, tail = ""] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  if (h.length + t.length > 8) return `other:${s}`;
  const full = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t].map((x) => (parseInt(x || "0", 16) || 0).toString(16));
  return `v6:${full.slice(0, 4).join(":")}::/64`;
}

/** Fixed-window counter per key. */
function limiter(perMinute, now) {
  const windows = new Map();
  return (key) => {
    const t = now(), w = Math.floor(t / 60_000);
    const e = windows.get(key);
    if (!e || e.w !== w) { windows.set(key, { w, n: 1 }); if (windows.size > 100_000) windows.clear(); return true; }
    e.n += 1;
    return e.n <= perMinute;
  };
}

export function memoryRelay(opts = {}) {
  const o = { ...RELAY_DEFAULTS, ...opts };
  const now = opts.now || (() => Date.now());
  const boxes = new Map(); // box -> [{ at, wire }]
  let total = 0;
  const canDeposit = limiter(o.depositsPerMinute, now);
  const canFetch = limiter(o.fetchesPerMinute, now);
  const observed = []; // everything the relay could log: for tests that check what it learns

  function expire() {
    const cutoff = now() - o.ttlMs;
    for (const [box, list] of boxes) {
      while (list.length && list[0].at < cutoff) { total -= list.shift().wire.length; }
      if (!list.length) boxes.delete(box);
    }
  }

  return {
    observed,
    get totalBytes() { return total; },

    /** Deposit. Throws MsgError: bad_box, bad_size, rate_limited, box_full, relay_full. */
    put(box, wire, { ip = "0.0.0.0" } = {}) {
      if (!isBox(box)) throw new MsgError("bad_box", "Bad mailbox id");
      if (!(wire instanceof Uint8Array) || wire.length > MAX_WIRE || !isWireSize(wire.length)) throw new MsgError("bad_size", "Not a wire object");
      if (!canDeposit(rateKey(ip))) throw new MsgError("rate_limited", "Too many deposits");
      expire();
      const list = boxes.get(box) || [];
      const boxBytes = list.reduce((n, e) => n + e.wire.length, 0);
      if (list.length >= o.maxPerBox || boxBytes + wire.length > o.maxBoxBytes) throw new MsgError("box_full", "Mailbox is full");
      if (total + wire.length > o.maxTotalBytes) throw new MsgError("relay_full", "Relay is full");
      list.push({ at: now(), wire: wire.slice() });
      boxes.set(box, list);
      total += wire.length;
      observed.push({ op: "put", box, size: wire.length, at: now() });
    },

    /**
     * Fetch and delete everything in a box. An unknown box and an empty box
     * both return []. `keep: true` reads without deleting (invite bundles,
     * which several invitees may fetch).
     */
    take(box, { ip = "0.0.0.0", keep = false } = {}) {
      if (!isBox(box)) throw new MsgError("bad_box", "Bad mailbox id");
      if (!canFetch(rateKey(ip))) throw new MsgError("rate_limited", "Too many requests");
      expire();
      const list = boxes.get(box) || [];
      if (!keep && list.length) { boxes.delete(box); total -= list.reduce((n, e) => n + e.wire.length, 0); }
      observed.push({ op: keep ? "peek" : "take", box, at: now() });
      return list.map((e) => e.wire);
    },
  };
}
