// keyshare — the second key of every split document (docs/SECURITY.md#compromised-phone).
//
// A phone that seals a document encrypts it under a fresh 256-bit document key, seals
// the result to the account's keys, and sends the document key here. From then on the
// phone forgets it. Opening the document needs BOTH the account keys and this key, and
// this service releases it only:
//   - to the document's own account,
//   - inside a live, chip-signed step-up for that exact document (the same check that
//     lets the vault return the envelope: no extra prompt), at most 60 seconds old,
//   - within a per-account hourly cap, so a hijacked phone can't drain the vault.
//
// Spyware that copies the account keys out of a phone's memory therefore opens nothing
// by itself. This service never sees an envelope, a name or an account key, and the
// vault never sees a document key: a breach of either one alone opens nothing.
//
// Shares are stored encrypted (AES-256-GCM, bound to account and document) under
// share-key.bin on this service's own volume. Keep that volume on separate storage
// from the vault's, ideally a separate host; the key file belongs in an HSM or KMS
// before real data (docs/SECURITY.md#before-real-data).
//
// Check-in (docs/CHECKIN.md). A holder can arm a timer before a high-stakes situation.
// While it's armed, every one of the account's document keys is kept under a fuse key
// that exists only in this process's memory: never on disk, never in a backup. The
// holder checks in (a live step-up) before each deadline. Miss one and the account is
// locked: no key is released. Miss the grace window too, or signal duress, and the
// fuse key is destroyed, which makes every copy of those keys (live, or in a backup
// made since arming) unreadable, so the documents never open again. Documents the
// holder marked for the decoy view are kept out of the fuse, so a forced unlock still
// looks normal. This service runs the countdown itself, on the monotonic clock, so
// neither stopping the gateway nor changing the wall clock can stretch it; and since
// the fuse keys live in memory only, a restart erases every armed vault (fail-deadly).

import { mkdirSync } from "node:fs";
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { createService, serviceTlsFromEnv, sealerFromEnv, secretFile, openDb, env, json, parseJson, verifyAssertion, unb64u, b64u, HttpError, isMain, logger } from "@humid/svc";
import { STEP_UP_MAX_AGE_MS } from "@humid/htp";

const OBJ_RE = /^[0-9a-f-]{36}$/;
const OWNER_RE = /^hid_[0-9a-f]{40}$/;
const SHARE_BYTES = 32;
const HOUR = 3_600_000;
const MINUTE = 60_000;

/** What Check-in can be set to. The gateway publishes the same lists in its policy hint. */
export const CHECKIN_WINDOWS_MS = [1, 2, 4, 8, 24].map((h) => h * HOUR);
export const CHECKIN_GRACE_MS = [0, 15, 30, 60].map((m) => m * MINUTE);

export function createKeyshare({
  /** Mutual TLS when the gateway calls from another machine (server 3.0): HUMID_TLS_* files. */
  tls = serviceTlsFromEnv(),
  /** Secrets sealed at rest (packages/svc/src/seal.js). */
  secretSeal = sealerFromEnv(),
  port = Number(env("PORT", "8086")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  releasesPerHour = Number(env("HUMID_SHARE_RELEASES_PER_HOUR", "120")),
  rollbackWindowMs = 120_000,
  now = () => Date.now(),
  mono = () => performance.now(), // Check-in deadlines: never goes back, ignores wall-clock changes
  tickMs = 1000,
} = {}) {
  const log = logger("keyshare");
  mkdirSync(dataDir, { recursive: true });
  // Sealed at rest when the server has a seal key (a plain one is sealed in place: the same master key).
  const shareKey = secretFile(`${dataDir}/share-key.bin`, { seal: secretSeal, name: "keyshare/share-key", make: () => randomBytes(32), log });
  const master = Buffer.from(hkdfSync("sha3-256", shareKey, Buffer.alloc(0), "HUMID-KEYSHARE-v1 at-rest", 32));

  const db = openDb(dataDir, "keyshare.db", [
    `CREATE TABLE shares (object TEXT PRIMARY KEY, owner TEXT NOT NULL, iv BLOB NOT NULL, ct BLOB NOT NULL,
                          created_at INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0, last_released_at INTEGER)`,
    `CREATE INDEX shares_owner ON shares(owner)`,
    `CREATE TABLE releases (owner TEXT NOT NULL, at INTEGER NOT NULL)`,
    `CREATE INDEX releases_owner ON releases(owner, at)`,
    // keyshare 1.1: Check-in. fused = the share is sealed under the account's fuse key.
    `ALTER TABLE shares ADD COLUMN fused INTEGER NOT NULL DEFAULT 0`,
    `CREATE TABLE checkin (owner TEXT PRIMARY KEY, state TEXT NOT NULL, window_ms INTEGER NOT NULL, max_window_ms INTEGER NOT NULL,
                           grace_ms INTEGER NOT NULL, armed_at INTEGER NOT NULL, deadline INTEGER NOT NULL,
                           erased_at INTEGER, cleaned INTEGER NOT NULL DEFAULT 1)`,
    // how many document keys an erase destroyed: the count the ledger records, however many sweeps it takes
    `ALTER TABLE checkin ADD COLUMN erased_count INTEGER`,
  ]);
  // state is 'armed' or 'erased' on disk; "locked" is only ever worked out from the clock (status()).
  // A deleted share's bytes are overwritten in the database file, not left in free pages.
  db.exec("PRAGMA secure_delete = ON");

  /**
   * Fuse keys, by account: { raw, key, deadline, erasesAt } (deadlines on the monotonic clock).
   * In memory only. This Map is the whole difference between a document that opens and one
   * that never will.
   */
  const fuses = new Map();
  const fuseKey = (owner, raw) => Buffer.from(hkdfSync("sha3-256", Buffer.concat([master, raw]), Buffer.from(owner), "HUMID-KEYSHARE-v1 fuse", 32));

  const aad = (owner, object, fused) => Buffer.from(`HUMID-KEYSHARE-v1${fused ? " fuse" : ""}\0${owner}\0${object}`);
  const keyFor = (owner, fused) => (fused ? fuses.get(owner)?.key || null : master);
  const seal = (owner, object, share, fused = false) => {
    const k = keyFor(owner, fused);
    if (!k) throw new HttpError(410, "vault_erased", "Your vault was erased by Check-in.");
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", k, iv).setAAD(aad(owner, object, fused));
    return { iv, ct: Buffer.concat([c.update(share), c.final(), c.getAuthTag()]) };
  };
  const open = (row) => {
    const k = keyFor(row.owner, !!row.fused);
    if (!k) throw new HttpError(410, "vault_erased", "Your vault was erased by Check-in.");
    const d = createDecipheriv("aes-256-gcm", k, row.iv).setAAD(aad(row.owner, row.object, !!row.fused));
    d.setAuthTag(Buffer.from(row.ct).subarray(-16));
    return Buffer.concat([d.update(Buffer.from(row.ct).subarray(0, -16)), d.final()]);
  };

  const gatewayOnly = (claims) => { if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only"); };
  const owner = (claims) => { if (!claims.sub) throw new HttpError(401, "unauthenticated", "Sign in first"); return claims.sub; };
  const stepUp = (claims) => {
    const s = claims.stepUp;
    if (!s || now() - s.at > STEP_UP_MAX_AGE_MS) throw new HttpError(403, "step_up_required", "This needs a fresh biometric check on your device.");
  };
  const object = (id) => { if (!OBJ_RE.test(String(id))) throw new HttpError(400, "bad_object", "Unknown document id"); return String(id); };
  const mine = (o, id) => {
    const r = db.prepare("SELECT * FROM shares WHERE object = ?").get(id);
    if (!r || r.owner !== o) throw new HttpError(404, "no_share", "This document has no split key here.");
    return r;
  };

  /* ---------------- Check-in ---------------- */

  const tx = (fn) => {
    db.exec("BEGIN IMMEDIATE");
    try { const out = fn(); db.exec("COMMIT"); return out; }
    catch (e) { db.exec("ROLLBACK"); throw e; }
  };
  // The write-ahead log can still hold a page as it was before a change; fold it in.
  const flush = () => { try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch {} };

  /**
   * Re-seal each of an account's shares where it belongs: under the fuse key when
   * fused(object) says so (armed, not a decoy), otherwise under the service key.
   */
  function reseal(o, fused) {
    const rows = db.prepare("SELECT * FROM shares WHERE owner = ?").all(o);
    const upd = db.prepare("UPDATE shares SET iv = ?, ct = ?, fused = ? WHERE object = ?");
    for (const r of rows) {
      const want = fused(r.object);
      if (!!r.fused === want) continue;
      const share = open(r);
      try { const { iv, ct } = seal(o, r.object, share, want); upd.run(iv, ct, want ? 1 : 0, r.object); }
      finally { share.fill(0); }
    }
  }

  /**
   * Erase: destroy the fuse key (that is the erase; everything after it is tidying up), then
   * drop the account's fused shares. Kept (decoy) documents and anything sealed since are untouched.
   */
  function erase(o) {
    const f = fuses.get(o);
    if (f) { f.raw.fill(0); f.key.fill(0); fuses.delete(o); }
    tx(() => {
      const gone = db.prepare("DELETE FROM shares WHERE owner = ? AND fused = 1").run(o).changes;
      db.prepare("UPDATE checkin SET state = 'erased', erased_at = ?, cleaned = 0, erased_count = ? WHERE owner = ?").run(now(), gone, o);
    });
    flush();
    log.warn("check-in: an armed vault's keys were destroyed"); // never the account id
  }

  /** Where an account stands. Settles a deadline that has passed. */
  function status(o) {
    const row = db.prepare("SELECT * FROM checkin WHERE owner = ?").get(o);
    if (!row) return { state: "off" };
    if (row.state === "erased") return { state: "erased", erasedAt: row.erased_at };
    const f = fuses.get(o);
    const m = mono();
    if (!f || m >= f.erasesAt) { erase(o); return status(o); }
    const t = now();
    return {
      state: m < f.deadline ? "armed" : "locked",
      deadline: Math.round(t + (f.deadline - m)),
      erasesAt: Math.round(t + (f.erasesAt - m)),
      windowMs: row.window_ms, maxWindowMs: row.max_window_ms, graceMs: row.grace_ms, armedAt: row.armed_at,
    };
  }

  const pick = (v, allowed, what) => {
    const n = Number(v);
    if (!allowed.includes(n)) throw new HttpError(400, "bad_checkin", `Check-in can't use that ${what}.`);
    return n;
  };
  const LOCKED = () => new HttpError(423, "checkin_missed", "You missed a check-in. Check in to use your vault again.");
  const ERASED = () => new HttpError(410, "vault_erased", "Your vault was erased by Check-in.");

  /** Every armed vault was erased if this process restarted: its fuse keys died with the old one. */
  {
    const orphans = db.prepare("SELECT owner FROM checkin WHERE state != 'erased'").all();
    for (const { owner: o } of orphans) erase(o);
    db.prepare("DELETE FROM shares WHERE fused = 1").run(); // a fused share with no fuse key: useless, gone
    flush();
    if (orphans.length) log.warn("keyshare restarted while Check-in was armed: those vaults were erased", { count: orphans.length });
  }

  const tick = () => {
    const m = mono();
    for (const [o, f] of [...fuses]) if (m >= f.erasesAt) {
      try { erase(o); } catch (e) { log.error("check-in erase failed", { err: e.message }); }
    }
  };
  const timer = tickMs > 0 ? setInterval(tick, tickMs) : null;
  timer?.unref?.();

  const routes = [
    // Store a document's key, once, right after the vault accepted its envelope.
    ["PUT", "/internal/shares/:id", ({ claims, params, body }) => {
      gatewayOnly(claims);
      const o = owner(claims), id = object(params.id);
      let share;
      try { share = unb64u(String(parseJson(body)?.share || "")); } catch { share = null; }
      if (!share || share.length !== SHARE_BYTES) throw new HttpError(400, "bad_share", "A document key is 32 bytes.");
      const st = status(o);
      if (st.state === "locked") throw LOCKED();
      const fused = st.state === "armed"; // sealed while armed: in the fuse from the start
      const { iv, ct } = seal(o, id, share, fused);
      const r = db.prepare("INSERT OR IGNORE INTO shares (object, owner, iv, ct, created_at, fused) VALUES (?, ?, ?, ?, ?, ?)").run(id, o, iv, ct, now(), fused ? 1 : 0);
      if (r.changes !== 1) throw new HttpError(409, "share_exists", "This document already has a key.");
      return json(201, { stored: true });
    }],

    // The gateway couldn't finish the upload: forget a key stored moments ago (never an older one).
    ["DELETE", "/internal/shares/:id", ({ claims, params }) => {
      gatewayOnly(claims);
      const o = owner(claims), id = object(params.id);
      const r = db.prepare("DELETE FROM shares WHERE object = ? AND owner = ? AND created_at > ?").run(id, o, now() - rollbackWindowMs);
      return json(200, { removed: r.changes === 1 });
    }],

    // Release one document's key: its owner, a fresh live step-up, under the hourly cap.
    ["GET", "/shares/:id", ({ claims, params }) => {
      const o = owner(claims);
      stepUp(claims);
      const st = status(o);
      if (st.state === "locked") throw LOCKED();
      const r = db.prepare("SELECT * FROM shares WHERE object = ?").get(object(params.id));
      if (!r) {
        // its key went with a Check-in erase, and the vault hasn't dropped the envelope yet
        if (st.state === "erased" && db.prepare("SELECT cleaned FROM checkin WHERE owner = ?").get(o)?.cleaned === 0) throw ERASED();
        return json(404, { error: "no_share", message: "This document has no split key." }); // sealed before split keys
      }
      if (r.owner !== o) throw new HttpError(404, "no_share", "This document has no split key here.");
      const t = now();
      db.prepare("DELETE FROM releases WHERE at < ?").run(t - HOUR);
      const n = db.prepare("SELECT COUNT(*) AS n FROM releases WHERE owner = ? AND at > ?").get(o, t - HOUR).n;
      if (n >= releasesPerHour) throw new HttpError(429, "share_rate_limited", "You've opened a lot of documents in the last hour. Wait a while and try again.");
      db.prepare("INSERT INTO releases (owner, at) VALUES (?, ?)").run(o, t);
      db.prepare("UPDATE shares SET released = released + 1, last_released_at = ? WHERE object = ?").run(t, r.object);
      return json(200, { share: b64u(open(r)) });
    }],

    // The document was deleted (the gateway calls this after the vault, under the same step-up).
    ["DELETE", "/shares/:id", ({ claims, params }) => {
      const o = owner(claims);
      stepUp(claims);
      mine(o, object(params.id));
      db.prepare("DELETE FROM shares WHERE object = ?").run(params.id);
      return json(200, { deleted: true });
    }],

    // Account closed: every key goes, and Check-in with it.
    ["DELETE", "/shares", ({ claims }) => {
      const o = owner(claims);
      stepUp(claims);
      const f = fuses.get(o);
      if (f) { f.raw.fill(0); f.key.fill(0); fuses.delete(o); }
      const r = db.prepare("DELETE FROM shares WHERE owner = ?").run(o);
      db.prepare("DELETE FROM releases WHERE owner = ?").run(o);
      db.prepare("DELETE FROM checkin WHERE owner = ?").run(o);
      flush();
      return json(200, { deleted: r.changes });
    }],

    /* ---------- Check-in (gateway only) ---------- */

    ["GET", "/internal/checkin", ({ claims }) => {
      gatewayOnly(claims);
      return json(200, status(owner(claims)));
    }],

    // Arm (or change settings and start a new window). objects: every document the vault holds
    // for this account: each must have its key here, or erasing it couldn't be final.
    // keep: documents marked for the decoy view, left out of the fuse.
    ["POST", "/internal/checkin/arm", ({ claims, body }) => {
      gatewayOnly(claims);
      const o = owner(claims);
      stepUp(claims);
      const r = parseJson(body) || {};
      const windowMs = pick(r.windowMs, CHECKIN_WINDOWS_MS, "window");
      const maxWindowMs = pick(r.maxWindowMs ?? r.windowMs, CHECKIN_WINDOWS_MS, "longest window");
      const graceMs = pick(r.graceMs, CHECKIN_GRACE_MS, "grace period");
      if (maxWindowMs < windowMs) throw new HttpError(400, "bad_checkin", "The longest window can't be shorter than the usual one.");
      if (!Array.isArray(r.objects) || r.objects.length > 100_000) throw new HttpError(400, "bad_checkin", "Send the documents in the vault.");
      const objects = r.objects.map(object);
      const listed = new Set(objects);
      const keep = new Set((Array.isArray(r.keep) ? r.keep : []).map(object).filter((id) => listed.has(id)));
      const have = new Set(db.prepare("SELECT object FROM shares WHERE owner = ?").all(o).map((x) => x.object));
      const unsplit = objects.filter((id) => !have.has(id));
      if (unsplit.length) {
        return json(409, { error: "unsplit_items", message: "Some documents were sealed before split keys, so Check-in couldn't erase them for good. Re-seal or delete them first.", items: unsplit });
      }
      const before = status(o);
      const fusedFor = (id) => !keep.has(id); // a decoy document stays out of the fuse
      if (before.state === "armed" || before.state === "locked") {
        // Already armed: new settings, the decoy marks as they are now, and a new window from
        // now (this is a live check, so it counts as a check-in).
        tx(() => {
          reseal(o, fusedFor);
          db.prepare("UPDATE checkin SET window_ms = ?, max_window_ms = ?, grace_ms = ?, deadline = ? WHERE owner = ?").run(windowMs, maxWindowMs, graceMs, now() + windowMs, o);
        });
        const f = fuses.get(o);
        f.deadline = mono() + windowMs; f.erasesAt = f.deadline + graceMs;
        flush();
        return json(200, status(o));
      }
      const raw = randomBytes(32);
      const f = { raw, key: fuseKey(o, raw), deadline: mono() + windowMs, erasesAt: 0 };
      f.erasesAt = f.deadline + graceMs;
      fuses.set(o, f);
      try {
        tx(() => {
          reseal(o, fusedFor);
          db.prepare("INSERT OR REPLACE INTO checkin (owner, state, window_ms, max_window_ms, grace_ms, armed_at, deadline, erased_at, cleaned) VALUES (?, 'armed', ?, ?, ?, ?, ?, NULL, 1)")
            .run(o, windowMs, maxWindowMs, graceMs, now(), now() + windowMs);
        });
      } catch (e) { fuses.delete(o); raw.fill(0); f.key.fill(0); throw e; }
      flush(); // the shares as they were before arming don't linger in the log
      return json(200, status(o));
    }, { bodyLimit: 4 << 20 }],

    // A check-in: the next deadline, from now. nextWindowMs (optional) up to the armed maximum,
    // e.g. a longer one for the night. Allowed during the grace window.
    ["POST", "/internal/checkin/check", ({ claims, body }) => {
      gatewayOnly(claims);
      const o = owner(claims);
      stepUp(claims);
      const st = status(o);
      if (st.state === "erased") throw ERASED();
      if (st.state === "off") throw new HttpError(409, "checkin_off", "Check-in isn't on.");
      const r = parseJson(body) || {};
      const next = r.nextWindowMs == null ? st.windowMs : pick(r.nextWindowMs, CHECKIN_WINDOWS_MS, "window");
      if (next > st.maxWindowMs) throw new HttpError(400, "bad_checkin", "That's longer than the longest window you allowed.");
      const f = fuses.get(o);
      f.deadline = mono() + next; f.erasesAt = f.deadline + st.graceMs;
      db.prepare("UPDATE checkin SET deadline = ? WHERE owner = ?").run(now() + next, o);
      return json(200, status(o));
    }],

    // Turn it off: every key goes back under the service key, and the fuse key is dropped.
    ["POST", "/internal/checkin/disarm", ({ claims }) => {
      gatewayOnly(claims);
      const o = owner(claims);
      stepUp(claims);
      const st = status(o);
      if (st.state === "erased") throw ERASED();
      if (st.state === "off") return json(200, { state: "off" });
      tx(() => {
        reseal(o, () => false);
        db.prepare("DELETE FROM checkin WHERE owner = ?").run(o);
      });
      const f = fuses.get(o);
      if (f) { f.raw.fill(0); f.key.fill(0); fuses.delete(o); }
      flush();
      return json(200, { state: "off" });
    }],

    // Erase now: the gateway saw a duress signal from this account. Nothing happens if it isn't armed.
    ["POST", "/internal/checkin/erase", ({ claims }) => {
      gatewayOnly(claims);
      const o = owner(claims);
      const st = status(o);
      if (st.state !== "armed" && st.state !== "locked") return json(200, { erased: false });
      erase(o);
      return json(200, { erased: true });
    }],

    // Accounts whose keys were destroyed and whose envelopes the vault still holds. keep: the
    // documents whose keys are still here (decoys, and anything sealed since), which stay.
    ["GET", "/internal/checkin/erased", ({ claims }) => {
      gatewayOnly(claims);
      const rows = db.prepare("SELECT owner, erased_at, erased_count FROM checkin WHERE state = 'erased' AND cleaned = 0 LIMIT 50").all();
      const keepOf = db.prepare("SELECT object FROM shares WHERE owner = ?");
      return json(200, { erased: rows.map((r) => ({ owner: r.owner, erasedAt: r.erased_at, count: r.erased_count ?? null, keep: keepOf.all(r.owner).map((x) => x.object) })) });
    }],
    ["POST", "/internal/checkin/erased/:owner/cleaned", ({ claims, params }) => {
      gatewayOnly(claims);
      if (!OWNER_RE.test(params.owner)) throw new HttpError(400, "bad_subject", "Unknown subject");
      db.prepare("UPDATE checkin SET cleaned = 1 WHERE owner = ? AND state = 'erased'").run(params.owner);
      return json(200, { cleaned: true });
    }],
  ];

  const svc = createService({ tls, name: "keyshare", port, routes, bodyLimit: 4 * 1024, verify: (t) => verifyAssertion(internalPk, t, "keyshare") });
  return {
    ...svc,
    tick,
    /** How many accounts are armed right now (the Windows server shows it before a restart). */
    armedCount: () => fuses.size,
    close: () => { if (timer) clearInterval(timer); for (const f of fuses.values()) { f.raw.fill(0); f.key.fill(0); } fuses.clear(); db.close(); },
  };
}

if (isMain(import.meta.url)) createKeyshare().start();
