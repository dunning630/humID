// ledger — tamper-evident access history, and the public log that holds it to account.
//
// Every security-relevant event (identity created, session opened, document
// sealed / opened / deleted, access denied, a device added and on what
// evidence, a recovery, a duress signal) is appended to the holder's own hash
// chain:  hash_n = SHA3-256(owner, n, hash_{n-1}, entry_n).
// Reads return the chain plus the head signed with the ledger's ML-DSA-87
// key, so the app can prove that no entry was edited, removed or reordered.
//
// Continuity: every entry of every account is also a leaf of one public,
// append-only Merkle tree (RFC 6962 shape). Signed checkpoints of that tree
// are public; independent cosigners can check each one extends the last and
// sign it too. A phone proves its latest entry is in the tree and that the
// tree only ever grew, so the server can't rewrite anyone's history, or show
// different histories to different people, without a provable fork.

import { mkdirSync } from "node:fs";
import { createService, serviceTlsFromEnv, sealerFromEnv, secretFile, openDb, env, json, parseJson, parseObject, verifyAssertion, HttpError, b64u, unb64u, isMain, logger } from "@humid/svc";
import { ml_dsa87, sha3_256, toHex } from "@humid/htp";
import {
  GENESIS, entryHash, headMessage, leafHash, nodeHash, EMPTY_ROOT,
  checkpointMessage, cosignMessage, inclusionProof, consistencyProof,
} from "@humid/audit";

export { GENESIS, entryHash, headMessage };

const EVENT_TYPES = new Set([
  "identity.created", "identity.closed", "session.opened", "session.closed",
  "object.sealed", "object.opened", "object.updated", "object.deleted", "vault.erased",
  "access.denied",
  // devices and recovery (ledger 1.1)
  "device.added", "device.removed", "device.link_approved",
  "recovery.card_set", "recovery.card_removed", "recovery.contacts_set", "recovery.contacts_removed",
  "recovery.requested", "recovery.approved", "recovery.helped", "recovery.cancelled", "recovery.completed",
  // two-proof recovery, stations, duress (ledger 1.2)
  "recovery.anchor_set", "recovery.anchor_removed", "recovery.evidence", "recovery.station_verified", "station.verified",
  "duress.signaled", "duress.cleared", "settings.changed",
  // server administration from an administrator's phone (ledger 1.3, docs/ADMIN.md)
  "admin.approved",
  // Check-in (docs/CHECKIN.md). Never one per check-in: an hourly heartbeat in the public log
  // would tell anyone watching that an account is armed.
  "checkin.armed", "checkin.disarmed", "checkin.erased",
  // security keys as a recovery proof (ledger 1.4, docs/SECURITY-KEY.md)
  "recovery.key_added", "recovery.key_removed", "recovery.key_refused",
]);

/**
 * cosigners: "name=base64url(ML-DSA-87 public key),…" (HUMID_TLOG_COSIGNERS). Their
 * signatures over checkpoints are accepted and published.
 */
function parseCosigners(s) {
  const out = new Map();
  for (const part of String(s || "").split(",").map((x) => x.trim()).filter(Boolean)) {
    const [name, pk] = part.split("=");
    if (/^[A-Za-z0-9._-]{1,40}$/.test(name || "") && pk) out.set(name, unb64u(pk));
  }
  return out;
}

export function createLedger({
  /** Mutual TLS when the gateway calls from another machine (server 3.0): HUMID_TLS_* files. */
  tls = serviceTlsFromEnv(),
  /** Secrets sealed at rest (packages/svc/src/seal.js). */
  seal = sealerFromEnv(),
  port = Number(env("PORT", "8083")),
  dataDir = env("DATA_DIR", "/data"),
  internalPk = env("HUMID_INTERNAL_PK"),
  cosigners = parseCosigners(env("HUMID_TLOG_COSIGNERS", "")),
} = {}) {
  const log = logger("ledger");
  mkdirSync(dataDir, { recursive: true });
  // The log's signing key, sealed at rest when the server has a seal key (a plain one is sealed in place: same key).
  const keyFile = `${dataDir}/ledger-key.json`;
  const j = JSON.parse(secretFile(keyFile, { seal, name: "ledger/ledger-key", log, make: () => { const k = ml_dsa87.keygen(); return JSON.stringify({ pk: b64u(k.publicKey), sk: b64u(k.secretKey) }); } }).toString("utf8"));
  const key = { pk: unb64u(j.pk), sk: unb64u(j.sk) };
  const keyFp = toHex(sha3_256(key.pk)).slice(0, 32);
  const ledgerKey = { dsa: b64u(key.pk), fp: keyFp };
  // Release builds of the app carry this fingerprint (HUMID_LEDGER_KEY_FP), so a new install
  // never has to trust the first ledger key it's shown (PC-04, CRYPTO-01).
  log.info("ledger key", { fp: keyFp });

  const db = openDb(dataDir, "ledger.db", [
    `CREATE TABLE entries (
       owner TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, type TEXT NOT NULL,
       body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL,
       PRIMARY KEY (owner, seq))`,
    // ledger 1.2: the public transparency log. One leaf per entry, plus the hash of every
    // complete aligned subtree, so roots and proofs take O(log n) lookups.
    `ALTER TABLE entries ADD COLUMN tlog_idx INTEGER;
     CREATE UNIQUE INDEX entries_tlog ON entries(tlog_idx);
     CREATE TABLE tlog_nodes (level INTEGER NOT NULL, idx INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY (level, idx));
     CREATE TABLE tlog_checkpoints (size INTEGER PRIMARY KEY, root BLOB NOT NULL, at INTEGER NOT NULL, sig BLOB NOT NULL);
     CREATE TABLE tlog_cosigs (size INTEGER NOT NULL, name TEXT NOT NULL, sig BLOB NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (size, name))`,
  ]);
  const last = db.prepare("SELECT seq, hash FROM entries WHERE owner = ? ORDER BY seq DESC LIMIT 1");
  const insert = db.prepare("INSERT INTO entries (owner, seq, at, type, body, prev, hash, tlog_idx) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  const getNode = db.prepare("SELECT hash FROM tlog_nodes WHERE level = ? AND idx = ?");
  const putNode = db.prepare("INSERT OR REPLACE INTO tlog_nodes (level, idx, hash) VALUES (?, ?, ?)");
  const sizeQ = db.prepare("SELECT COUNT(*) AS n FROM tlog_nodes WHERE level = 0");

  /* ---------- the tree ---------- */

  const node = (level, idx) => new Uint8Array(getNode.get(level, idx).hash);
  const treeSize = () => sizeQ.get().n;

  /** Add one leaf and every complete subtree it finishes. Call inside a transaction. */
  function addLeaf(idx, leaf) {
    putNode.run(0, idx, leaf);
    let level = 0, i = idx, h = leaf;
    while (i % 2 === 1) {
      h = nodeHash(node(level, i - 1), h);
      level++; i = Math.floor(i / 2);
      putNode.run(level, i, h);
    }
  }

  /** Hash of leaves [lo, hi). Left subtrees in RFC 6962's split are always complete and aligned. */
  function th(lo, hi) {
    const n = hi - lo;
    if (n === 0) return EMPTY_ROOT;
    if ((n & (n - 1)) === 0 && lo % n === 0) return node(Math.log2(n), lo / n);
    let k = 1; while (k * 2 < n) k *= 2;
    return nodeHash(th(lo, lo + k), th(lo + k, hi));
  }
  const leafAt = (i) => node(0, i);

  // Entries written before the log existed join it once, in their original order.
  {
    const missing = db.prepare("SELECT rowid, owner, seq, hash FROM entries WHERE tlog_idx IS NULL ORDER BY rowid").all();
    if (missing.length) {
      db.exec("BEGIN IMMEDIATE");
      let idx = treeSize();
      for (const r of missing) {
        addLeaf(idx, leafHash(r.owner, r.seq, r.hash));
        db.prepare("UPDATE entries SET tlog_idx = ? WHERE rowid = ?").run(idx, r.rowid);
        idx++;
      }
      db.exec("COMMIT");
      log.info("transparency log backfilled", { entries: missing.length });
    }
  }

  function append(owner, type, detail) {
    if (!EVENT_TYPES.has(type)) throw new HttpError(400, "bad_event", `Unknown event type ${type}`);
    db.exec("BEGIN IMMEDIATE");
    try {
      const prevRow = last.get(owner);
      const seq = (prevRow?.seq || 0) + 1;
      const prev = prevRow?.hash || GENESIS;
      const at = new Date().toISOString();
      const body = JSON.stringify({ at, type, detail: detail || {} });
      const hash = entryHash(owner, seq, prev, body);
      const idx = treeSize();
      insert.run(owner, seq, at, type, body, prev, hash, idx);
      addLeaf(idx, leafHash(owner, seq, hash));
      db.exec("COMMIT");
      return { seq, hash, index: idx };
    } catch (e) { db.exec("ROLLBACK"); throw e; }
  }

  /** The signed checkpoint for the current tree (signed once per size). */
  function checkpoint() {
    const size = treeSize();
    let cp = db.prepare("SELECT * FROM tlog_checkpoints WHERE size = ?").get(size);
    if (!cp) {
      const root = th(0, size);
      const at = Date.now();
      const sig = ml_dsa87.sign(checkpointMessage(size, root, at), key.sk);
      db.prepare("INSERT OR IGNORE INTO tlog_checkpoints (size, root, at, sig) VALUES (?, ?, ?, ?)").run(size, root, at, sig);
      cp = db.prepare("SELECT * FROM tlog_checkpoints WHERE size = ?").get(size);
    }
    const cosigs = db.prepare("SELECT name, sig FROM tlog_cosigs WHERE size = ?").all(size)
      .filter((c) => cosigners.has(c.name))
      .map((c) => ({ name: c.name, pk: b64u(cosigners.get(c.name)), sig: b64u(c.sig) }));
    return { checkpoint: { size: cp.size, root: toHex(new Uint8Array(cp.root)), at: cp.at, sig: b64u(cp.sig) }, cosignatures: cosigs, ledgerKey };
  }

  const sizeParam = (v, max) => {
    const n = Number(v);
    if (!Number.isSafeInteger(n) || n < 0 || n > max) throw new HttpError(400, "bad_size", "Tree size out of range");
    return n;
  };

  const routes = [
    ["POST", "/internal/events", ({ body, claims }) => {
      if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only");
      const e = parseObject(body);
      if (!/^hid_[0-9a-f]{40}$/.test(String(e.sub))) throw new HttpError(400, "bad_subject", "Unknown subject");
      return json(201, append(e.sub, String(e.type), e.detail));
    }],

    ["GET", "/events", ({ claims, query }) => {
      const owner = claims.sub;
      if (!owner) throw new HttpError(401, "unauthenticated", "Sign in first");
      // A range of older entries (?from=&to=), for a phone linking a page back to the head
      // it saw last time (CRYPTO-01). No head signature: the page's signed head covers them.
      if (query.get("from") != null) {
        const from = Number(query.get("from")), to = Number(query.get("to") ?? from + 999);
        if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 1 || to < from) throw new HttpError(400, "bad_range", "Bad range");
        const rows = db.prepare("SELECT seq, body, prev, hash FROM entries WHERE owner = ? AND seq >= ? AND seq <= ? ORDER BY seq LIMIT 1000").all(owner, from, to);
        return json(200, { owner, entries: rows.map((r) => ({ seq: r.seq, body: r.body, prev: r.prev, hash: r.hash })), ledgerKey });
      }
      const limit = Math.min(Math.max(Number(query.get("limit")) || 200, 1), 1000);
      const rows = db.prepare("SELECT seq, body, prev, hash FROM entries WHERE owner = ? ORDER BY seq DESC LIMIT ?").all(owner, limit).reverse();
      const headRow = rows[rows.length - 1];
      const head = headRow ? (() => {
        const signedAt = Date.now();
        return { seq: headRow.seq, hash: headRow.hash, signedAt, sig: b64u(ml_dsa87.sign(headMessage(owner, headRow.seq, headRow.hash, signedAt), key.sk)) };
      })() : null;
      return json(200, {
        owner,
        entries: rows.map((r) => ({ seq: r.seq, body: r.body, prev: r.prev, hash: r.hash })),
        head,
        ledgerKey,
      });
    }],

    /* ---------- the public log ---------- */

    // Latest signed checkpoint, with cosignatures. Public.
    ["GET", "/tlog/checkpoint", () => json(200, checkpoint())],

    // Proof that the tree of size `to` extends the tree of size `from`. Public.
    ["GET", "/tlog/consistency", ({ query }) => {
      const size = treeSize();
      const to = sizeParam(query.get("to") ?? size, size);
      const from = sizeParam(query.get("from"), to);
      return json(200, { from, to, proof: consistencyProof(leafAt, from, to, th).map(toHex) });
    }],

    // The signed-in holder: where their ledger entry `seq` (default: latest) sits in the tree, with its proof.
    ["GET", "/tlog/inclusion", ({ claims, query }) => {
      const owner = claims.sub;
      if (!owner) throw new HttpError(401, "unauthenticated", "Sign in first");
      const cp = checkpoint();
      const size = cp.checkpoint.size;
      const seq = query.get("seq") ? Number(query.get("seq")) : last.get(owner)?.seq;
      const row = seq && db.prepare("SELECT seq, hash, tlog_idx FROM entries WHERE owner = ? AND seq = ?").get(owner, seq);
      if (!row || row.tlog_idx == null || row.tlog_idx >= size) throw new HttpError(404, "not_in_log", "That entry isn't in the public log yet.");
      return json(200, { ...cp, owner, seq: row.seq, hash: row.hash, index: row.tlog_idx, proof: inclusionProof(leafAt, row.tlog_idx, 0, size, th).map(toHex) });
    }],

    // An independent cosigner vouches for a checkpoint it has checked against the one before. Public.
    ["POST", "/tlog/cosign", ({ body }) => {
      const r = parseObject(body);
      const pk = cosigners.get(String(r.name));
      if (!pk) throw new HttpError(403, "unknown_cosigner", "That cosigner isn't configured on this server.");
      const cp = db.prepare("SELECT * FROM tlog_checkpoints WHERE size = ?").get(Number(r.size));
      if (!cp) throw new HttpError(404, "unknown_checkpoint", "No such checkpoint.");
      let ok = false;
      try { ok = ml_dsa87.verify(unb64u(String(r.sig || "")), cosignMessage(String(r.name), cp.size, new Uint8Array(cp.root), cp.at), pk); } catch {}
      if (!ok) throw new HttpError(401, "bad_cosignature", "Cosignature doesn't verify.");
      db.prepare("INSERT OR REPLACE INTO tlog_cosigs (size, name, sig, at) VALUES (?, ?, ?, ?)").run(cp.size, String(r.name), unb64u(String(r.sig)), Date.now());
      return json(200, { accepted: true, size: cp.size });
    }],
  ];

  return createService({ tls, name: "ledger", port, routes, bodyLimit: 32 * 1024, verify: (t) => verifyAssertion(internalPk, t, "ledger") });
}

if (isMain(import.meta.url)) createLedger().start();
