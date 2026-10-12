// ledger — tamper-evident access history.
//
// Every security-relevant event (identity created, session opened, document
// sealed / opened / deleted, access denied) is appended to the holder's own
// hash chain:  hash_n = SHA3-256(owner, n, hash_{n-1}, entry_n).
// Reads return the chain plus the head signed with the ledger's ML-DSA-87
// key, so the app can prove that no entry was edited, removed or reordered.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { createService, openDb, env, json, parseJson, verifyAssertion, HttpError, b64u, unb64u } from "@humid/svc";
import { ml_dsa87, sha3_256, toHex } from "@humid/htp";
import { GENESIS, entryHash, headMessage } from "@humid/audit";

export { GENESIS, entryHash, headMessage };

const EVENT_TYPES = new Set([
  "identity.created", "identity.closed", "session.opened", "session.closed",
  "object.sealed", "object.opened", "object.updated", "object.deleted", "vault.erased",
  "access.denied",
]);

export function createLedger({ port = Number(env("PORT", "8083")), dataDir = env("DATA_DIR", "/data"), internalPk = env("HUMID_INTERNAL_PK") } = {}) {
  mkdirSync(dataDir, { recursive: true });
  const keyFile = `${dataDir}/ledger-key.json`;
  let key;
  if (existsSync(keyFile)) {
    const j = JSON.parse(readFileSync(keyFile, "utf8"));
    key = { pk: unb64u(j.pk), sk: unb64u(j.sk) };
  } else {
    const k = ml_dsa87.keygen();
    key = { pk: k.publicKey, sk: k.secretKey };
    writeFileSync(keyFile, JSON.stringify({ pk: b64u(key.pk), sk: b64u(key.sk) }), { mode: 0o600 });
  }
  const keyFp = toHex(sha3_256(key.pk)).slice(0, 32);

  const db = openDb(dataDir, "ledger.db", [
    `CREATE TABLE entries (
       owner TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, type TEXT NOT NULL,
       body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL,
       PRIMARY KEY (owner, seq))`,
  ]);
  const last = db.prepare("SELECT seq, hash FROM entries WHERE owner = ? ORDER BY seq DESC LIMIT 1");
  const insert = db.prepare("INSERT INTO entries (owner, seq, at, type, body, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?)");

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
      insert.run(owner, seq, at, type, body, prev, hash);
      db.exec("COMMIT");
      return { seq, hash };
    } catch (e) { db.exec("ROLLBACK"); throw e; }
  }

  const routes = [
    ["POST", "/internal/events", ({ body, claims }) => {
      if (claims.iss !== "gateway") throw new HttpError(403, "forbidden", "Gateway only");
      const e = parseJson(body);
      if (!/^hid_[0-9a-f]{40}$/.test(String(e.sub))) throw new HttpError(400, "bad_subject", "Unknown subject");
      return json(201, append(e.sub, String(e.type), e.detail));
    }],

    ["GET", "/events", ({ claims, query }) => {
      const owner = claims.sub;
      if (!owner) throw new HttpError(401, "unauthenticated", "Sign in first");
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
        ledgerKey: { dsa: b64u(key.pk), fp: keyFp },
      });
    }],
  ];

  return createService({ name: "ledger", port, routes, bodyLimit: 32 * 1024, verify: (t) => verifyAssertion(internalPk, t, "ledger") });
}

if (import.meta.url === `file://${process.argv[1]}`) createLedger().start();
