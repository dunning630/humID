// The ledger at scale (crypto review, efficiency): a read doesn't sign a new ML-DSA-87 head
// every time, and the public log signs one checkpoint per interval, not one per entry.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { newInternalKeys, signRequest, internalRequest } from "@humid/svc";
import { verifyLedger } from "@humid/audit";
import { createLedger } from "../services/ledger/src/server.js";

const keys = newInternalKeys();
const dir = mkdtempSync(join(tmpdir(), "humid-ledger-"));
const owner = "hid_" + "ef".repeat(20);
let ledger, base;
before(async () => {
  ledger = createLedger({ port: 0, dataDir: dir, internalPk: keys.pk, tls: null, seal: null, checkpointEveryMs: 400 });
  await ledger.start();
  base = `http://127.0.0.1:${ledger.server.address().port}`;
});
after(async () => { await ledger?.stop(); ledger?.close?.(); rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });

async function call(method, path, json, claims = { sub: owner }) {
  const body = json ? Buffer.from(JSON.stringify(json)) : undefined;
  const r = await internalRequest(`${base}${path}`, { method, body, headers: { "x-humid-assertion": signRequest(keys.sk, { aud: "ledger", method, path, body, claims }), ...(body ? { "content-type": "application/json" } : {}) } });
  return { status: r.status, json: JSON.parse(Buffer.from(r.body).toString() || "null") };
}
const append = (type) => call("POST", "/internal/events", { sub: owner, type, detail: {} }, {});
const checkpoints = () => { const db = new DatabaseSync(join(dir, "ledger.db")); const n = db.prepare("SELECT COUNT(*) AS n FROM tlog_checkpoints").get().n; db.close(); return n; };

test("reading the history twice doesn't sign the head twice; a new entry gets a new signature", async () => {
  await append("session.opened");
  const a = (await call("GET", "/events")).json, b = (await call("GET", "/events")).json;
  assert.equal(verifyLedger(a, { expectedOwner: owner }).ok, true);
  assert.equal(b.head.sig, a.head.sig, "the cached signature, still valid");
  assert.equal(b.head.signedAt, a.head.signedAt);
  await append("session.closed");
  const c = (await call("GET", "/events")).json;
  assert.notEqual(c.head.sig, a.head.sig);
  assert.equal(verifyLedger(c, { expectedOwner: owner }).ok, true);
});

test("many entries, many readers: one checkpoint per interval, and every entry still gets its proof", async () => {
  await call("GET", "/tlog/checkpoint");
  const before = checkpoints();
  for (let i = 0; i < 20; i++) { await append("object.opened"); await call("GET", "/tlog/checkpoint"); }
  assert.ok(checkpoints() - before <= 2, `${checkpoints() - before} new checkpoints for 20 entries read 20 times`);
  // The newest entry isn't in the latest checkpoint yet: its proof waits for the next one.
  const t0 = Date.now();
  const inc = await call("GET", "/tlog/inclusion");
  assert.equal(inc.status, 200);
  assert.ok(inc.json.index < inc.json.checkpoint.size, "covered by the checkpoint it's proven against");
  assert.ok(Date.now() - t0 < 2000);
});
