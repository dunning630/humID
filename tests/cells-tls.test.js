// Holder cells (docs/CELLS.md): each cell has its own certificate, humid-cell-<id>, from the
// server's CA. The gateway accepts a cell only under the exact name the pool gives for it, so
// one cell can't answer for another, and a cell's certificate is never taken for front, core
// or keys. A real vault in cell mode, over mutual TLS with the hybrid group.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as svc from "@humid/svc";
import { createVault } from "../services/vault/src/server.js";

const { makeCa, issueRoleCert, issueCellCert, cellOf, roleOf, serverTls, clientTls, roleAgent, internalRequest, signRequest, newInternalKeys, newStatementKeys } = svc;

const ca = makeCa();
const front = issueRoleCert(ca, "front");
const ik = newInternalKeys();
const dir = mkdtempSync(join(tmpdir(), "humid-cell-tls-"));
process.env.HUMID_BIND_HOST = "127.0.0.1";
const cellA = issueCellCert(ca, "alpha00001");
const vault = createVault({
  port: 0, dataDir: dir, internalPk: ik.pk, corePk: newStatementKeys().pk, keysPk: newStatementKeys().pk, cell: "alpha00001",
  tls: serverTls({ ca: ca.certPem, cert: cellA.certPem, key: cellA.keyPem }),
});
await vault.start();
after(async () => { await vault.stop(); vault.close(); rmSync(dir, { recursive: true, force: true }); });
const url = `https://127.0.0.1:${vault.server.address().port}`;

const bind = (agent, owner) => {
  const body = Buffer.from(JSON.stringify({ owner }));
  const path = "/internal/cell/bind";
  return internalRequest(`${url}${path}`, { method: "POST", agent, body, headers: { "content-type": "application/json", "x-humid-assertion": signRequest(ik.sk, { aud: "vault", method: "POST", path, body }) } });
};
const owner = "hid_" + "ab".repeat(20);

test("a cell's certificate names the cell, and no role", () => {
  assert.equal(cellOf(cellA.certPem), "alpha00001");
  assert.equal(roleOf(cellA.certPem), null, "never front, core or keys");
  assert.equal(cellOf(front.certPem), null);
  assert.throws(() => issueCellCert(ca, "../x"), /cell id/);
});

test("the gateway reaches the cell it meant, and binds it", async () => {
  const agent = roleAgent(clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expectCell: "alpha00001" }));
  const r = await bind(agent, owner);
  assert.equal(r.status, 200);
  assert.equal(vault.binding().owner, owner);
});

test("expecting another cell at that address: refused before any request", async () => {
  const agent = roleAgent(clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expectCell: "beta000002" }));
  await assert.rejects(bind(agent, owner));
});

test("expecting core at that address: refused", async () => {
  const agent = roleAgent(clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expect: "core" }));
  await assert.rejects(bind(agent, owner));
});

test("a caller with another cell's certificate is refused by the cell", async () => {
  const cellB = issueCellCert(ca, "beta000002");
  const agent = roleAgent(clientTls({ ca: ca.certPem, cert: cellB.certPem, key: cellB.keyPem, expectCell: "alpha00001" }));
  await assert.rejects(bind(agent, owner));
});

test("a cell's data refuses to start as a different cell", () => {
  assert.throws(() => createVault({ port: 0, dataDir: dir, internalPk: ik.pk, corePk: newStatementKeys().pk, keysPk: newStatementKeys().pk, cell: "gamma00003", tls: null }), /belongs to cell alpha00001/);
});
