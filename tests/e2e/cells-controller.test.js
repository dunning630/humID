// The holder-cell controller (deploy/windows/src/cells.mjs, docs/CELLS.md) against a stand-in
// for Hyper-V: "booting" a cell starts a real vault in cell mode, configured only from the
// seed the controller wrote (as the guest does at first boot), over mutual TLS with the
// cell's own certificate. The gateway's side (services/gateway/src/cells.js) takes cells from
// the pool the controller writes, as it does on the server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as svc from "@humid/svc";
import { createVault } from "../../services/vault/src/server.js";
import { createCells } from "../../services/gateway/src/cells.js";
import { createController, START_TIMEOUT_MS } from "../../deploy/windows/src/cells.mjs";

const { makeCa, issueRoleCert, serverTls, newInternalKeys, newStatementKeys, signRequest, internalRequest } = svc;

const root = mkdtempSync(join(tmpdir(), "humid-cellctl-"));
const ca = makeCa();
const front = issueRoleCert(ca, "front");
const ik = newInternalKeys();
const keys = { internalSk: ik.sk, internalPk: ik.pk, corePk: newStatementKeys().pk, keysPk: newStatementKeys().pk };
const settings = { warm: 2, max: 3, reserveMb: 4096, diskMb: 1024, image: join(root, "base.vhdx"), quotaBytes: 5 << 20 };
let clock = Date.now();
const vms = new Map(); // id -> vault, or null for a VM that never comes up
let freeMb = 16_000, failNext = false, neverBoot = false;
const removed = [], detached = [];

// What Hyper-V plus the guest's first boot do, in one process.
const hv = {
  async create({ id, seedDir }) {
    if (failNext) { failNext = false; throw new Error("Hyper-V said no"); }
    const seed = JSON.parse(readFileSync(join(seedDir, "cell.json"), "utf8"));
    const f = (n) => readFileSync(join(seedDir, n), "utf8");
    if (neverBoot) { vms.set(id, null); return { address: "127.0.0.1", port: 1 }; }
    const v = createVault({
      port: 0, dataDir: join(root, "vm", id), cell: seed.id, internalPk: seed.internalPk, corePk: seed.corePk, keysPk: seed.keysPk, quotaBytes: seed.quotaBytes,
      tls: serverTls({ ca: f("ca.crt"), cert: f("cell.crt"), key: f("cell.key") }),
    });
    process.env.HUMID_BIND_HOST = "127.0.0.1";
    await v.start();
    vms.set(id, v);
    return { address: "127.0.0.1", port: v.server.address().port };
  },
  async detachSeed(id) { detached.push(id); },
  async remove(id) { const v = vms.get(id); if (v) { await v.stop(); v.close(); } vms.delete(id); removed.push(id); },
  async freeMemoryMb() { return freeMb; },
};

let ctl, gw;
before(() => {
  mkdirSync(join(root, "data", "gateway"), { recursive: true });
  ctl = createController({ root, settings, keys, ca, front: { cert: front.certPem, key: front.keyPem }, hv, now: () => clock });
  gw = createCells({ poolFile: join(root, "cells", "pool.json"), dataDir: join(root, "data", "gateway"), tls: { ca: ca.certPem, cert: front.certPem, key: front.keyPem }, log: { warn: () => {} } });
});
after(async () => {
  for (const v of vms.values()) if (v) { await v.stop(); v.close(); }
  rmSync(root, { recursive: true, force: true });
});

const pool = () => JSON.parse(readFileSync(join(root, "cells", "pool.json"), "utf8")).cells;
const sub = (n) => "hid_" + String(n).repeat(40).slice(0, 40);
/** The gateway's bind call, signed with the internal key, over the cell's mutual TLS. */
const bindAs = (owner) => async ({ url, agent }) => {
  const path = "/internal/cell/bind", body = Buffer.from(JSON.stringify({ owner }));
  const r = await internalRequest(`${url}${path}`, { method: "POST", agent, body, headers: { "content-type": "application/json", "x-humid-assertion": signRequest(ik.sk, { aud: "vault", method: "POST", path, body }) } });
  return r.status === 200;
};

test("first pass starts the warm cells; the next one, once they answer, makes them ready", async () => {
  const r1 = await ctl.reconcile();
  assert.equal(r1.started.length, 2);
  assert.deepEqual(pool(), [], "not ready until they answer under their own names");
  const r2 = await ctl.reconcile();
  assert.deepEqual(r2.ready.sort(), r1.started.sort());
  assert.deepEqual(detached.sort(), r1.started.sort(), "seed disks detached");
  assert.equal(pool().length, 2);
  for (const id of r1.started) assert.ok(!existsSync(join(root, "cells", "private", "seed", id)), "and the seed's private key deleted");
});

test("the gateway takes a cell, and the controller refills the pool", async () => {
  const id = await gw.claim(sub(1), bindAs(sub(1)));
  assert.ok(id);
  assert.equal(vms.get(id).binding().owner, sub(1));
  const r = await ctl.reconcile();
  assert.equal(r.started.length, 1, "one more, to keep two warm");
  await ctl.reconcile();
  assert.equal(pool().length, 2);
  assert.ok(!pool().some((c) => c.id === id), "a taken cell is never offered again");
});

test("never past HUMID_CELLS_MAX", async () => {
  await gw.claim(sub(2), bindAs(sub(2)));
  const r = await ctl.reconcile();
  assert.equal(r.started.length, 0, "three cells already: the max");
  assert.equal(ctl.summary().bound, 2);
  assert.equal(pool().length, 1);
});

test("never below the memory reserve", async () => {
  settings.max = 10;
  freeMb = 4096 + 100;
  const r = await ctl.reconcile();
  assert.equal(r.started.length, 0);
  freeMb = 16_000;
});

test("a cell that never answers is removed after the timeout", async () => {
  neverBoot = true;
  const r = await ctl.reconcile();
  neverBoot = false;
  assert.equal(r.started.length, 1);
  const stuck = r.started[0];
  clock += START_TIMEOUT_MS + 1000;
  const r2 = await ctl.reconcile();
  assert.ok(r2.failed.includes(stuck));
  assert.ok(removed.includes(stuck));
  assert.ok(!existsSync(join(root, "cells", "private", "seed", stuck)));
});

test("Hyper-V refusing a cell stops that pass and leaves nothing behind", async () => {
  // fill the pool back up first, then ask for one more
  await ctl.reconcile(); await ctl.reconcile();
  settings.warm = pool().length + 1;
  failNext = true;
  const r = await ctl.reconcile();
  assert.equal(r.started.length, 0);
  settings.warm = 2;
});

test("a closed account's cell goes only once the cell itself says it's empty", async () => {
  const cellId = gw.forSub(sub(1)).id;
  // a document still in the cell (as if the gateway marked it by mistake, or was taken over)
  const db = new DatabaseSync(join(root, "vm", cellId, "vault.db"));
  db.prepare("INSERT INTO objects (id, owner, blob, size, idx, uploaded_at, updated_at) VALUES ('x', ?, 'b', 1, x'00', 't', 't')").run(sub(1));
  gw.retire(sub(1));
  const r = await ctl.reconcile();
  assert.deepEqual(r.kept, [cellId]);
  assert.ok(vms.has(cellId), "kept");
  db.prepare("DELETE FROM objects").run();
  db.close();
  const r2 = await ctl.reconcile();
  assert.deepEqual(r2.retired, [cellId]);
  assert.ok(!vms.has(cellId), "the VM and its disks are gone");
  assert.equal(ctl.cells()[cellId].state, "retired");
});

test("the controller's state survives a restart", () => {
  const again = createController({ root, settings, keys, ca, front: { cert: front.certPem, key: front.keyPem }, hv, now: () => clock });
  assert.deepEqual(again.summary(), ctl.summary());
});
