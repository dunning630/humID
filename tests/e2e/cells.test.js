// End to end: holder cells (docs/CELLS.md). Each new HumID gets its own cell from the warm
// pool, its documents live there and nowhere else, and a cell serves no other account even
// when the gateway signs the request. Here the cells are vaults in cell mode on loopback,
// standing in for the Hyper-V VMs the controller boots.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { signRequest, internalRequest } from "@humid/svc";
import { startStack } from "./stack.js";
import { makeHolder, register, sealFor } from "./holder.js";

let stack, alice, bob, carol, aliceApi, bobApi, carolApi;
before(async () => {
  stack = await startStack({ cells: 2 });
  alice = makeHolder("alice-cells"); bob = makeHolder("bob-cells"); carol = makeHolder("carol-cells");
});
after(async () => { await stack?.stop(); });

const claims = () => JSON.parse(readFileSync(join(stack.root, "gateway", "cells.json"), "utf8")).claims;
const rows = (dir) => {
  const db = new DatabaseSync(join(dir, "vault.db"), { readOnly: true });
  try { return db.prepare("SELECT owner FROM objects").all().map((r) => r.owner); } finally { db.close(); }
};
/** A request to one vault directly, signed with the gateway's own key: what a misrouted call would look like. */
async function direct(v, method, path, sub, json) {
  const body = json ? Buffer.from(JSON.stringify(json)) : undefined;
  const r = await internalRequest(`http://127.0.0.1:${v.server.address().port}${path}`, {
    method, body, headers: { "content-type": "application/json", "x-humid-assertion": signRequest(stack.internalSk, { aud: "vault", method, path, body, claims: sub ? { sub } : {} }) },
  });
  return { status: r.status, data: r.body.length ? JSON.parse(Buffer.from(r.body).toString()) : null };
}

test("a new HumID gets its own cell from the pool, bound to it", async () => {
  aliceApi = await register(alice, stack.baseUrl);
  const c = claims()[alice.id];
  assert.ok(c, "alice has a cell");
  assert.equal(c.state, "bound");
  const v = stack.cellVaults.find((x) => x.cell === c.cell);
  assert.equal(v.binding().owner, alice.id);
});

test("her documents go to her cell, not the shared vault", async () => {
  const s = await sealFor(alice, "deed.txt", "The deed to the cabin.");
  const { id } = await aliceApi.upload(s.envelope, s.index);
  const cell = stack.cellVaults.find((x) => x.cell === claims()[alice.id].cell);
  assert.deepEqual(rows(join(stack.root, "cells", cell.cell)), [alice.id]);
  assert.deepEqual(rows(join(stack.root, "vault")), [], "the shared vault holds nothing of hers");
  const list = await aliceApi.list();
  assert.deepEqual(list.items.map((x) => x.id), [id]);
  const envelope = await aliceApi.download(id, alice.stepUp);
  assert.equal(new TextDecoder().decode((await alice.S.open(envelope, alice.keys)).bytes), "The deed to the cabin.");
});

test("the next HumID gets a different cell", async () => {
  bobApi = await register(bob, stack.baseUrl);
  assert.notEqual(claims()[bob.id].cell, claims()[alice.id].cell);
  const s = await sealFor(bob, "bob.txt", "bob's note");
  await bobApi.upload(s.envelope, s.index);
  assert.equal((await aliceApi.list()).items.length, 1, "alice still sees only her own");
});

test("a cell refuses any other account, even with the gateway's own signature", async () => {
  const aliceCell = stack.cellVaults.find((x) => x.cell === claims()[alice.id].cell);
  const r = await direct(aliceCell, "GET", "/objects", bob.id);
  assert.equal(r.status, 403);
  assert.equal(r.data.error, "wrong_cell");
  const again = await direct(aliceCell, "POST", "/internal/cell/bind", null, { owner: bob.id });
  assert.equal(again.status, 409, "a bound cell can't be re-bound to someone else");
  assert.equal(again.data.error, "cell_taken");
  assert.equal(aliceCell.binding().owner, alice.id);
});

test("an unbound cell serves nobody", async () => {
  const spare = await stack.addCell();
  const r = await direct(spare, "GET", "/objects", alice.id);
  assert.equal(r.status, 409);
  assert.equal(r.data.error, "cell_unbound");
});

test("pool empty: sign-up still works, on the shared vault", async () => {
  // the spare cell above is in the pool; take it with a fourth holder first
  const dave = makeHolder("dave-cells");
  await register(dave, stack.baseUrl);
  assert.ok(claims()[dave.id], "dave took the last warm cell");
  carolApi = await register(carol, stack.baseUrl);
  assert.equal(claims()[carol.id], undefined, "no cell left for carol");
  const s = await sealFor(carol, "carol.txt", "carol's note");
  await carolApi.upload(s.envelope, s.index);
  assert.deepEqual(rows(join(stack.root, "vault")), [carol.id]);
  assert.deepEqual(stack.gateway.cells.stats(), { bound: 3, retiring: 0, warm: 0 });
});

test("closing a HumID erases its cell and marks it for retirement", async () => {
  const cellId = claims()[bob.id].cell;
  await bobApi.closeIdentity(bob.stepUp);
  assert.equal(claims()[bob.id].state, "retire");
  const v = stack.cellVaults.find((x) => x.cell === cellId);
  const st = await direct(v, "GET", "/internal/cell/status");
  assert.equal(st.status, 200);
  assert.equal(st.data.total, 0, "nothing left in the cell for the controller to lose");
});

test("a holder whose cell is down is refused, never sent to the shared vault", async () => {
  const v = stack.cellVaults.find((x) => x.cell === claims()[alice.id].cell);
  await v.stop();
  await assert.rejects(aliceApi.list(), (e) => e.status === 503);
  assert.deepEqual(rows(join(stack.root, "vault")), [carol.id]);
});
