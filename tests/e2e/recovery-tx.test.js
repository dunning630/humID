// SRV-02 (review 2026-10-23): a write that fails inside a transaction must roll back. A card tag
// another account already uses threw mid-transaction with no ROLLBACK, which left recovery.db's one
// shared connection inside an open transaction and wedged every account's recovery writes.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { startStack } from "./stack.js";
import { makeHolder, register } from "./holder.js";
import { cardTag, newCard, sealCard } from "@humid/recovery";

let stack, a, b, v, apiA, apiB, apiV;
before(async () => {
  stack = await startStack({ recoveryDelayMs: 500 });
  a = makeHolder("a"); b = makeHolder("b"); v = makeHolder("victim");
  apiA = await register(a, stack.baseUrl); apiB = await register(b, stack.baseUrl); apiV = await register(v, stack.baseUrl);
});
after(async () => { await stack?.stop(); });

test("a clashing card tag fails alone and leaves recovery working for everyone", async () => {
  const c = newCard();
  const tag = cardTag(c.secret);
  await apiA.setCard({ tag, blob: await sealCard(c.secret, a.seed, a.id) }, a.stepUp);
  await assert.rejects(apiB.setCard({ tag, blob: await sealCard(c.secret, b.seed, b.id) }, b.stepUp));
  const vc = newCard();
  await apiV.setCard({ tag: cardTag(vc.secret), blob: await sealCard(vc.secret, v.seed, v.id) }, v.stepUp);
  const other = new DatabaseSync(`${stack.root}/recovery/recovery.db`, { readOnly: true });
  try {
    const row = other.prepare("SELECT account FROM cards WHERE account = ?").get(v.id);
    assert.equal(row?.account, v.id, "the victim's card is committed and visible to another connection");
  } finally { other.close(); }
});
