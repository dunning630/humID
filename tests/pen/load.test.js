// Load sanity, not a benchmark: 20 holders at once, each doing 20 calls that go
// through the ledger (uploads and step-up downloads), with zero errors and never
// an audit_unavailable. Per-IP handshake limit is 30/min, so 20 sessions fit.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startStack } from "../e2e/stack.js";
import { sealFor } from "../e2e/holder.js";
import { registered } from "./_lib.js";

const SESSIONS = 20, CALLS = 20;
let stack;
before(async () => { stack = await startStack(); });
after(async () => { await stack?.stop(); });

test(`${SESSIONS} concurrent sessions × ${CALLS} calls: no errors, no audit_unavailable`, async () => {
  const errors = [];
  const t0 = Date.now();
  const one = async (n) => {
    const { api, holder } = await registered(stack, `load-${n}`);
    const { envelope, index } = await sealFor(holder, `doc-${n}.txt`, `payload ${n}`);
    const id = (await api.upload(envelope, index)).id;
    for (let i = 0; i < CALLS; i++) {
      try {
        switch (i % 4) {
          case 0: await api.list(); break;
          case 1: await api.me(); break;
          case 2: { const env = await api.download(id, holder.stepUp); assert.ok(env.length > 0); break; }
          case 3: { const l = await api.ledger(); assert.equal(l.ok, true, l.reason); break; }
        }
      } catch (e) { errors.push({ session: n, call: i, code: e.code, message: e.message }); }
    }
    await api.logout();
  };
  await Promise.all(Array.from({ length: SESSIONS }, (_, n) => one(n)));
  const audit = errors.filter((e) => e.code === "audit_unavailable");
  assert.equal(audit.length, 0, `audit_unavailable: ${JSON.stringify(audit.slice(0, 3))}`);
  assert.deepEqual(errors, [], `${errors.length} errors, first: ${JSON.stringify(errors.slice(0, 3))}`);
  assert.ok(Date.now() - t0 < 60_000, "finished inside a minute");
});
