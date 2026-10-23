// SRV-34: an anonymous session (no sign-in, no pass, no phone) could create recovery requests
// the recovery service kept for a week, limited only by per-session and per-handshake limits.
// Now: a per-network cap at the gateway, a ceiling on unproven requests at the recovery service,
// and an unproven request ends (and is deleted) a day after it was made, not a week.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startStack } from "./stack.js";
import { HtpClient } from "@humid/htp/client";
import { b64u } from "@humid/htp";
import { newInternalKeys, signRequest } from "@humid/svc";
import { createRecovery } from "../../services/recovery/src/server.js";

let stack;
before(async () => { stack = await startStack({ messaging: false, recoveryStartsPerHour: 10 }); });
after(async () => { await stack?.stop(); });

const startBody = () => ({ method: "quorum", kemPk: b64u(randomBytes(1568)), xPk: b64u(randomBytes(32)), platform: "x".repeat(40) });

test("one network can start only a few recoveries an hour, whatever the sessions", async () => {
  let made = 0, limited = 0;
  for (let s = 0; s < 3; s++) {
    const c = new HtpClient({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
    for (let i = 0; i < 8; i++) {
      const r = await c.call("POST", "/recovery/requests", { body: startBody() });
      if (r.status === 201) made++; else if (r.status === 429) limited++;
    }
  }
  assert.equal(made, 10, "the per-network allowance");
  assert.equal(limited, 14);
});

test("the recovery service holds at most maxUnbound unproven requests, and ends them after unboundTtlMs", async () => {
  const keys = newInternalKeys();
  const dir = mkdtempSync(join(tmpdir(), "humid-recflood-"));
  let t = Date.now();
  const rec = createRecovery({ port: 0, dataDir: dir, internalPk: keys.pk, corePk: keys.pk, tls: null, maxUnbound: 5, unboundTtlMs: 60_000 });
  await rec.start();
  try {
    const url = `http://127.0.0.1:${rec.server.address().port}`;
    const post = async () => {
      const body = Buffer.from(JSON.stringify(startBody()));
      const res = await fetch(`${url}/requests`, { method: "POST", body, headers: { "content-type": "application/json", "x-humid-assertion": signRequest(keys.sk, { aud: "recovery", method: "POST", path: "/requests", body, claims: { sid: "anon" } }) } });
      return res.status;
    };
    const codes = [];
    for (let i = 0; i < 7; i++) codes.push(await post());
    assert.deepEqual(codes, [201, 201, 201, 201, 201, 503, 503], "fail closed at the ceiling");
    // a day (here a minute) on with no proof: they end and leave no row behind
    const db = new DatabaseSync(join(dir, "recovery.db"));
    db.prepare("UPDATE requests SET created_at = created_at - 61000").run();
    db.close();
    assert.equal(await post(), 201, "the sweep ran on this request and made room");
    const db2 = new DatabaseSync(join(dir, "recovery.db"), { readOnly: true });
    const rows = db2.prepare("SELECT status, COUNT(*) n FROM requests GROUP BY status").all();
    db2.close();
    assert.deepEqual(rows.map((r) => ({ ...r })), [{ status: "collecting", n: 1 }], "the stale unproven requests are gone, not kept for a week");
  } finally { await rec.stop(); rmSync(dir, { recursive: true, force: true }); }
});
