// Stamp keys per epoch at the issuer (services/access, security review MSG-01): the issuer
// can't see when a stamp's message says it was sent, so each key signs only during its own
// hour, and phones count a stamp only for a time inside that hour. Tested against the real
// service with a clock the test moves.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createAccess } from "@humid/access-service";
import { newInternalKeys, signRequest, internalRequest } from "@humid/svc";
import * as M from "@humid/msg";

const ik = newInternalKeys();
const root = mkdtempSync(join(tmpdir(), "humid-stamp-epochs-"));
after(() => rmSync(root, { recursive: true, force: true }));
const HOUR = 3600_000, MIN = 60_000;
const T0 = Date.UTC(2026, 9, 23, 9, 0, 0);

async function call(svc, method, path, json) {
  const body = json ? new TextEncoder().encode(JSON.stringify(json)) : undefined;
  const assertion = signRequest(ik.sk, { aud: "access", method, path, body, claims: { iss: "gateway" } });
  const res = await internalRequest(`http://127.0.0.1:${svc.server.address().port}${path}`, { method, headers: { "x-humid-assertion": assertion, "content-type": "application/json" }, body });
  return { status: res.status, data: res.body.length ? JSON.parse(Buffer.from(res.body).toString()) : null };
}

test("hourly stamp keys: current and next published, each signs only in its own hour, retired ones archived", async () => {
  let t = T0 + 10 * MIN;
  const svc = createAccess({ port: 0, dataDir: join(root, "a"), internalPk: ik.pk, keyBits: 2048, stampKeyBits: 2048, now: () => t });
  await svc.start();
  try {
    const k0 = (await call(svc, "GET", "/internal/stamp/keys")).data;
    assert.equal(k0.epochMs, HOUR);
    assert.equal(k0.keys.length, 2, "this hour's key and the next");
    assert.deepEqual(k0.keys.map((k) => [k.issuing, k.notBefore, k.notAfter]), [[true, T0, T0 + HOUR], [false, T0 + HOUR, T0 + 2 * HOUR]]);
    const keys = M.importStampKeys(k0.keys);
    const c = new Uint8Array(32).fill(3);
    // Asking now for a stamp under the NEXT hour's key (to date a message an hour on) is refused.
    const ahead = M.blindStamp(keys, c, { at: T0 + 70 * MIN });
    assert.equal(ahead.draft.kid, k0.keys[1].id);
    assert.equal((await call(svc, "POST", "/internal/stamp/sign", { kid: ahead.draft.kid, blinded: [Buffer.from(ahead.blinded).toString("base64url")] })).data.error, "key_changed");
    // This hour's key signs.
    const d = M.blindStamp(keys, c, { at: t });
    const ok = await call(svc, "POST", "/internal/stamp/sign", { kid: d.draft.kid, blinded: [Buffer.from(d.blinded).toString("base64url")] });
    assert.equal(ok.status, 200);
    const stamp = M.finalizeStamp(keys, d.draft, new Uint8Array(Buffer.from(ok.data.blindSigs[0], "base64url")));
    assert.ok(M.verifyStamp(keys, stamp, c, { at: t }));
    assert.ok(!M.verifyStamp(keys, stamp, c, { at: T0 + HOUR + 3 * MIN }), "dated after the epoch (+ skew): not live");

    // An hour and a half later: the old key no longer signs, its private half is gone, and it is archived.
    t = T0 + 90 * MIN;
    await svc.tick();
    assert.equal((await call(svc, "POST", "/internal/stamp/sign", { kid: d.draft.kid, blinded: [Buffer.from(d.blinded).toString("base64url")] })).data.error, "key_changed");
    const k1 = (await call(svc, "GET", "/internal/stamp/keys")).data;
    assert.deepEqual(k1.keys.map((k) => k.id), [k0.keys[1].id, k1.keys[1].id], "the announced next key became issuing on time");
    assert.ok(k1.archive.some((k) => k.id === k0.keys[0].id && k.notAfter === T0 + HOUR), "the retired key is archived with its epoch");
    const later = M.importStampKeys(k1.keys, { archive: k1.archive });
    assert.ok(M.verifyStamp(later, stamp, c, { at: T0 + 10 * MIN }), "a stamp from last hour still checks, by its own time");
    const since = (await call(svc, "GET", `/internal/stamp/keys?since=${T0 + HOUR}`)).data;
    assert.equal(since.archive.length, 0, "?since leaves out what the phone already has");
    const db = new DatabaseSync(join(root, "a", "access.db"), { readOnly: true });
    try {
      assert.equal(db.prepare("SELECT pem FROM stamp_keys WHERE id = ?").get(k0.keys[0].id).pem, "", "the retired private key is erased");
    } finally { db.close(); }
  } finally { await svc.stop(); svc.close(); }
});
