// CRYPTO-03 (b): role-to-role TLS (front -> core, front -> keys) carries split-key shares,
// anchor parts and ID-chip fields. With Node's default groups it negotiated X25519 alone, which
// someone recording the link today could open with a quantum computer later. Both ends now
// offer and accept only the hybrid X25519MLKEM768 group.
import { test } from "node:test";
import assert from "node:assert/strict";
import tls from "node:tls";
import * as svc from "@humid/svc";

const { makeCa, issueRoleCert, serverTls, clientTls, INTERNAL_TLS_GROUPS } = svc;

const ca = makeCa();
const core = issueRoleCert(ca, "core"), front = issueRoleCert(ca, "front");
const S = serverTls({ ca: ca.certPem, cert: core.certPem, key: core.keyPem });
const C = clientTls({ ca: ca.certPem, cert: front.certPem, key: front.keyPem, expect: "core" });

async function connect(server, client) {
  const srv = tls.createServer(server, (s) => s.end());
  srv.on("tlsClientError", () => {});
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    return await new Promise((resolve) => {
      const c = tls.connect({ host: "127.0.0.1", port: srv.address().port, ...client }, () => { const info = c.getEphemeralKeyInfo(); c.end(); resolve({ ok: true, info }); });
      c.on("error", (e) => resolve({ ok: false, err: e.code || e.message }));
    });
  } finally { srv.close(); }
}

test("internal TLS settings name the hybrid group on both ends", () => {
  assert.equal(INTERNAL_TLS_GROUPS, "X25519MLKEM768");
  assert.equal(S.ecdhCurve, INTERNAL_TLS_GROUPS);
  assert.equal(C.ecdhCurve, INTERNAL_TLS_GROUPS);
});

test("front and core connect, and the group is not plain X25519", async () => {
  const r = await connect(S, C);
  assert.ok(r.ok, r.err);
  // Node 22 reports no details for a hybrid group ({}); for a classical one it names it
  assert.notEqual(r.info?.name, "X25519");
  assert.notEqual(r.info?.type, "ECDH");
});

test("a client that offers only X25519 is refused by a role", async () => {
  const r = await connect(S, { ...C, ecdhCurve: "X25519" });
  assert.equal(r.ok, false);
});

test("the gateway refuses a role that will only do X25519", async () => {
  const r = await connect({ ...S, ecdhCurve: "X25519:P-256" }, C);
  assert.equal(r.ok, false);
});
