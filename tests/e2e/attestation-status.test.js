// LIVE-02 / SRV-33 / PC-14: Google's revoked-key list actually reaches identity in the
// Docker layout (identity has no internet; a sidecar writes the list to a file it reads),
// a stale or missing copy refuses Android phones under the attested policy instead of
// waving them through, and the test-only "any signer" lever can't ride along silently.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import { newInternalKeys, newStatementKeys } from "@humid/svc";
import { HumidApi } from "@humid/api";
import { serialKey, fetchStatusToFile } from "@humid/attest";
import { createIdentity } from "../../services/identity/src/server.js";
import { createVault } from "../../services/vault/src/server.js";
import { createLedger } from "../../services/ledger/src/server.js";
import { createRecovery } from "../../services/recovery/src/server.js";
import { createAccess } from "../../services/access/src/server.js";
import { createKeyshare } from "../../services/keyshare/src/server.js";
import { createGateway } from "../../services/gateway/src/server.js";
import { makeHolder, ROOTS, IOS_APP_ID } from "./holder.js";

const ATTEST = {
  roots: { android: [ROOTS.android.pem], apple: [ROOTS.apple.pem] },
  androidPackages: ["app.humid.vault"], iosAppId: IOS_APP_ID, appAttestEnvironment: "production", requireLockedBoot: true,
  androidDigests: ["01".repeat(32)],
};
const code = (c) => (e) => { assert.equal(e.code, c, `expected ${c}, got ${e.code}: ${e.message}`); return true; };
const HOUR = 3600_000;

let root, ik, core, keys, others, identity, gateway, statusFile, clock;
const url = (s) => `http://127.0.0.1:${s.server.address().port}`;
const writeStatus = (entries, fetchedAt) => writeFileSync(statusFile, JSON.stringify({ fetchedAt: new Date(fetchedAt).toISOString(), status: { entries } }));

async function startIdentity(opts = {}) {
  await identity?.stop();
  identity = createIdentity({ port: 0, dataDir: join(root, "identity"), internalPk: ik.pk, statementSk: core.sk, statusFile, statusUrl: "", attest: ATTEST, devicePolicy: "attested", ...opts });
  await identity.start();
  await identity.revocation.refresh();
  if (gateway) await gateway.stop();
  gateway = createGateway({ port: 0, dataDir: join(root, "gateway"), internalSk: ik.sk, upstreams: { ...others, identity: url(identity) }, allowedOrigins: [], trustProxy: false, devicePolicy: "attested", registration: "open" });
  await gateway.start();
}

before(async () => {
  root = mkdtempSync(join(tmpdir(), "humid-status-"));
  statusFile = join(root, "status", "attestation-status.json");
  ik = newInternalKeys();
  core = newStatementKeys(); keys = newStatementKeys();
  const svcs = {
    vault: createVault({ port: 0, dataDir: join(root, "vault"), internalPk: ik.pk, corePk: core.pk, keysPk: keys.pk }),
    ledger: createLedger({ port: 0, dataDir: join(root, "ledger"), internalPk: ik.pk, statementSk: core.sk }),
    recovery: createRecovery({ port: 0, dataDir: join(root, "recovery"), internalPk: ik.pk, corePk: core.pk }),
    access: createAccess({ port: 0, dataDir: join(root, "access"), internalPk: ik.pk, keyBits: 2048, stampKeyBits: 2048 }),
    keyshare: createKeyshare({ port: 0, dataDir: join(root, "keyshare"), internalPk: ik.pk, statementSk: keys.sk, corePk: core.pk }),
  };
  await Promise.all(Object.values(svcs).map((s) => s.start()));
  others = Object.fromEntries(Object.entries(svcs).map(([k, s]) => [k, url(s)]));
  others.svcs = svcs;
});
after(async () => {
  await gateway?.stop(); await identity?.stop();
  const { svcs } = others;
  await Promise.all(Object.values(svcs).map((s) => s.stop()));
  svcs.access.close(); svcs.keyshare.close();
  rmSync(root, { recursive: true, force: true });
});

/** Register a new Android holder; `revoke` adds its chain's intermediate to the status file first. */
async function enrol(label, { revoke = false, fetchedAt = Date.now() } = {}) {
  const h = makeHolder(label);
  const api = new HumidApi({ baseUrl: url(gateway) });
  const sign = async (m) => {
    const r = await h.registerSign(m);
    const entries = {};
    if (revoke) for (const c of r.live.attestation.chain.slice(1, -1)) entries[serialKey(new X509Certificate(Buffer.from(c)).serialNumber)] = { status: "REVOKED", reason: "KEY_COMPROMISE" };
    writeStatus(entries, fetchedAt);
    await identity.revocation.refresh();
    return r;
  };
  return api.register({ pub: h.pub, commit: h.commit, device: h.device, sign });
}

test("the sidecar's file reaches identity: a revoked phone is refused, a clean one joins", async () => {
  // the sidecar's own write path, with Google's endpoint stood in for
  await fetchStatusToFile({ url: "https://example.test/status", file: statusFile, fetch: async () => ({ ok: true, json: async () => ({ entries: {} }) }) });
  await startIdentity();
  assert.equal(identity.revocation.source, "file");
  assert.ok(identity.revocation.ready, "identity read the sidecar's copy");
  await assert.rejects(enrol("revoked-phone", { revoke: true }), code("revoked"));
  assert.ok((await enrol("clean-phone")).id);
});

test("attested policy, no copy at all: Android phones are refused, not waved through", async () => {
  rmSync(statusFile, { force: true });
  await startIdentity();
  assert.equal(identity.revocation.ready, false);
  const h = makeHolder("no-list-phone");
  await assert.rejects(new HumidApi({ baseUrl: url(gateway) }).register({ pub: h.pub, commit: h.commit, device: h.device, sign: h.registerSign }), code("status_unavailable"));
});

test("attested policy, a copy older than the maximum age: refused (status_stale)", async () => {
  writeStatus({}, Date.now() - 49 * HOUR);
  await startIdentity();
  await assert.rejects(enrol("stale-list-phone", { fetchedAt: Date.now() - 49 * HOUR }), code("status_stale"));
  assert.ok((await enrol("fresh-list-phone", { fetchedAt: Date.now() - 1 * HOUR })).id, "a fresh copy lets it in");
});

test("HUMID_ATTESTATION_STATUS_REQUIRED=0 is the explicit opt-out, and the posture says so", async () => {
  writeStatus({}, Date.now() - 49 * HOUR);
  await startIdentity({ statusRequired: false });
  assert.ok((await enrol("opted-out-phone", { fetchedAt: Date.now() - 49 * HOUR })).id);
  assert.match(identity.posture().weakened.join("\n"), /STATUS_REQUIRED=0/);
});

test("LIVE-04: any-signer with the attested policy refuses to start without HUMID_INSECURE_TEST=1", async () => {
  const dataDir = join(root, "identity-anysigner");
  const make = (extra) => createIdentity({ port: 0, dataDir, internalPk: ik.pk, statusUrl: "", attest: { ...ATTEST, allowAnySigner: true }, devicePolicy: "attested", ...extra });
  assert.throws(() => make({}), /HUMID_INSECURE_TEST=1/);
  const id = make({ insecureTest: true });
  const p = id.posture();
  assert.equal(p.allowAnySigner, true);
  assert.match(p.weakened.join("\n"), /ALLOW_ANY_SIGNER=1/);
  await id.stop?.().catch(() => {});
  // other policies already accept unproven devices: the lever is allowed, and still reported
  assert.match(make({ devicePolicy: "biometric" }).posture().weakened.join("\n"), /ALLOW_ANY_SIGNER=1/);
});

test("the startup posture of a default attested server names nothing weakened", async () => {
  writeStatus({}, Date.now());
  await startIdentity();
  const p = identity.posture();
  assert.deepEqual(p.weakened, []);
  assert.equal(p.revocationRequired, true);
  assert.equal(p.revocation, "file");
});
