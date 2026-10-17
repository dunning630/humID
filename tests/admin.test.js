// The admin console's trust pieces (docs/ADMIN.md), without Windows or a network:
// request codes and digests, approval checks, the hash-chained audit log, which
// GitHub release is offered, and that a download must match GitHub's digest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ml_dsa87, stepUpMessage, actionBytes, deviceId, random, b64u, utf8 } from "@humid/htp";
import { adminCheck, keyCode, ADMIN_CHECK_LABEL, formatCode as fmt, parseQr, qrPayload } from "@humid/recovery";
import { newCode, CODE_RE, canonical, requestDigest, digestCheck, verifyApproval, ApprovalError } from "../deploy/windows/admin/verify.mjs";
import { openStore } from "../deploy/windows/admin/store.mjs";
import { latestRelease, download, compareVersions } from "../deploy/windows/admin/updates.mjs";
import { validate } from "../deploy/windows/src/config.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "humid-admin-unit-"));

test("request codes: 12 Crockford characters, the same alphabet as the app's codes", () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) { const c = newCode(); assert.match(c, CODE_RE); seen.add(c); }
  assert.equal(seen.size, 200);
  const qr = parseQr(qrPayload("admin", "W8EH9R67XA5G", Date.now() + 60_000));
  assert.equal(qr.kind, "admin", "the app's scanner knows admin codes");
});

test("digests: canonical, and bound to the server, the code, the change and the time", () => {
  assert.equal(canonical({ b: 1, a: [2, { d: 3, c: 4 }] }), '{"a":[2,{"c":4,"d":3}],"b":1}');
  const base = { kid: "k", code: "W8EH9R67XA5G", kind: "action", type: "reboot", args: { x: 1, y: 2 }, createdAt: 1 };
  const d = requestDigest(base);
  assert.match(d, /^[0-9a-f]{64}$/);
  assert.equal(requestDigest({ ...base, args: { y: 2, x: 1 } }), d, "key order doesn't matter");
  for (const change of [{ kid: "k2" }, { code: "W8EH9R67XA5H" }, { type: "backup" }, { args: { x: 2, y: 2 } }, { createdAt: 2 }]) {
    assert.notEqual(requestDigest({ ...base, ...change }), d, `changing ${Object.keys(change)[0]} changes the digest`);
  }
  assert.match(digestCheck(d), /^[0-9A-F]{4}-[0-9A-F]{4}$/);
});

test("admin check: the phone's code is computed from its own device key", () => {
  const pk = ml_dsa87.keygen(random(32)).publicKey;
  assert.equal(adminCheck(pk), fmt(keyCode(ADMIN_CHECK_LABEL, pk)));
  assert.notEqual(adminCheck(pk), adminCheck(ml_dsa87.keygen(random(32)).publicKey));
});

/** An approval as the gateway hands it over, signed by `signer`. */
function approval({ request, account, dev, signer = dev, tamper = {} }) {
  const path = `/admin/requests/${request.code}/approve`;
  const body = utf8(JSON.stringify({ digest: request.digest }));
  const th = random(32), seq = 4, at = Date.now(), exp = at + 60_000, nonce = random(16);
  const device = deviceId(dev.publicKey);
  const action = actionBytes({ method: "POST", path, device, nonce, exp });
  const sig = ml_dsa87.sign(stepUpMessage(th, seq, "POST", path, body, at, action), signer.secretKey);
  return { code: request.code, account, device, platform: "test", deviceDsaPk: b64u(dev.publicKey), th: b64u(th), seq, method: "POST", path, body: b64u(body), at, exp, nonce: b64u(nonce), sig: b64u(sig), live: null, ...tamper };
}

test("approvals: a pinned administrator's signature over exactly this request is accepted", () => {
  const dev = ml_dsa87.keygen(random(32));
  const account = "hid_" + "1".repeat(40);
  const admins = [{ account, device: deviceId(dev.publicKey), deviceDsaPk: b64u(dev.publicKey), livePub: null, platform: "Pixel" }];
  const request = { code: "W8EH9R67XA5G", kind: "action", createdAt: Date.now() - 1000 };
  request.digest = requestDigest({ kid: "k", code: request.code, kind: "action", type: "reboot", args: {}, createdAt: request.createdAt });
  const v = verifyApproval(approval({ request, account, dev }), request, admins);
  assert.equal(v.admin.platform, "Pixel");
  assert.match(v.proof, /^[0-9a-f]{32}$/);

  const refuse = (rec, code, list = admins, req = request) => assert.throws(() => verifyApproval(rec, req, list), (e) => e instanceof ApprovalError && e.code === code);
  const other = ml_dsa87.keygen(random(32));
  refuse(approval({ request, account, dev, signer: other }), "bad_signature");
  refuse(approval({ request, account, dev: other }), "not_admin");
  refuse(approval({ request, account, dev }), "not_admin", []);
  refuse(approval({ request: { ...request, digest: "0".repeat(64) }, account, dev }), "wrong_digest");
  refuse(approval({ request, account, dev, tamper: { path: "/admin/requests/AAAAAAAAAAAA/approve" } }), "wrong_request");
  refuse(approval({ request, account, dev, tamper: { at: Date.now() - 10 * 60_000 } }), "stale");
  refuse(approval({ request, account, dev, tamper: { at: request.createdAt - 60_000 } }), "stale");
  refuse(approval({ request, account, dev }), "wrong_code", admins, { ...request, code: "W8EH9R67XA5H" });
  // a pinned phone with a secure chip must also carry the chip's signature
  refuse(approval({ request, account, dev }), "no_live_check", [{ ...admins[0], livePub: b64u(random(91)) }]);
});

test("enrolment: the keys come with the approval and must match the device id", () => {
  const dev = ml_dsa87.keygen(random(32));
  const account = "hid_" + "2".repeat(40);
  const request = { code: "W8EH9R67XA5G", kind: "enrol", createdAt: Date.now() - 1000, digest: "a".repeat(64) };
  const v = verifyApproval(approval({ request, account, dev }), request, []);
  assert.equal(v.enrolCheck, adminCheck(dev.publicKey));
  const other = ml_dsa87.keygen(random(32));
  assert.throws(() => verifyApproval(approval({ request, account, dev, tamper: { deviceDsaPk: b64u(other.publicKey) } }), request, []), (e) => e.code === "bad_record");
});

test("audit log: chained, and an edit anywhere is noticed when the console starts", () => {
  const root = tmp();
  const s = openStore(root);
  s.audit("console.started", { version: "1" });
  s.audit("request.created", { code: "A", action: "reboot" });
  s.audit("approval.verified", { code: "A" });
  assert.equal(s.auditState().count, 3);
  assert.equal(openStore(root).auditState().broken, null);
  assert.equal(s.recentAudit()[0].type, "approval.verified", "newest first");
  const f = join(root, "admin", "audit.jsonl");
  writeFileSync(f, readFileSync(f, "utf8").replace('"action":"reboot"', '"action":"backup"'));
  assert.match(openStore(root).auditState().broken, /line 3 doesn't follow/);
});

test("sign-in links: once only, and only before they expire", () => {
  const root = tmp();
  const s = openStore(root);
  const token = b64u(random(32));
  const file = join(root, "admin", "logins", `${createHash("sha256").update(token).digest("hex")}.json`);
  writeFileSync(file, JSON.stringify({ exp: Date.now() + 60_000 }));
  assert.equal(s.useLogin("short"), false);
  assert.equal(s.useLogin(token), true);
  assert.equal(existsSync(file), false);
  assert.equal(s.useLogin(token), false, "used");
  const old = b64u(random(32));
  writeFileSync(join(root, "admin", "logins", `${createHash("sha256").update(old).digest("hex")}.json`), JSON.stringify({ exp: Date.now() - 1 }));
  assert.equal(s.useLogin(old), false, "expired");
});

const release = (v, { digest = true, draft = false, name } = {}) => ({
  tag_name: `server-win-v${v}`, draft, name: `HumID Server for Windows ${v}`, published_at: "2026-10-17T00:00:00Z", body: "notes",
  assets: [{ id: Number(v.replaceAll(".", "")), name: name || `HumID-Server-Windows-${v}.zip`, size: 10, ...(digest ? { digest: `sha256:${createHash("sha256").update(`zip ${v}`).digest("hex")}` } : {}) }],
});
const fakeGitHub = (list, files = {}) => async (url, opts) => {
  if (url.endsWith("/releases?per_page=50")) return new Response(JSON.stringify(list), { status: 200 });
  const m = /assets\/(\d+)$/.exec(url);
  if (m && opts.headers.accept === "application/octet-stream") return new Response(files[m[1]] ?? "", { status: 200 });
  return new Response("{}", { status: 404 });
};

test("updates: only a newer server release is offered, never an app release or a draft", async () => {
  assert.equal(compareVersions("1.10.0", "1.9.9"), 1);
  assert.equal(compareVersions("1.6.0", "1.6.0"), 0);
  const list = [release("1.7.0", { draft: true }), release("1.6.2"), release("1.6.1"), { tag_name: "app-v9.0.0", assets: [] }, release("1.5.0")];
  const r = await latestRelease({ current: "1.6.0", fetchImpl: fakeGitHub(list) });
  assert.equal(r.version, "1.6.2");
  assert.match(r.asset.sha256, /^[0-9a-f]{64}$/);
  assert.equal(await latestRelease({ current: "1.6.2", fetchImpl: fakeGitHub(list) }), null);
  await assert.rejects(latestRelease({ current: "1.6.0", fetchImpl: async () => new Response("{}", { status: 404 }) }), /private/);
});

test("updates: the download must match GitHub's digest, or nothing is kept", async () => {
  const dir = tmp();
  const r = await latestRelease({ current: "1.6.0", fetchImpl: fakeGitHub([release("1.6.1")]) });
  const good = await download({ release: r, dir, fetchImpl: fakeGitHub([], { 161: "zip 1.6.1" }) });
  assert.equal(good.sha256, r.asset.sha256);
  assert.equal(readFileSync(good.file, "utf8"), "zip 1.6.1");
  const dir2 = tmp();
  await assert.rejects(download({ release: r, dir: dir2, fetchImpl: fakeGitHub([], { 161: "tampered" }) }), /doesn't match/);
  assert.equal(existsSync(join(dir2, "HumID-Server-Windows-1.6.1.zip")), false);
  const nodigest = await latestRelease({ current: "1.6.0", fetchImpl: fakeGitHub([release("1.6.1", { digest: false })]) });
  await assert.rejects(download({ release: nodigest, dir: tmp(), fetchImpl: fakeGitHub([]) }), /no SHA-256 digest/);
});

test("settings: the console's port can't be the one the tunnel forwards", () => {
  const ok = { HUMID_INTERNAL_SK: "a", HUMID_INTERNAL_PK: "b" };
  validate({ ...ok, HUMID_ADMIN_PORT: "8490" });
  assert.throws(() => validate({ ...ok, HUMID_PORT: "8480", HUMID_ADMIN_PORT: "8480" }), /tunnel/);
  assert.throws(() => validate({ ...ok, HUMID_ADMIN_PORT: "0" }), /HUMID_ADMIN_PORT/);
});
