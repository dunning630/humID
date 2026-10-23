// What a breached or malicious server can't make the phone believe (pre-certification
// audit, October 2026): a document signed by anyone but the account (PC-03), a history
// signed by a ledger key or "cosigners" the server picked for itself (PC-04), and a history
// shown to the phone that isn't the one in the public log (CRYPTO-01). Each case is the
// audit's own proof of concept, now refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suite, splitWrap, splitUnwrap, isSplit } from "@humid/crypto";
import { GENESIS, entryHash, signHead, leafHash, checkpointMessage, cosignMessage, verifyLedger, verifyCheckpoint, parseCosigners } from "@humid/audit";
import { ml_dsa87, b64u, toHex, sha3_256 } from "@humid/htp";
import { histLedgerKey, ev, chain, pageOf, maliciousServer } from "./support/ledger-server.js";

const S = suite();
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const victim = S.deriveKeys(rnd(64));
const attacker = S.deriveKeys(rnd(64));
const recipient = { kemPk: victim.kemPk, xPk: victim.xPk }; // public: every server holds these

test("PC-03: a document the server sealed and signed itself doesn't open as the holder's own", async () => {
  const { file, share } = await splitWrap({ bytes: new TextEncoder().encode("I leave everything to Mallory."), name: "Last will.txt", type: "text/plain" });
  const { envelope } = await S.seal(file, attacker, recipient, { identityCommit: "00".repeat(32), interrupt: { method: "ios-keychain-biometry" } });
  // Before the fix this opened: the signature checks out against the key inside the envelope.
  const unchecked = await S.open(envelope, victim);
  assert.ok(isSplit(unchecked.meta));
  // The vault's read path names the account key as the only acceptable signer.
  await assert.rejects(S.open(envelope, victim, { signer: victim.dsaPk }), (e) => e.code === "wrong_signer");
  // The holder's own documents still open.
  const { envelope: real } = await S.seal(file, victim, recipient, { identityCommit: "00".repeat(32), interrupt: { method: "ios-keychain-biometry" } });
  const out = await S.open(real, victim, { signer: victim.dsaPk });
  assert.equal(new TextDecoder().decode((await splitUnwrap(out.bytes, share)).bytes), "I leave everything to Mallory.");
});

/** A self-consistent ledger page and one-leaf public log, all under keys the server made. */
function forgedHistory() {
  const owner = "hid_" + "ab".repeat(20);
  const lk = ml_dsa87.keygen(), c1 = ml_dsa87.keygen(), c2 = ml_dsa87.keygen();
  const ledgerKey = { dsa: b64u(lk.publicKey), fp: toHex(sha3_256(lk.publicKey)).slice(0, 32) };
  const body = JSON.stringify({ type: "session.opened", at: "2026-10-20T00:00:00Z", detail: {} });
  const hash = entryHash(owner, 1, GENESIS, body);
  const signedAt = Date.now();
  const page = { owner, entries: [{ seq: 1, prev: GENESIS, body, hash }], head: { seq: 1, hash, signedAt, sig: signHead(owner, 1, hash, signedAt, lk.secretKey) }, ledgerKey };
  const root = leafHash(owner, 1, hash), at = Date.now();
  const checkpoint = { size: 1, root: toHex(root), at, sig: b64u(ml_dsa87.sign(checkpointMessage(1, root, at), lk.secretKey)) };
  const cosignatures = [["Electronic Frontier Foundation", c1], ["Let's Encrypt", c2]].map(([name, k]) => ({ name, pk: b64u(k.publicKey), sig: b64u(ml_dsa87.sign(cosignMessage(name, 1, root, at), k.secretKey)) }));
  return { owner, hash, page, inc: { checkpoint, cosignatures, ledgerKey, owner, seq: 1, hash, index: 0, proof: [] }, c1 };
}

test("PC-04: a history under a ledger key other than the one the phone pinned is refused", () => {
  const f = forgedHistory();
  const pinned = toHex(sha3_256(ml_dsa87.keygen().publicKey)).slice(0, 32); // the real server's key, seen first
  assert.equal(verifyLedger(f.page, { expectedOwner: f.owner }).ok, true, "self-consistent on its own");
  const l = verifyLedger(f.page, { expectedOwner: f.owner, trustedKeyFp: pinned });
  assert.equal(l.ok, false);
  assert.match(l.reason, /Ledger key changed/);
  const c = verifyCheckpoint(f.inc, { trustedKeyFp: pinned, inclusion: { owner: f.owner, seq: 1, hash: f.hash, index: 0, proof: [] } });
  assert.equal(c.ok, false);
});

test("PC-04: cosigners the server names and signs for itself count for nothing", () => {
  const f = forgedHistory();
  const inclusion = { owner: f.owner, seq: 1, hash: f.hash, index: 0, proof: [] };
  assert.deepEqual(verifyCheckpoint(f.inc, { inclusion }).cosigned, [], "no built-in list: nothing counts");
  const real = ml_dsa87.keygen();
  const builtIn = parseCosigners(`Electronic Frontier Foundation=${b64u(real.publicKey)}`.replace(/ /g, "-"));
  assert.deepEqual(verifyCheckpoint(f.inc, { inclusion, cosigners: builtIn }).cosigned, [], "a name the app doesn't know, or the right name with the wrong key");
  const same = new Map([["Electronic Frontier Foundation", real.publicKey]]);
  assert.deepEqual(verifyCheckpoint(f.inc, { inclusion, cosigners: same }).cosigned, [], "the server's key for a known name is ignored");
  // A genuine cosignature by a built-in cosigner counts.
  const trusted = new Map([["Electronic Frontier Foundation", f.c1.publicKey]]);
  assert.deepEqual(verifyCheckpoint(f.inc, { inclusion, cosigners: trusted }).cosigned, ["Electronic Frontier Foundation"]);
});

test("parseCosigners reads the server's HUMID_TLOG_COSIGNERS form and skips anything malformed", () => {
  const k = ml_dsa87.keygen().publicKey;
  const m = parseCosigners(`eu-witness=${b64u(k)}, bad name=${b64u(k)},=x,nokey=`);
  assert.deepEqual([...m.keys()], ["eu-witness"]);
  assert.deepEqual(m.get("eu-witness"), k);
});

/* ---------------- CRYPTO-01: the page and the public log must describe one history ---------------- */

const honest = chain([ev("identity.created"), ev("device.added", { device: "dev_attacker", via: "card" }), ev("object.opened", { id: "will" })]);

test("CRYPTO-01: a ledger page with an event removed no longer passes as 'Published in the public log'", async () => {
  // the audit's PoC: the attacker's device.added is gone from what the phone is shown, chain rebuilt, head re-signed
  const doctored = chain([ev("identity.created"), ev("object.opened", { id: "will" })]);
  const api = maliciousServer({ shown: { page: doctored, all: doctored }, logged: honest });
  const l = await api.ledger({ trustedKeyFp: histLedgerKey.fp });
  assert.equal(l.ok, true, "the page is self-consistent: that alone proves nothing");
  // Before the fix the phone asked for "the latest entry" and got the honest one: ok.
  const before = await api.continuity({ trustedKeyFp: histLedgerKey.fp });
  assert.equal(before.ok, true);
  assert.notEqual(before.hash, l.head.hash, "...about a different history");
  // Now it asks about the head it was shown, and the log holds something else there.
  const c = await api.continuity({ trustedKeyFp: histLedgerKey.fp, head: l.head });
  assert.equal(c.ok, false);
  assert.equal(c.mismatch, true);
  assert.match(c.reason, /doesn't match the public log at entry 2/);
});

test("CRYPTO-01: the honest page and the log agree", async () => {
  const api = maliciousServer({ shown: { page: honest, all: honest }, logged: honest });
  const l = await api.ledger({ trustedKeyFp: histLedgerKey.fp });
  const c = await api.continuity({ trustedKeyFp: histLedgerKey.fp, head: l.head });
  assert.equal(c.ok, true, c.reason);
  assert.deepEqual([c.seq, c.hash], [l.head.seq, l.head.hash]);
});

test("CRYPTO-01: a page that drops or rewrites the head this phone saw last time is refused", async () => {
  const seen = { seq: 3, hash: honest[2].hash };
  // truncated: entries after seq 1 gone (the server rolled the account back)
  assert.match(verifyLedger(pageOf(honest.slice(0, 1)), { trustedKeyFp: histLedgerKey.fp, previousHead: seen }).reason, /got shorter/);
  assert.match(verifyLedger(pageOf([]), { previousHead: seen }).reason, /got shorter/);
  // rewritten: same length and more, but entry 3 isn't the one this phone verified
  const forked = chain([ev("identity.created"), ev("device.added", { device: "dev_attacker", via: "card" }), ev("session.opened"), ev("session.closed")]);
  assert.match(verifyLedger(pageOf(forked), { previousHead: seen }).reason, /Entry 3 changed/);
  // an honest page that grew is fine
  const grown = chain([...honest.map((e) => e.body), ev("session.closed")]);
  const ok = verifyLedger(pageOf(grown), { previousHead: seen });
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.previousHeadOnPage, true);
});

test("CRYPTO-01: when the page starts after the head seen last time, the entries in between must link back to it", async () => {
  const long = chain([...honest.map((e) => e.body), ...Array.from({ length: 6 }, () => ev("session.opened"))]); // 9 entries
  const seen = { seq: 3, hash: honest[2].hash };
  // honest server: a page of the last 4, and the entries 3..5 on request
  const good = maliciousServer({ shown: { page: long.slice(-4), all: long }, logged: long });
  const l = await good.ledger({ trustedKeyFp: histLedgerKey.fp, previousHead: seen });
  assert.equal(l.ok, true, l.reason);
  // a server that rewrote entry 3 (and everything after) can't link its page to it
  const forked = chain([ev("identity.created"), ev("session.opened"), ...Array.from({ length: 7 }, () => ev("session.opened"))]);
  const bad = maliciousServer({ shown: { page: forked.slice(-4), all: forked }, logged: long });
  const r = await bad.ledger({ trustedKeyFp: histLedgerKey.fp, previousHead: seen });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no longer contains entry 3/);
});
