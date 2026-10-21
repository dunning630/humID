// What a breached or malicious server can't make the phone believe (pre-certification
// audit, October 2026): a document signed by anyone but the account (PC-03), and a history
// signed by a ledger key or "cosigners" the server picked for itself (PC-04). Each case is
// the audit's own proof of concept, now refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suite, splitWrap, splitUnwrap, isSplit } from "@humid/crypto";
import { GENESIS, entryHash, signHead, leafHash, checkpointMessage, cosignMessage, verifyLedger, verifyCheckpoint, parseCosigners } from "@humid/audit";
import { ml_dsa87, b64u, toHex, sha3_256 } from "@humid/htp";

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
