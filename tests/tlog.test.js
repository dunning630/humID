// The public transparency log: RFC 6962 inclusion and consistency proofs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { leafHash, treeHash, inclusionProof, consistencyProof, verifyInclusion, verifyConsistency } from "@humid/audit";
import { sha3_256, toHex } from "@humid/htp";

const leaves = Array.from({ length: 37 }, (_, i) => leafHash("hid_" + String(i).padStart(40, "0"), i + 1, toHex(sha3_256(new Uint8Array([i]))).padEnd(64, "0")));
const get = (i) => leaves[i];

test("every leaf of every tree size has a valid inclusion proof, and a wrong leaf fails", () => {
  for (let n = 1; n <= leaves.length; n++) {
    const root = treeHash(get, 0, n);
    for (let m = 0; m < n; m++) {
      const p = inclusionProof(get, m, 0, n);
      assert.ok(verifyInclusion(leaves[m], m, n, p, root), `leaf ${m} of ${n}`);
      assert.equal(verifyInclusion(leaves[(m + 1) % leaves.length], m, n, p, root), n === 1 && leaves.length === 1);
    }
  }
});

test("every pair of tree sizes has a valid consistency proof; a rewritten past fails", () => {
  for (let n = 1; n <= leaves.length; n++) {
    for (let m = 1; m <= n; m++) {
      const p = consistencyProof(get, m, n);
      assert.ok(verifyConsistency(m, treeHash(get, 0, m), n, treeHash(get, 0, n), p), `${m} -> ${n}`);
    }
  }
  const forged = [...leaves]; forged[3] = leafHash("hid_" + "f".repeat(40), 1, "0".repeat(64));
  const fget = (i) => forged[i];
  const p = consistencyProof(fget, 10, 20);
  assert.equal(verifyConsistency(10, treeHash(get, 0, 10), 20, treeHash(fget, 0, 20), p), false);
});
