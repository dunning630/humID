// @humid/audit — the ledger's hash-chain format. The ledger service writes
// with it and the app verifies with it, so "tamper-evident" is something the
// holder can check on their own phone, not a promise.

import { ml_dsa87, sha3_256, toHex, fromHex, concat, utf8, b64u, unb64u } from "@humid/htp";

export const GENESIS = "0".repeat(64);

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
const lp = (...parts) => concat(...parts.flatMap((p) => [u32(p.length), p]));

export const entryHash = (owner, seq, prev, body) =>
  toHex(sha3_256(lp(utf8("HUMID-LEDGER-v1"), utf8(owner), u64(seq), fromHex(prev), utf8(body))));

export const headMessage = (owner, seq, hash, signedAt) =>
  lp(utf8("HUMID-LEDGER-HEAD-v1"), utf8(owner), u64(seq), fromHex(hash), u64(signedAt));

export const signHead = (owner, seq, hash, signedAt, sk) => b64u(ml_dsa87.sign(headMessage(owner, seq, hash, signedAt), sk));

/**
 * Verify a ledger page. Returns { ok, reason, entries } where entries are parsed.
 * Checks every link, every hash, contiguous sequence numbers, and the head signature.
 * A page that starts after seq 1 is verified from its first entry onward.
 */
export function verifyLedger(page, { expectedOwner, trustedKeyFp } = {}) {
  const fail = (reason) => ({ ok: false, reason, entries: [] });
  if (!page || !Array.isArray(page.entries)) return fail("No ledger data");
  if (expectedOwner && page.owner !== expectedOwner) return fail("Ledger belongs to someone else");
  const keyFp = toHex(sha3_256(unb64u(page.ledgerKey.dsa))).slice(0, 32);
  if (keyFp !== page.ledgerKey.fp) return fail("Ledger key fingerprint mismatch");
  if (trustedKeyFp && keyFp !== trustedKeyFp) return fail("Ledger key changed since last check");
  const out = [];
  let prev = null;
  for (const e of page.entries) {
    if (prev && (e.seq !== prev.seq + 1 || e.prev !== prev.hash)) return fail(`Chain broken at entry ${e.seq}`);
    if (!prev && e.seq === 1 && e.prev !== GENESIS) return fail("First entry does not start the chain");
    if (entryHash(page.owner, e.seq, e.prev, e.body) !== e.hash) return fail(`Entry ${e.seq} was altered`);
    out.push({ seq: e.seq, hash: e.hash, ...JSON.parse(e.body) });
    prev = e;
  }
  if (!prev) return { ok: true, reason: "Empty", entries: [], keyFp };
  const h = page.head;
  if (!h || h.seq !== prev.seq || h.hash !== prev.hash) return fail("Head does not match the latest entry");
  let sigOk = false;
  try { sigOk = ml_dsa87.verify(unb64u(h.sig), headMessage(page.owner, h.seq, h.hash, h.signedAt), unb64u(page.ledgerKey.dsa)); } catch {}
  if (!sigOk) return fail("Head signature is invalid");
  return { ok: true, reason: "Verified", entries: out, keyFp, head: h };
}

/* ---------------- public transparency log ----------------
 * Every ledger entry of every account also becomes one leaf of a single,
 * append-only Merkle tree (RFC 6962 / Certificate Transparency shape, SHA3-256).
 * The ledger signs checkpoints {size, root}; independent cosigners can check
 * that each checkpoint extends the last one and sign it too. A phone checks:
 *   inclusion    its own latest ledger entry is in the published tree;
 *   consistency  the tree it sees now extends the one it saw last time.
 * So the server can't show one history to you and another to everyone else,
 * or quietly rewrite the past, without leaving a provable fork.
 */

const leafPrefix = new Uint8Array([0]);
const nodePrefix = new Uint8Array([1]);

/** The leaf for one ledger entry. */
export const leafHash = (owner, seq, hash) => sha3_256(concat(leafPrefix, lp(utf8("HUMID-TLOG-v1"), utf8(owner), u64(seq), fromHex(hash))));
export const nodeHash = (l, r) => sha3_256(concat(nodePrefix, l, r));
export const EMPTY_ROOT = sha3_256(new Uint8Array(0));

const largestPow2Below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** Merkle tree hash of leaves[lo, hi), using get(i) for leaf i. Reference implementation. */
export function treeHash(get, lo, hi) {
  const n = hi - lo;
  if (n === 0) return EMPTY_ROOT;
  if (n === 1) return get(lo);
  const k = largestPow2Below(n);
  return nodeHash(treeHash(get, lo, lo + k), treeHash(get, lo + k, hi));
}

export const checkpointMessage = (size, root, at, label = "HUMID-TLOG-CHECKPOINT-v1") => lp(utf8(label), u64(size), root, u64(at));
export const cosignMessage = (name, size, root, at) => checkpointMessage(size, root, at, `HUMID-TLOG-COSIGN-v1 ${name}`);

/** RFC 6962 inclusion proof check: is leaf `index` (of `size`) with this hash under `root`? */
export function verifyInclusion(leaf, index, size, proof, root) {
  if (!(index >= 0 && index < size)) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else r = nodeHash(r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(r, root);
}

/** RFC 6962 consistency proof check: does the tree (size2, root2) extend (size1, root1)? */
export function verifyConsistency(size1, root1, size2, root2, proof) {
  if (size1 > size2) return false;
  if (size1 === size2) return proof.length === 0 && equalBytes(root1, root2);
  if (size1 === 0) return proof.length === 0;
  let path = [...proof];
  if (isPow2(size1)) path = [root1, ...path];
  let fn = size1 - 1, sn = size2 - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  if (!path.length) return false;
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else sr = nodeHash(sr, c);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && equalBytes(fr, root1) && equalBytes(sr, root2);
}

const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;
const equalBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Inclusion proof for leaf m in leaves[lo, hi) (RFC 6962 PATH). */
export function inclusionProof(get, m, lo, hi, th = (a, b) => treeHash(get, a, b)) {
  const n = hi - lo;
  if (n <= 1) return [];
  const k = largestPow2Below(n);
  if (m < k) return [...inclusionProof(get, m, lo, lo + k, th), th(lo + k, hi)];
  return [...inclusionProof(get, m - k, lo + k, hi, th), th(lo, lo + k)];
}

/** Consistency proof between the first m leaves and all n leaves (RFC 6962 PROOF). */
export function consistencyProof(get, m, n, th = (a, b) => treeHash(get, a, b)) {
  const sub = (m, lo, hi, complete) => {
    const n = hi - lo;
    if (m === n) return complete ? [] : [th(lo, hi)];
    const k = largestPow2Below(n);
    if (m <= k) return [...sub(m, lo, lo + k, complete), th(lo + k, hi)];
    return [...sub(m - k, lo + k, hi, false), th(lo, lo + k)];
  };
  if (m === 0 || m === n) return [];
  return sub(m, 0, n, true);
}

/**
 * Check a signed checkpoint, its cosignatures and (optionally) that it extends
 * the last checkpoint this device trusted. Returns { ok, reason, size, cosigned }.
 * page: { checkpoint: { size, root, at, sig }, ledgerKey: { dsa, fp }, cosignatures: [{ name, pk, sig }] }
 */
export function verifyCheckpoint(page, { trustedKeyFp, previous, consistency, inclusion } = {}) {
  const fail = (reason) => ({ ok: false, reason });
  const cp = page?.checkpoint;
  if (!cp) return fail("No published checkpoint");
  const pk = unb64u(page.ledgerKey.dsa);
  const keyFp = toHex(sha3_256(pk)).slice(0, 32);
  if (trustedKeyFp && keyFp !== trustedKeyFp) return fail("Ledger key changed since last check");
  const root = fromHex(cp.root);
  let ok = false;
  try { ok = ml_dsa87.verify(unb64u(cp.sig), checkpointMessage(cp.size, root, cp.at), pk); } catch {}
  if (!ok) return fail("Checkpoint signature is invalid");
  const cosigned = [];
  for (const c of page.cosignatures || []) {
    try { if (ml_dsa87.verify(unb64u(c.sig), cosignMessage(c.name, cp.size, root, cp.at), unb64u(c.pk))) cosigned.push(c.name); } catch {}
  }
  if (previous && previous.size > 0) {
    if (cp.size < previous.size) return fail("The public log got shorter");
    if (!consistency || !verifyConsistency(previous.size, fromHex(previous.root), cp.size, root, consistency.map(fromHex))) {
      return fail("The public log doesn't extend the one this device saw before");
    }
  }
  if (inclusion) {
    const { owner, seq, hash, index, proof } = inclusion;
    if (!verifyInclusion(leafHash(owner, seq, hash), index, cp.size, proof.map(fromHex), root)) return fail("Your latest entry isn't in the public log");
  }
  return { ok: true, reason: "Verified", size: cp.size, root: cp.root, at: cp.at, cosigned, keyFp };
}
