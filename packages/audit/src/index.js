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
