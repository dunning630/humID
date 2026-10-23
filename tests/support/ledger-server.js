// A vault server under an attacker's control, for the CRYPTO-01 tests: it holds the ledger
// signing key, so it can show the phone any self-consistent history it likes while the
// public log keeps another. Reached over real HTP/1, through the real @humid/api client.
import { GENESIS, entryHash, signHead, leafHash, checkpointMessage, treeHash, inclusionProof, consistencyProof } from "@humid/audit";
import { ml_dsa87, b64u, toHex, sha3_256, MEDIA_TYPE } from "@humid/htp";
import { HtpServer, createStatics } from "@humid/htp/server";
import { HumidApi } from "@humid/api";

export const histOwner = "hid_" + "cd".repeat(20);
export const histKey = ml_dsa87.keygen();
export const histLedgerKey = { dsa: b64u(histKey.publicKey), fp: toHex(sha3_256(histKey.publicKey)).slice(0, 32) };
export const ev = (type, detail = {}) => JSON.stringify({ at: "2026-10-22T10:00:00.000Z", type, detail });
export function chain(bodies) {
  const out = []; let prev = GENESIS;
  bodies.forEach((body, i) => { const hash = entryHash(histOwner, i + 1, prev, body); out.push({ seq: i + 1, body, prev, hash }); prev = hash; });
  return out;
}
export const pageOf = (entries) => {
  const h = entries.at(-1), signedAt = Date.now();
  return { owner: histOwner, entries, ledgerKey: histLedgerKey, head: h ? { seq: h.seq, hash: h.hash, signedAt, sig: signHead(histOwner, h.seq, h.hash, signedAt, histKey.secretKey) } : null };
};

/**
 * A vault server under the attacker's control, reached over real HTP/1: it serves `shown`
 * as the account's ledger and keeps `logged`, the honest chain, in the public log.
 */
export function maliciousServer({ shown, logged }) {
  const htp = new HtpServer(createStatics());
  const leaves = logged.map((e) => leafHash(histOwner, e.seq, e.hash));
  const get = (i) => leaves[i];
  const size = leaves.length, root = treeHash(get, 0, size), at = Date.now();
  const checkpoint = { size, root: toHex(root), at, sig: b64u(ml_dsa87.sign(checkpointMessage(size, root, at), histKey.secretKey)) };
  const routes = {
    "/ledger/events": (q) => {
      if (q.get("from")) { const from = Number(q.get("from")), to = Number(q.get("to")); return { owner: histOwner, entries: shown.all.filter((e) => e.seq >= from && e.seq <= to), ledgerKey: histLedgerKey }; }
      return pageOf(shown.page);
    },
    "/ledger/tlog/inclusion": (q) => {
      const e = q.get("seq") ? logged[Number(q.get("seq")) - 1] : logged.at(-1);
      if (!e) return null;
      return { checkpoint, cosignatures: [], ledgerKey: histLedgerKey, owner: histOwner, seq: e.seq, hash: e.hash, index: e.seq - 1, proof: inclusionProof(get, e.seq - 1, 0, size).map(toHex) };
    },
    "/ledger/tlog/consistency": (q) => ({ proof: consistencyProof(get, Number(q.get("from")), Number(q.get("to"))).map(toHex) }),
  };
  const fetch = async (url, init = {}) => {
    const path = new URL(url, "http://x").pathname;
    if (path === "/htp/v1/keys") return Response.json(htp.publicKeys());
    if (path === "/htp/v1/hello") return Response.json(htp.hello(JSON.parse(init.body)));
    const { session, seq, meta } = await htp.open(new Uint8Array(init.body));
    const u = new URL(meta.p, "http://x");
    const out = routes[u.pathname]?.(u.searchParams);
    const status = out ? 200 : 404;
    const body = new TextEncoder().encode(JSON.stringify(out || { error: "not_in_log" }));
    return new Response(await htp.seal(session, seq, status, { "content-type": "application/json" }, body), { headers: { "content-type": MEDIA_TYPE } });
  };
  return new HumidApi({ fetch });
}
