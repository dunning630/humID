// Holder cells, the gateway's side (docs/CELLS.md).
//
// The cell controller (SYSTEM, on the Hyper-V host) keeps a pool of booted, unbound cells and
// writes it to a file this process can read but not change. When an account is created the
// gateway takes one ready cell, binds it to the account (the cell writes that down and refuses
// any other account from then on), and records the claim in its own data folder, which the
// controller reads to refill the pool and, after an account is closed, to retire its cell.
//
// The gateway never creates or removes a VM. Every call to a cell is mutual TLS with the
// server's own CA, accepted only under the exact name humid-cell-<id> the pool gives for it.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { CELL_ID, clientTls, roleAgent, writeAtomic } from "@humid/svc";

const ACCOUNT_ID = /^hid_[0-9a-f]{40}$/;
const ADDRESS = /^(?:\d{1,3}\.){3}\d{1,3}$|^[a-z0-9.-]{1,253}$/i;

/** One pool entry from the controller, checked: { id, url } or null. */
export function poolEntry(e, { allowPlain = false } = {}) {
  if (!e || typeof e !== "object" || e.state !== "ready") return null;
  if (!CELL_ID.test(String(e.id))) return null;
  if (allowPlain && typeof e.url === "string" && /^http:\/\/127\.0\.0\.1:\d+$/.test(e.url)) return { id: e.id, url: e.url };
  const port = Number(e.port);
  if (!ADDRESS.test(String(e.address || "")) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { id: e.id, url: `https://${e.address}:${port}` };
}

/**
 * poolFile:   the controller's pool (JSON: { cells: [{ id, address, port, state }] })
 * dataDir:    the gateway's data folder; claims go to cells.json there
 * tls:        { ca, cert, key } of humid-front, for mutual TLS to the cells
 * allowPlain: tests only (cells on loopback HTTP); never read from settings
 */
export function createCells({ poolFile, dataDir, tls = null, allowPlain = false, log = console }) {
  if (!allowPlain && !tls) throw new Error("Holder cells need this gateway's humid-front certificate (humid pki init)");
  const claimsFile = join(dataDir, "cells.json");
  /** sub -> { cell, url, at, state: "bound" | "retire" } */
  let claims = {};
  if (existsSync(claimsFile)) {
    try { claims = JSON.parse(readFileSync(claimsFile, "utf8")).claims || {}; }
    catch (e) { throw new Error(`${claimsFile} can't be read (${e.message}); holders' cells would be lost, so the gateway won't start`); }
  }
  const save = () => writeAtomic(claimsFile, JSON.stringify({ v: 1, updatedAt: new Date().toISOString(), claims }, null, 1), 0o644);

  const agents = new Map();
  const agentFor = (id, url) => {
    if (url.startsWith("http:")) return undefined;
    if (!agents.has(id)) agents.set(id, roleAgent(clientTls({ ...tls, expectCell: id })));
    return agents.get(id);
  };

  let pool = { mtime: 0, cells: [] };
  const readPool = () => {
    try {
      const m = statSync(poolFile).mtimeMs;
      if (m !== pool.mtime) {
        const raw = JSON.parse(readFileSync(poolFile, "utf8"));
        pool = { mtime: m, cells: (Array.isArray(raw.cells) ? raw.cells : []).map((e) => poolEntry(e, { allowPlain })).filter(Boolean) };
      }
    } catch { pool = { mtime: 0, cells: [] }; }
    return pool.cells;
  };
  const taken = () => new Set(Object.values(claims).map((c) => c.cell));
  const pending = new Set(); // cells being bound right now

  return {
    /** Where this account's vault calls go: { id, url, agent }, or null for the shared vault. */
    forSub(sub) {
      const c = claims[sub];
      return c ? { id: c.cell, url: c.url, agent: agentFor(c.cell, c.url) } : null;
    },

    /**
     * Give a new account a cell from the pool. bind({ url, agent }) makes the cell's bind call
     * and resolves to true when the cell accepted. Returns the cell id, or null when no cell
     * could be had (the account then uses the shared vault).
     */
    async claim(sub, bind) {
      if (!ACCOUNT_ID.test(sub)) throw new Error("not an account id");
      if (claims[sub]) return claims[sub].cell;
      const busy = taken();
      for (const e of readPool().filter((x) => !busy.has(x.id) && !pending.has(x.id)).slice(0, 3)) {
        pending.add(e.id);
        try {
          const ok = await bind({ url: e.url, agent: agentFor(e.id, e.url), id: e.id }).catch(() => false);
          if (!ok) { log.warn?.("a pool cell refused binding", { cell: e.id }); continue; }
          claims[sub] = { cell: e.id, url: e.url, at: new Date().toISOString(), state: "bound" };
          save();
          return e.id;
        } finally { pending.delete(e.id); }
      }
      log.warn?.("no holder cell free: this account uses the shared vault", { warm: readPool().length });
      return null;
    },

    /** The account is closed and its vault erased: the controller may remove its cell once the cell says it's empty. */
    retire(sub) {
      if (!claims[sub] || claims[sub].state === "retire") return false;
      claims[sub] = { ...claims[sub], state: "retire", retireAt: new Date().toISOString() };
      save();
      return true;
    },

    /** Counts for status: cells bound, cells being retired, and warm cells free. */
    stats() {
      const all = Object.values(claims);
      const busy = taken();
      return { bound: all.filter((c) => c.state === "bound").length, retiring: all.filter((c) => c.state === "retire").length, warm: readPool().filter((x) => !busy.has(x.id)).length };
    },
    claimsFile,
  };
}
