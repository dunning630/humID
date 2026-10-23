// The holder-cell controller (docs/CELLS.md). Runs as SYSTEM on the Hyper-V host
// (`humid-server.mjs cells run`, scheduled task "HumID Cells"); it listens on nothing.
//
// Every pass (reconcile) it:
//   1. reads the gateway's claims (data\gateway\cells.json): which cells belong to whom, and
//      which closed accounts' cells may go;
//   2. finishes cells it started: once a new cell answers over mutual TLS under its own name,
//      its seed disk (settings and certificate) is detached and deleted, and the cell is ready;
//   3. retires cells the gateway marked, but only after asking the cell itself, with a signed
//      request, and hearing that it holds nothing;
//   4. starts new cells until HUMID_CELLS_WARM are free, never past HUMID_CELLS_MAX and never
//      when the host's free memory would drop below HUMID_CELLS_RESERVE_MB;
//   5. writes the pool (cells\pool.json), the ready and unclaimed cells, for the gateway.
//
// Hyper-V itself is behind `hv` (hyperv.mjs on Windows; a stand-in in the tests), so this
// file decides and the driver only does.

import { existsSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { issueCellCert, clientTls, roleAgent, internalRequest, signRequest, writeAtomic } from "@humid/svc";

export const CELL_PORT = 8502;
export const SUBNET = "10.77.0";          // host 10.77.0.1, cells .10 to .250
export const START_TIMEOUT_MS = 10 * 60_000;
export const CELL_MEMORY_MB = 512;        // each cell's ceiling (dynamic memory starts at 256)

const newId = () => `c${randomBytes(8).toString("hex").slice(0, 11)}`; // 12 lowercase letters and digits

/**
 * root:      the data root (C:\ProgramData\HumID)
 * settings:  { warm, max, reserveMb, diskMb, image, quotaBytes }
 * keys:      { internalSk, internalPk, corePk, keysPk } (the internal key signs status probes)
 * ca:        { certPem, keyPem }, the server's CA (issues each cell's certificate)
 * front:     { cert, key } of humid-front, for mutual TLS to the cells
 * hv:        { create({ id, ip, seedDir, memoryMb, diskMb, image }) -> { address, port },
 *              detachSeed(id), remove(id), freeMemoryMb() }
 */
export function createController({ root, settings, keys, ca, front, hv, now = () => Date.now(), log = () => {} }) {
  // cells\pool.json: what the gateway (LOCAL SERVICE) reads. cells\private: the controller's own
  // state and the seeds (each holds a cell's private key until its first boot), SYSTEM and
  // Administrators only (`humid cells enable` sets that).
  const dir = join(root, "cells");
  const priv = join(dir, "private");
  mkdirSync(priv, { recursive: true });
  const stateFile = join(priv, "cells.json");
  const poolFile = join(dir, "pool.json");
  const claimsFile = join(root, "data", "gateway", "cells.json");

  /** id -> { id, ip, address, port, state: "starting" | "ready" | "bound" | "retired", startedAt, readyAt?, owner? } */
  let cells = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, "utf8")).cells || {} : {};
  const saveState = () => writeAtomic(stateFile, JSON.stringify({ v: 1, cells }, null, 1));

  const readClaims = () => {
    if (!existsSync(claimsFile)) return {};
    try { return JSON.parse(readFileSync(claimsFile, "utf8")).claims || {}; }
    catch (e) { throw new Error(`can't read the gateway's claims (${e.message}); changing nothing`); }
  };

  const agents = new Map();
  const agentFor = (id) => {
    if (!agents.has(id)) agents.set(id, roleAgent(clientTls({ ca: ca.certPem, cert: front.cert, key: front.key, expectCell: id })));
    return agents.get(id);
  };
  const base = (c) => `https://${c.address}:${c.port}`;
  async function healthy(c) {
    try { return (await internalRequest(`${base(c)}/healthz`, { agent: agentFor(c.id), timeoutMs: 5000 })).status === 200; }
    catch { return false; }
  }
  /** The cell's own count of what it stores (a signed request, as the gateway would make). */
  async function status(c) {
    const path = "/internal/cell/status";
    const r = await internalRequest(`${base(c)}${path}`, {
      agent: agentFor(c.id), timeoutMs: 10_000,
      headers: { "x-humid-assertion": signRequest(keys.internalSk, { aud: "vault", method: "GET", path, claims: { cellctl: true } }) },
    });
    if (r.status !== 200) throw new Error(`status ${r.status}`);
    return JSON.parse(Buffer.from(r.body).toString());
  }

  const usedIps = () => new Set(Object.values(cells).filter((c) => c.state !== "retired").map((c) => c.ip));
  const nextIp = () => {
    const used = usedIps();
    for (let i = 10; i <= 250; i++) if (!used.has(`${SUBNET}.${i}`)) return `${SUBNET}.${i}`;
    return null;
  };

  /** The seed: what a new cell reads at first boot, then never again (its copy lives on its data disk). */
  function writeSeed(id, ip) {
    const seedDir = join(priv, "seed", id);
    mkdirSync(seedDir, { recursive: true });
    const cert = issueCellCert(ca, id);
    writeAtomic(join(seedDir, "cell.json"), JSON.stringify({
      v: 1, id, ip, prefix: 24, host: `${SUBNET}.1`, port: CELL_PORT,
      internalPk: keys.internalPk, corePk: keys.corePk, keysPk: keys.keysPk, quotaBytes: settings.quotaBytes,
    }, null, 1));
    writeAtomic(join(seedDir, "ca.crt"), ca.certPem, 0o644);
    writeAtomic(join(seedDir, "cell.crt"), cert.certPem, 0o644);
    writeAtomic(join(seedDir, "cell.key"), cert.keyPem);
    return seedDir;
  }
  const dropSeed = (id) => rmSync(join(priv, "seed", id), { recursive: true, force: true });

  async function reconcile() {
    const report = { started: [], ready: [], retired: [], kept: [], failed: [] };
    const claims = readClaims();
    const byCell = new Map(Object.entries(claims).map(([sub, c]) => [c.cell, { sub, ...c }]));

    // 1. claims: a ready cell the gateway took is bound now
    for (const c of Object.values(cells)) {
      const cl = byCell.get(c.id);
      if (cl && c.state === "ready") { c.state = "bound"; c.owner = cl.sub; }
    }

    // 2. cells starting up
    for (const c of Object.values(cells).filter((x) => x.state === "starting")) {
      if (await healthy(c)) {
        let st;
        try { st = await status(c); } catch (e) { log("warn", "a new cell answers but not its status", { cell: c.id, err: e.message }); continue; }
        if (st.cell !== c.id || st.bound) { log("error", "a new cell isn't what it should be: removing it", { cell: c.id }); await hv.remove(c.id).catch(() => {}); dropSeed(c.id); c.state = "retired"; report.failed.push(c.id); continue; }
        await hv.detachSeed(c.id);
        dropSeed(c.id);
        c.state = "ready"; c.readyAt = new Date(now()).toISOString();
        report.ready.push(c.id);
      } else if (now() - Date.parse(c.startedAt) > START_TIMEOUT_MS) {
        log("error", "a cell didn't come up in time: removing it", { cell: c.id });
        await hv.remove(c.id).catch((e) => log("error", "couldn't remove it", { cell: c.id, err: e.message }));
        dropSeed(c.id);
        c.state = "retired";
        report.failed.push(c.id);
      }
    }

    // 3. retirement, only of a cell that says it is empty
    for (const [cellId, cl] of byCell) {
      if (cl.state !== "retire") continue;
      const c = cells[cellId];
      if (!c || c.state === "retired") continue;
      let st;
      try { st = await status(c); } catch (e) { log("warn", "a cell to retire didn't answer; trying again next pass", { cell: cellId, err: e.message }); report.kept.push(cellId); continue; }
      if (st.total !== 0) { log("warn", "a cell marked for retirement still holds documents: kept", { cell: cellId, count: st.total }); report.kept.push(cellId); continue; }
      await hv.remove(cellId);
      c.state = "retired"; c.retiredAt = new Date(now()).toISOString();
      report.retired.push(cellId);
    }

    // 4. top the pool up
    const alive = Object.values(cells).filter((c) => c.state !== "retired");
    const free = alive.filter((c) => (c.state === "ready" && !byCell.has(c.id)) || c.state === "starting").length;
    let want = Math.min(settings.warm - free, settings.max - alive.length);
    while (want-- > 0) {
      const freeMb = await hv.freeMemoryMb();
      if (freeMb - CELL_MEMORY_MB < settings.reserveMb) { log("warn", "not starting a cell: memory would drop below the reserve", { freeMb, reserveMb: settings.reserveMb }); break; }
      const ip = nextIp();
      if (!ip) { log("warn", "no addresses left on the cells network"); break; }
      const id = newId();
      const seedDir = writeSeed(id, ip);
      try {
        const at = await hv.create({ id, ip, seedDir, memoryMb: CELL_MEMORY_MB, diskMb: settings.diskMb, image: settings.image });
        cells[id] = { id, ip, address: at.address, port: at.port, state: "starting", startedAt: new Date(now()).toISOString() };
        report.started.push(id);
      } catch (e) {
        log("error", "couldn't start a cell", { err: e.message });
        await hv.remove(id).catch(() => {});
        dropSeed(id);
        break;
      }
      saveState(); // a crash between cells mustn't lose one
    }

    saveState();
    // 5. the pool the gateway reads: ready cells nobody has claimed
    const pool = Object.values(cells).filter((c) => c.state === "ready" && !byCell.has(c.id)).map((c) => ({ id: c.id, address: c.address, port: c.port, state: "ready" }));
    writeAtomic(poolFile, JSON.stringify({ v: 1, updatedAt: new Date(now()).toISOString(), cells: pool }, null, 1), 0o644);
    return report;
  }

  return {
    reconcile,
    cells: () => ({ ...cells }),
    summary() {
      const all = Object.values(cells), claims = (() => { try { return readClaims(); } catch { return {}; } })();
      const by = (s) => all.filter((c) => c.state === s).length;
      return { starting: by("starting"), ready: by("ready"), bound: by("bound"), retired: by("retired"), retiring: Object.values(claims).filter((c) => c.state === "retire").length, max: settings.max, warm: settings.warm };
    },
    poolFile, stateFile,
  };
}
