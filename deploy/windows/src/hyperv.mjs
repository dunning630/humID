// The cell controller's Hyper-V driver (docs/CELLS.md): each step is one call to
// scripts\humid-cells.ps1, run by Windows PowerShell 5.1 as SYSTEM with fixed arguments.
// Ids, addresses and paths are checked here before they reach PowerShell, and they are passed
// as separate arguments (never through a shell), so nothing from a file can become a command.

import { execFile } from "node:child_process";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { CELL_ID } from "@humid/svc";
import { CELL_PORT, SUBNET } from "./cells.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const IP = new RegExp(`^${SUBNET.replace(/\./g, "\\.")}\\.(\\d{1,3})$`);

function ps(script, verb, args, { timeoutMs = 10 * 60_000 } = {}) {
  const exe = join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const argv = ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, verb];
  for (const [k, v] of Object.entries(args)) argv.push(`-${k}`, String(v));
  return new Promise((resolve, reject) => {
    execFile(exe, argv, { windowsHide: true, timeout: timeoutMs, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      const last = String(stdout).trim().split(/\r?\n/).pop() || "";
      let out = null;
      try { out = JSON.parse(last); } catch {}
      if (err || !out || out.ok !== true) return reject(new Error(out?.error || String(stderr).trim() || err?.message || "humid-cells.ps1 failed"));
      resolve(out);
    });
  });
}

/** root: the data root; script: humid-cells.ps1 (next to humid-server.mjs in the install). */
export function hyperV({ root, script = join(here, "humid-cells.ps1") }) {
  const vmDir = join(root, "cells", "vm");
  const id = (x) => { if (!CELL_ID.test(String(x))) throw new Error(`bad cell id ${x}`); return x; };
  return {
    async create({ id: cid, ip, seedDir, memoryMb, diskMb, image }) {
      const m = IP.exec(String(ip));
      if (!m || Number(m[1]) < 10 || Number(m[1]) > 250) throw new Error(`bad cell address ${ip}`);
      if (!isAbsolute(seedDir) || !isAbsolute(image)) throw new Error("seed and image paths must be absolute");
      await ps(script, "New-Cell", { Id: id(cid), Ip: ip, SeedDir: seedDir, MemoryMB: memoryMb, DiskMB: diskMb, Image: image, VmDir: vmDir });
      return { address: ip, port: CELL_PORT };
    },
    detachSeed: (cid) => ps(script, "Remove-Seed", { Id: id(cid), VmDir: vmDir }),
    remove: (cid) => ps(script, "Remove-Cell", { Id: id(cid), VmDir: vmDir }),
    freeMemoryMb: async () => (await ps(script, "Get-FreeMemory", {}, { timeoutMs: 60_000 })).freeMb,
    check: () => ps(script, "Test-Host", {}, { timeoutMs: 60_000 }),
    ensureSwitch: () => ps(script, "Install-Switch", {}, { timeoutMs: 120_000 }),
  };
}
