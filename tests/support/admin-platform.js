// A stand-in for Windows in the admin console tests: what `humid.ps1 probe` would
// print, and a job runner that does what `humid.ps1 job-run` would do with the job
// files (without touching the computer it runs on).
import { readdirSync, existsSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

export function fakeWindows(root, { onJob = () => ({}), probe = {} } = {}) {
  const jobsDir = join(root, "admin", "jobs");
  const ran = [];
  const platform = {
    name: "test",
    async probe() {
      return {
        computer: "TEST-PC", os: { caption: "Microsoft Windows 11 Pro", version: "10.0.26100", build: "26100" }, lastBoot: new Date(Date.now() - 86400000).toISOString(),
        disks: [{ drive: "C:", label: "Windows", sizeBytes: 512 * 2 ** 30, freeBytes: 200 * 2 ** 30 }],
        defender: { available: true, antivirus: true, realtime: true, signatureAgeDays: 0, signatureVersion: "1.421.0.0" },
        firewall: [{ profile: "Domain", enabled: true }, { profile: "Private", enabled: true }, { profile: "Public", enabled: true }],
        bitlocker: { drive: "C:", status: "on" }, pendingReboot: false, pendingRebootReasons: [],
        tasks: [{ name: "HumID Server", state: "Running", lastResult: 267009 }, { name: "HumID Admin", state: "Running", lastResult: 267009 }, { name: "HumID Admin Job", state: "Ready", lastResult: 0 }],
        installed: { version: "1.5.0" }, previous: null,
        ...probe,
      };
    },
    async startJob() {
      for (const f of readdirSync(jobsDir).filter((x) => x.endsWith(".request.json")).sort()) {
        const id = f.slice(0, -".request.json".length);
        const out = join(jobsDir, `${id}.json`);
        if (existsSync(out)) continue;
        const req = JSON.parse(readFileSync(join(jobsDir, f), "utf8"));
        ran.push(req);
        const extra = (await onJob(req)) || {};
        writeFileSync(out, JSON.stringify({ id, state: "done", steps: [{ t: new Date().toISOString(), msg: `ran ${req.type}` }], finishedAt: new Date().toISOString(), ...extra }));
      }
    },
  };
  return { platform, ran };
}
