// What the console asks Windows, and how it starts privileged work.
//
// Everything that touches Windows itself (disks, Defender, the firewall, BitLocker,
// Windows Update, the scheduled tasks, installing HumID) lives in humid.ps1, so it can
// be read in one place and run by hand. The console only:
//   probe()      runs `humid.ps1 probe`, which prints one JSON object
//   startJob()   starts the "HumID Admin Job" task, which runs `humid.ps1 job-run`:
//                every request in <root>\admin\jobs that has no result yet
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const JOB_TASK = "HumID Admin Job";

/** The job task's name for the install in `installDir`: a test instance's (instance.txt beside it) has its name in brackets, as humid.ps1 names it. */
export function jobTaskFor(installDir) {
  const f = join(installDir, "instance.txt");
  const name = existsSync(f) ? readFileSync(f, "utf8").split(/\r?\n/)[0].trim() : "";
  return /^[a-z][a-z0-9]{0,15}$/.test(name) ? `${JOB_TASK} (${name})` : JOB_TASK;
}

const run = (exe, args, timeoutMs) => new Promise((resolve, reject) => {
  execFile(exe, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
    if (err) return reject(Object.assign(err, { stderr: String(stderr || "").slice(0, 2000) }));
    resolve(String(stdout));
  });
});

export function windowsPlatform({ installDir }) {
  const ps1 = join(installDir, "humid.ps1");
  const powershell = join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const schtasks = join(process.env.SystemRoot || "C:\\Windows", "System32", "schtasks.exe");
  return {
    name: "windows",
    async probe() {
      const out = await run(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ps1, "probe"], 90_000);
      const line = out.split(/\r?\n/).reverse().find((l) => l.trim().startsWith("{"));
      if (!line) throw new Error("humid.ps1 probe printed nothing");
      return JSON.parse(line);
    },
    async startJob() {
      await run(schtasks, ["/Run", "/TN", jobTaskFor(installDir)], 30_000);
    },
  };
}
