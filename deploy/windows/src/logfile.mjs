// Copy everything the services print to a log file, rotating at a fixed size.
// A scheduled task has no console, so this file is the only place logs go.
import { openSync, writeSync, closeSync, fstatSync, renameSync, existsSync, rmSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function teeToFile(file, { maxBytes = 10 * 1024 * 1024, keep = 5, quiet = false } = {}) {
  mkdirSync(dirname(file), { recursive: true });
  let fd = openSync(file, "a");
  let size = fstatSync(fd).size;

  const rotate = () => {
    closeSync(fd);
    rmSync(`${file}.${keep}`, { force: true });
    for (let i = keep - 1; i >= 1; i--) if (existsSync(`${file}.${i}`)) renameSync(`${file}.${i}`, `${file}.${i + 1}`);
    renameSync(file, `${file}.1`);
    fd = openSync(file, "a");
    size = 0;
  };

  const write = (chunk) => {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : Buffer.from(chunk.buffer ?? chunk, chunk.byteOffset ?? 0, chunk.byteLength ?? chunk.length);
    try {
      if (size + buf.length > maxBytes) rotate();
      writeSync(fd, buf);
      size += buf.length;
    } catch { /* a full disk must not take the server down */ }
  };

  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write.bind(stream);
    stream.write = (chunk, encoding, cb) => {
      write(typeof chunk === "string" && encoding && encoding !== "utf8" ? Buffer.from(chunk, encoding) : chunk);
      if (quiet) { if (typeof encoding === "function") encoding(); else if (typeof cb === "function") cb(); return true; }
      return original(chunk, encoding, cb);
    };
  }
  return { write };
}
