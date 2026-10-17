// Node file-system adapters: a folder (or USB drive) as the store, a folder
// tree as the source, and a folder as the restore target. Desktop only; the
// app and services import "@humid/backup", never this file.

import { open, readdir, lstat, readlink, mkdir, readFile, writeFile, rename, rm, symlink as mkSymlink, chmod, utimes } from "node:fs/promises";
import { join, dirname, relative, sep, resolve } from "node:path";

const toPosix = (p) => p.split(sep).join("/");

/** A folder as a repository store. Writes are atomic (temp file + rename). */
export function dirStore(root) {
  const abs = (name) => {
    const p = resolve(root, ...name.split("/"));
    if (!p.startsWith(resolve(root) + sep)) throw new Error("Store name escapes the backup folder.");
    return p;
  };
  return {
    root,
    async put(name, bytes) {
      const p = abs(name);
      await mkdir(dirname(p), { recursive: true });
      const tmp = `${p}.${process.pid}.tmp`;
      await writeFile(tmp, bytes);
      await rename(tmp, p);
    },
    async get(name) {
      try { return new Uint8Array(await readFile(abs(name))); }
      catch (e) { if (e.code === "ENOENT") return null; throw e; }
    },
    async has(name) {
      try { await lstat(abs(name)); return true; }
      catch (e) { if (e.code === "ENOENT") return false; throw e; }
    },
    async list(prefix = "") {
      const out = [];
      const walk = async (dir) => {
        let items;
        try { items = await readdir(dir, { withFileTypes: true }); } catch (e) { if (e.code === "ENOENT") return; throw e; }
        for (const it of items) {
          const p = join(dir, it.name);
          if (it.isDirectory()) await walk(p);
          else if (!it.name.endsWith(".tmp")) out.push(toPosix(relative(root, p)));
        }
      };
      await walk(root);
      return out.filter((n) => n.startsWith(prefix)).sort();
    },
    async remove(name) { await rm(abs(name), { force: true }); },
  };
}

/**
 * A folder tree as a backup source. Never follows symbolic links (they are
 * recorded as links), never crosses into excluded folders, and skips files it
 * can't read (open by another program, no permission), reporting them.
 */
export function fsSource(root, { onSkip } = {}) {
  return {
    async *entries({ exclude = () => false } = {}) {
      const stack = [""];
      while (stack.length) {
        const rel = stack.pop();
        let items;
        try { items = await readdir(join(root, rel), { withFileTypes: true }); }
        catch (e) { onSkip?.(rel, e); continue; }
        items.sort((a, b) => (a.name < b.name ? 1 : -1)); // popped in name order
        for (const it of items) {
          const r = rel ? `${rel}/${it.name}` : it.name;
          const abs = join(root, ...r.split("/"));
          let st;
          try { st = await lstat(abs); } catch (e) { onSkip?.(r, e); continue; }
          if (st.isSymbolicLink()) {
            let target = "";
            try { target = await readlink(abs); } catch (e) { onSkip?.(r, e); continue; }
            yield { path: r, kind: "symlink", target };
          } else if (st.isDirectory()) {
            yield { path: r, kind: "dir", mode: st.mode & 0o7777 }; // backup counts it, or drops it if excluded
            if (!exclude(r, true)) stack.push(r); // never walk into an excluded folder
          } else if (st.isFile()) {
            yield { path: r, kind: "file", size: st.size, mode: st.mode & 0o7777, mtime: Math.floor(st.mtimeMs) };
          }
        }
      }
    },
    async *read(entry, chunkSize) {
      const fh = await open(join(root, ...entry.path.split("/")), "r");
      try {
        for (;;) {
          const buf = new Uint8Array(chunkSize);
          let filled = 0;
          while (filled < chunkSize) {
            const { bytesRead } = await fh.read(buf, filled, chunkSize - filled, null);
            if (!bytesRead) break;
            filled += bytesRead;
          }
          if (!filled) return;
          yield buf.subarray(0, filled);
          if (filled < chunkSize) return;
        }
      } finally { await fh.close(); }
    },
  };
}

/** A folder as a restore target. Refuses to overwrite unless `overwrite` is set. */
export function fsTarget(root, { overwrite = false, keepModes = process.platform !== "win32" } = {}) {
  const abs = (p) => {
    const a = resolve(root, ...p.split("/"));
    if (!a.startsWith(resolve(root) + sep)) throw new Error("Restore path escapes the target folder.");
    return a;
  };
  return {
    async mkdir(path, d) {
      await mkdir(abs(path), { recursive: true });
      if (keepModes && d?.mode) await chmod(abs(path), d.mode).catch(() => {});
    },
    async write(path, chunks, f) {
      const p = abs(path);
      await mkdir(dirname(p), { recursive: true });
      if (!overwrite) {
        const exists = await lstat(p).then(() => true, () => false);
        if (exists) throw new Error(`${path} already exists in the restore folder.`);
      }
      const tmp = `${p}.humid-restore.tmp`;
      const fh = await open(tmp, "w");
      try { for await (const c of chunks) await fh.write(c); }
      catch (e) { await fh.close(); await rm(tmp, { force: true }); throw e; }
      await fh.close();
      await rename(tmp, p);
      if (keepModes && f?.mode) await chmod(p, f.mode).catch(() => {});
      if (f?.mtime) await utimes(p, new Date(), new Date(f.mtime)).catch(() => {});
    },
    async symlink(path, target) {
      const p = abs(path);
      await mkdir(dirname(p), { recursive: true });
      await mkSymlink(target, p).catch(() => {}); // Windows may refuse without developer mode
    },
  };
}
