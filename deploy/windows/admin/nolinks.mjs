// SYSTEM never follows a link that the HumID server's account could have planted
// (docs/ADMIN.md, "Separate rights"). Before the console or a job reads or writes under
// the data root, every folder from the root down must be a real folder, and every file
// it reads a real file. Node's lstat reports a Windows junction as a symbolic link.
import { lstatSync } from "node:fs";
import { join, relative, resolve, sep, isAbsolute } from "node:path";

export class LinkError extends Error {
  constructor(message) { super(message); this.code = "link"; }
}

/** Throw a LinkError if `path` (when it exists) or any folder between `root` and it is a link. */
export function assertNoLinks(root, path) {
  const top = resolve(root);
  const rel = relative(top, resolve(path));
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new LinkError(`${path} isn't under ${root}.`);
  let p = top;
  for (const part of ["", ...rel.split(sep).filter(Boolean)]) {
    if (part) p = join(p, part);
    let st;
    try { st = lstatSync(p); } catch (e) { if (e.code === "ENOENT") return; throw e; }
    if (st.isSymbolicLink()) throw new LinkError(`${p} is a link (a junction or symbolic link). HumID never makes one there, so it won't follow it.`);
  }
}

/** A real file (not a link, a folder or a device) of at most `maxBytes`. */
export function isPlainFile(p, maxBytes = Infinity) {
  try {
    const st = lstatSync(p);
    return st.isFile() && !st.isSymbolicLink() && st.size <= maxBytes;
  } catch { return false; }
}
