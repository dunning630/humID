// The dev server's static files (PC-25): a request path maps to a file inside the
// app's dist folder or to nothing. `/..%2f..%2fetc%2fpasswd` decoded and joined onto
// dist used to read any file the developer's account could.
import { resolve, sep } from "node:path";

/** The file under `dist` that `pathname` names, or null if it points outside it or can't be read. */
export function devFile(dist, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return null; }
  if (rel.includes("\0")) return null;
  const root = resolve(dist);
  const file = resolve(root, "." + sep + rel.replace(/^[/\\]+/, ""));
  return file === root || file.startsWith(root + sep) ? file : null;
}
