// Leaving HumID for another app, on purpose: a web page (where to buy an access
// code, a map of where a document was sealed), a phone number (the bank on the
// back of a card) or an email address. Nothing else ever leaves the app.
//
//   openExternal(url) → Promise<boolean>   true if the system was asked to open it
//
// Only https:, tel: and mailto: are accepted; anything else (javascript:, file:,
// intent:, custom schemes, http:) is refused without being opened. In the native
// app the URL goes to the OS through the Tauri opener plugin, whose capability
// (src-tauri/capabilities/default.json) allows the same three schemes and nothing
// else, so the WebView never navigates: the shell also refuses navigation away from
// its own origin (src-tauri/src/lib.rs). In a browser it opens a new tab with no
// opener and no referrer.

const SCHEMES = new Set(["https:", "tel:", "mailto:"]);
const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";

/** The URL as it will be opened, or null if it isn't one HumID opens. Exported for tests. */
export function externalUrl(input) {
  const s = String(input ?? "").trim();
  if (!s || s.length > 2048 || /[\u0000-\u001f\u007f]/.test(s)) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!SCHEMES.has(u.protocol)) return null;
  if (u.protocol === "https:") {
    if (!u.hostname || u.username || u.password) return null; // no credentials in a link
  } else {
    // tel: digits, + and separators; mailto: one address, no headers
    const body = u.pathname;
    if (u.protocol === "tel:" && !/^\+?[\d\s().-]{3,32}$/.test(body)) return null;
    if (u.protocol === "mailto:" && (!/^[^\s@/?]+@[^\s@/?]+\.[^\s@/?]+$/.test(body) || u.search)) return null;
  }
  return u.href;
}

/**
 * Ask the system to open `url` outside HumID. Resolves true when it was handed over,
 * false when the URL was refused or the system declined. Never throws.
 */
export async function openExternal(url) {
  const href = externalUrl(url);
  if (!href) return false;
  try {
    if (inTauri()) {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(href);
      return true;
    }
    const w = globalThis.open?.(href, "_blank", "noopener,noreferrer");
    // a popup blocker returns null; nothing more to do (the person can retry)
    return w !== undefined; // undefined only when there's no window at all
  } catch { return false; }
}
