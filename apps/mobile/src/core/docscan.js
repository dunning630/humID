// Document capture on Android: the phone's own document scanner (ML Kit, run by Google
// Play services) through tauri-plugin-humid-docscan (humid-docscan@1). It finds the
// document's edges, takes the photo when it's steady and flattens it, on the phone; the
// page comes back here as a JPEG and is read and sealed like any photo. Where there is
// no scanner (iPhone, a computer, a browser, a phone without Play services or with too
// little memory), HumID's own camera is used instead, and for the rest of the session.

/* global __HUMID_ALLOW_DEMO__ */
const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";
const onAndroid = () => /\bAndroid\b/i.test(globalThis.navigator?.userAgent || "");
// Development builds only: a browser test can stand in for the phone's scanner. The flag is
// tested inline so release builds fold it to false and drop the stand-in entirely
// (tests/bundle.test.js checks), as in core/nfc.js.
const fake = () => ((typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) ? globalThis.__humidFakeScanner || null : null);
const tauriInvoke = (cmd, args) => (fake() ? fake().invoke(cmd, args) : globalThis.__TAURI_INTERNALS__.invoke(`plugin:humid-docscan|${cmd}`, args));
const msg = (e) => (typeof e === "string" ? e : e?.message || String(e));

/** What a failed scan means: "cancelled" (the person backed out), "unavailable" (no scanner here: use the camera) or "failed". */
export function outcome(e) {
  const m = msg(e).toLowerCase();
  if (/\bcancel/.test(m)) return "cancelled";
  if (m.startsWith("unavailable") || /not (found|available|supported)|no command|plugin not|unknown plugin|not allowed/.test(m)) return "unavailable";
  return "failed";
}

/**
 * A scanner over an invoke function (the plugin's, or a test's).
 *   available()            whether to try it at all (Android app, not turned off this session)
 *   scan({ maxSide })       → { blob, width, height } for the page, or null if the person backed out;
 *                           throws { kind: "unavailable" | "failed", message } otherwise.
 *                           "unavailable" also turns the scanner off for the rest of the session.
 */
export function createDocScanner({ invoke = tauriInvoke, supported = () => !!fake() || (inTauri() && onAndroid()) } = {}) {
  let off = null; // why the scanner isn't used this session
  return {
    available: () => !off && supported(),
    why: () => off,
    disable(reason = "turned off") { off = reason; },
    async scan({ maxSide = 3200 } = {}) {
      let page;
      try { page = await invoke("scan", { maxSide }); }
      catch (e) {
        const kind = outcome(e);
        if (kind === "cancelled") return null;
        if (kind === "unavailable") off = msg(e);
        throw Object.assign(new Error(kind === "unavailable" ? "The phone's document scanner isn't available. Using HumID's camera." : "The scanner couldn't hand the page back. Scan it again."), { kind });
      }
      if (!page?.data) throw Object.assign(new Error("The scanner gave back no page. Try again."), { kind: "failed" });
      const bytes = Uint8Array.from(atob(page.data), (ch) => ch.charCodeAt(0));
      return { blob: new Blob([bytes], { type: page.mime || "image/jpeg" }), width: page.width, height: page.height };
    },
  };
}

/** The app's scanner. */
export const docScanner = createDocScanner();
