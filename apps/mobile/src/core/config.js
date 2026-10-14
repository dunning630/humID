// Build-time configuration (see build.mjs). In the installable web app the
// server is the same origin; the native apps are built with HUMID_SERVER_URL.
/* global __HUMID_SERVER__, __HUMID_KID__, __HUMID_VERSION__, __HUMID_MODULES__, __HUMID_SIM__ */

/** Simulation build: the vault server runs inside the app, over the real HTP/1 protocol. */
export const SIM = typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true;
export const SIM_URL = "sim://this-phone";
export const SERVER_URL = SIM ? SIM_URL : typeof __HUMID_SERVER__ !== "undefined" ? __HUMID_SERVER__ : "";
export const PINNED_KID = (typeof __HUMID_KID__ !== "undefined" && __HUMID_KID__) || null;
export const VERSION = typeof __HUMID_VERSION__ !== "undefined" ? __HUMID_VERSION__ : "dev";
export const MODULES = typeof __HUMID_MODULES__ !== "undefined" ? __HUMID_MODULES__ : {};
export { DEMO_BUILD } from "@humid/gate";

const inApp = typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";
const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
const os = /iPhone|iPad|iPod/.test(ua) ? "iOS"
  : /Android/.test(ua) ? "Android"
  : /Macintosh/.test(ua) ? "macOS"
  : /Windows/.test(ua) ? "Windows"
  : /Linux/.test(ua) ? "Linux" : "Unknown";
export const PLATFORM = `${os} ${inApp ? "app" : "web"}`;
export const IN_APP = inApp;

export const serverHost = (url) => {
  if (String(url || "").startsWith("sim:")) return "simulated on this phone";
  try { return new URL(url || location.origin).host; } catch { return url || "this server"; }
};
