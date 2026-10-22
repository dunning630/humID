// What the person is told, and how an error becomes words. One vocabulary
// (tests/ia-v3.test.js checks the screens use the same words).
import { CANCELLED } from "@humid/gate";
import * as S from "./state.js";
import { R } from "./runtime.js";

export function toast(text, kind = "ok") {
  if (!text) return; // e.g. a lost session: the lock screen says it once, not every failed request
  if (text === UNREACHABLE && S.link.value.state === "down") return; // the connection bar already says so
  const id = Math.random().toString(36).slice(2);
  S.toasts.value = [...S.toasts.value, { id, text, kind }].slice(-3);
  setTimeout(() => { S.toasts.value = S.toasts.value.filter((t) => t.id !== id); }, kind === "error" ? 5200 : 3600);
}

export const UNREACHABLE = "Can't reach your vault server. Check your connection.";
// The server has forgotten this session (it expired or restarted). The app locks with
// "Your session ended"; the requests that hit it say nothing more.
export const SESSION_LOST = new Set(["session_unknown", "session_expired", "sign_in_required"]);

export const friendly = (e) => {
  if (SESSION_LOST.has(e?.code)) return null;
  // the server says Heartbeat locked or erased the vault: show where it stands now
  if (e?.code === "checkin_missed" || e?.code === "vault_erased") setTimeout(() => R.hooks.loadCheckin?.(), 0);
  if (e?.name === "NotAllowedError" || e?.message === CANCELLED) return "The check was cancelled.";
  if (e?.code === "no_match") return "That didn't match. Try again.";
  if (e?.code === "server_identity_changed") return "This server's identity changed. HumID refused to connect.";
  if (e?.code === "key_invalidated") return "This phone's HumID key is gone: its fingerprints or face changed, or HumID was reinstalled.";
  if (e?.code === "offline") return "You're offline. Opening or changing anything needs a connection to your vault.";
  if (e instanceof TypeError || e?.code === "server_unreachable") return UNREACHABLE;
  return e?.message || "That didn't work. Try again, or lock and unlock.";
};
export const cancelled = (e) => e?.name === "NotAllowedError" || e?.message === CANCELLED;
export const quietly = (p) => p.catch((e) => { if (!cancelled(e)) toast(friendly(e), "error"); return null; });
/** The vault didn't answer at all (as opposed to answering "no"). */
export const unreachable = (e) => e instanceof TypeError || e?.code === "server_unreachable" || e?.name === "AbortError" || [502, 503, 504].includes(e?.status);

/** A short buzz, unless the person turned haptics off. */
export const buzz = (pattern) => { if (!S.prefs.value.haptics) return; try { globalThis.navigator?.vibrate?.(pattern); } catch {} };
/** A short buzz when a check passes, a distinct one when it fails (Android; iPhones have no web vibration). */
export const haptic = (ok) => buzz(ok ? 18 : [40, 70, 40]);
