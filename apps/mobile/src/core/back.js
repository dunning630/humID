// The Android back button and edge-swipe back gesture. HumID is one page, so by
// default Android would treat "back" as "leave the app". Instead, back closes
// whatever is on top, the way its own close or Back button would:
//   the camera › an open document › the top sheet (or the step inside it) ›
//   the screen's Back button › the Vault tab.
// At the bottom of that list it does nothing: back never exits HumID.
//
// Any control marked data-back is what back presses for its layer.
import * as S from "./state.js";

const visible = (el) => !!el && !el.disabled && el.getClientRects().length > 0;
const top = (sel) => { const all = document.querySelectorAll(sel); return all[all.length - 1] || null; };

/** Do what back means right now. Returns what it did, for tests. */
export function handleBack() {
  // A live check in progress: its own prompt (or Cancel) decides; back must not race it.
  if (S.interrupt.value) return "interrupt";
  for (const layer of [".doccam", ".interrupt.chip-read", ".viewer"]) {
    const el = top(layer);
    if (!el) continue;
    const b = [...el.querySelectorAll("[data-back]")].find(visible);
    if (b) b.click();
    return layer;
  }
  const sheet = top(".sheet");
  if (sheet) {
    const inner = [...sheet.querySelectorAll("[data-back]")].reverse().find(visible);
    if (inner) { inner.click(); return "sheet-step"; }
    top(".scrim")?.click(); // the sheet closes the way a tap outside it does (a busy sheet stays)
    return "sheet";
  }
  const back = [...document.querySelectorAll(".screen [data-back]")].find(visible);
  if (back) { back.click(); return "screen"; }
  if (S.view.value === "app" && S.tab.value !== "vault") { S.sheet.value = null; S.tab.value = "vault"; window.scrollTo({ top: 0 }); return "tab"; }
  return "stay";
}

/** In the Android app, take over the back button and gesture (Tauri's app plugin, core:default allows it). */
export async function wireBack() {
  if (!globalThis.__TAURI_INTERNALS__?.invoke || !/Android/.test(navigator.userAgent)) return;
  try {
    const { onBackButtonPress } = await import("@tauri-apps/api/app");
    await onBackButtonPress(() => { handleBack(); });
  } catch { /* an older shell: Android keeps its default */ }
}

// Development and tests: the same behaviour without a phone.
globalThis.__humidBack = handleBack;
