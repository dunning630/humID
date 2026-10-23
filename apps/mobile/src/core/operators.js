// For operators: a verification station (vouching for a person in front of you) and
// managing a HumID server (docs/ADMIN.md). Ordinary holders never see these.
import { adminCheck } from "@humid/recovery";
import * as S from "./state.js";
import { R, epoch, stale } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withStepUp, showInterrupt, needVault } from "./interrupt.js";
import { demoPassport } from "./recovery.js";
import { readChip } from "./chips.js";

/* global __HUMID_SIM__ */

/* ---------------- verification station ---------------- */

export async function stationLookup(code) {
  try { needVault(); return await R.api.stationRequest(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** The station reads the chip in front of it; the chip answers a fresh server challenge in the same session. */
export async function stationReadChip(code, { access, demo } = {}) {
  try {
    const nonce = await R.api.stationChallenge(code);
    if (demo != null) {
      const c = await demoPassport(demo);
      return c ? { ...c, aaSignature: await c.answer(nonce) } : null;
    }
    return await readChip(access, { nonce, purpose: "station" });
  } catch (e) { toast(friendly(e), "error"); return null; }
}

/** The operator vouches: document genuine, face matches, person present. Their own live check signs it. */
export async function stationVerify(code, chip, checks) {
  try {
    return await withStepUp("stationVerify", [code], "station", "Vouch for this person", async ({ proof }) => {
      showInterrupt({ progress: 0.6, message: "Checking the chip with its issuing country…" });
      return R.api.stationVerify(code, { chip, checks, signature: chip.aaSignature }, proof);
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/* ---------------- managing a HumID server ---------------- */

/** How the server is doing, for its administrators; null for everyone else (asked quietly). */
export async function loadAdminSummary() {
  if (S.offline.value || S.decoy.value || (typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true)) { S.adminSummary.value = null; return; }
  const ep = epoch();
  try { const a = await R.api.adminSummary(); if (!stale(ep)) S.adminSummary.value = a; } catch { if (!stale(ep)) S.adminSummary.value = null; }
}

/** What a code from the server's admin console asks for. */
export async function findAdminRequest(code) {
  try { needVault(); return await R.api.adminRequest(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Approve exactly that request with a live check. For becoming an administrator, returns the admin match code from this device's own key. */
export async function approveAdminRequest(req) {
  try {
    let check = null;
    await withStepUp("approveAdmin", [req.code], "admin", req.kind === "enrol" ? "Become a server administrator" : req.title, async ({ dkeys, proof }) => {
      check = adminCheck(dkeys.dsaPk);
      return R.api.approveAdmin(req.code, req.digest, proof);
    });
    loadAdminSummary();
    return { check };
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}
