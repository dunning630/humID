// Creating a HumID: the access pass (paying without being known), the first live
// check that binds the keys to this person, and the recovery card shown once.
import { batch } from "@preact/signals";
import { toB64, fromB64, toHex } from "@humid/codec";
import { suite, random } from "@humid/crypto";
import { ASSURANCE } from "@humid/gate";
import { saveBytes } from "@humid/io";
import { ml_dsa87, identityId } from "@humid/htp";
import { newCard, cardTag, sealCardPart, quorumParts } from "@humid/recovery";
import { parseAccessCode } from "@humid/pass";
import * as S from "./state.js";
import { PLATFORM } from "./config.js";
import { R, SEED, wipe, concat, utf8 } from "./runtime.js";
import { createIdentity } from "./identity.js";
import { toast, friendly, cancelled } from "./notify.js";
import { showInterrupt, endInterrupt, waitForHold, holdMessage, sessionKeys } from "./interrupt.js";
import { connectServer, serverPinned, chooseGate, gateClaim, serverRecord, wallet, markPicking } from "./session.js";
import { refresh } from "./vault.js";
import { loadAlerts } from "./recovery.js";
import { signMode, HOLDER_ONLY, HARDENED } from "./recmode.js";

/* global __HUMID_SIM__, __HUMID_ALLOW_DEMO__ */

export function startEnroll() {
  S.enrollStep.value = serverPinned() ? (S.passNeeded.value ? "access" : "mode") : "connect";
  S.setupMode.value = "hardened"; // the recommended choice is selected; the holder can pick holder-only
  S.view.value = "enroll";
  if (!S.server.value) connectServer();
}

/* ---------------- anonymous payment: access code → access pass ---------------- */
// The pass is signed blind (RFC 9474): the vault signs it without seeing it, so when
// registration spends it, the vault can't tell which access code, purchase or person it
// came from. Before the code is sent, the request is saved (sealed at rest, @humid/pass/atrest),
// so a crash or a lost connection never loses a paid-for code.

const PASS_REFUSED = new Set(["code_invalid", "code_unknown", "code_used", "too_many_keys", "no_keys", "bad_key"]);

export async function redeemAccessCode(input) {
  const code = parseAccessCode(input);
  if (!code) { toast("That access code isn't valid. Check it and try again.", "error"); return false; }
  if (S.pass.value?.state === "ready") return true;
  if (S.pass.value?.state === "draft") return resumePass();
  S.passBusy.value = true;
  let saved = false;
  try {
    const pass = await R.api.getPass(code, {
      saveDraft: async (draft) => {
        const rec = { state: "draft", code, draft, savedAt: new Date().toISOString().slice(0, 10) };
        await wallet().put(rec);
        S.pass.value = rec;
        saved = true;
      },
    });
    await keepPass(pass);
    return true;
  } catch (e) {
    if (saved && PASS_REFUSED.has(e?.code)) { await wallet().clear(); S.pass.value = null; }
    toast(saved && !PASS_REFUSED.has(e?.code) ? "Your access code is saved on this phone. HumID will finish your pass when it can reach the vault." : friendly(e), "error");
    return false;
  } finally { S.passBusy.value = false; }
}

/** Finish a pass whose request was sent but whose answer never arrived. */
export async function resumePass() {
  const rec = S.pass.value;
  if (rec?.state !== "draft" || S.passBusy.value) return rec?.state === "ready";
  S.passBusy.value = true;
  try {
    await keepPass(await R.api.getPass(rec.code, { draft: rec.draft }));
    return true;
  } catch (e) {
    if (PASS_REFUSED.has(e?.code)) { await wallet().clear(); S.pass.value = null; toast(friendly(e), "error"); }
    return false;
  } finally { S.passBusy.value = false; }
}

/** Keep the finished pass, and drop the access code: from here on, nothing ties the pass to it. */
async function keepPass(pass) {
  const rec = { state: "ready", pass };
  await wallet().put(rec);
  S.pass.value = rec;
}

/** A demo access code: in the simulation build, or from a local development server. Release builds: nothing. */
export async function demoAccessCode() {
  if (!(typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true) && !(typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) return false;
  try {
    if ((typeof __HUMID_SIM__ !== "undefined" && __HUMID_SIM__ === true)) return redeemAccessCode(R.sim.demoAccessCode());
    const r = await fetch("/dev/access-code", { method: "POST" });
    if (!r.ok) throw new Error("This server has no demo access codes.");
    return redeemAccessCode((await r.json()).code);
  } catch (e) { toast(friendly(e), "error"); return false; }
}

/* ---------------- the first device ---------------- */

/**
 * Create the account. recoveryMode: "hardened" (the default: a recovery card is made under
 * this same check) or "holder-only" (no card, no recovery part leaves this phone, ever).
 * Either way the choice is signed by the new account key and sent with the registration.
 */
export async function enroll(useDemo, { soleBiometric = false, recoveryMode = S.setupMode.value } = {}) {
  const holderOnly = recoveryMode === HOLDER_ONLY;
  if (!holderOnly && recoveryMode !== HARDENED) { toast("Choose how you want to be able to get back in.", "warn"); return false; }
  const pass = S.passNeeded.value ? S.pass.value?.pass : undefined;
  if (S.passNeeded.value && S.pass.value?.state !== "ready") { S.enrollStep.value = "access"; toast("Add an access pass first.", "warn"); return false; }
  const gate = chooseGate(useDemo);
  if (!gate) return false;
  const Suite = suite();
  R.busy = true;
  showInterrupt({ purpose: "enroll", label: "Create your HumID", state: "scanning", progress: 0.06, needsHold: false, message: "Generating your post-quantum keys…" });
  let secret, seed, dseed, both, keys, dkeys, card, enrolled;
  try {
    // Keys and the recovery card are made before the check; the check binds them to you.
    seed = random(SEED); dseed = random(SEED);
    keys = Suite.deriveKeys(seed);
    dkeys = Suite.deriveKeys(dseed);
    const pub = Suite.publicOf(keys);
    const accountId = identityId(pub.dsaPk);
    const commit = toHex(Suite.identityCommit(pub, Suite.sha3_256(dkeys.dsaPk)));
    // Hardened: the recovery card holds one of the recovery parts; recovery always needs a
    // second proof. Holder-only: no part is made at all.
    let cardBody;
    if (!holderOnly) {
      card = newCard();
      const parts = quorumParts(seed);
      cardBody = { tag: cardTag(card.secret), blob: await sealCardPart(card.secret, parts.card, accountId) };
      for (const p of Object.values(parts)) wipe(p.y);
    }
    const mode = signMode(accountId, keys.dsaSk, recoveryMode);
    showInterrupt({ progress: 0.2, message: "Connecting to your vault…" });

    const sess = await R.api.register({
      pub, commit, card: cardBody, soleBiometric, pass, recoveryMode: mode,
      device: { dsaPk: dkeys.dsaPk, platform: PLATFORM, ...gateClaim(gate) },
      // One live check: the secure chip makes a liveness key for this session (th),
      // proves it, and signs the device statement with it.
      sign: async ({ register, device, th }) => {
        showInterrupt({ progress: 0.3, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : "Look at your phone or touch the sensor to lock HumID to you." });
        await waitForHold(gate);
        enrolled = await gate.enroll({ prompt: "Lock HumID to your face or fingerprint", challenge: device, attest: th });
        secret = enrolled.secret;
        showInterrupt({ needsHold: false, progress: 0.6, message: enrolled.live?.attestation ? "Your phone's secure chip vouched for the live check. Registering…" : "Registering your public keys with the vault…" });
        return {
          registerSig: ml_dsa87.sign(register, keys.dsaSk),
          sigAccount: ml_dsa87.sign(device, keys.dsaSk),
          sigDevice: ml_dsa87.sign(device, dkeys.dsaSk),
          live: enrolled.live, gateMethod: enrolled.interrupt.method, assurance: enrolled.interrupt.assurance,
        };
      },
    });

    both = concat(seed, dseed);
    const wrapped = await Suite.wrapSeed(secret, both, fromB64(enrolled.bindingId));
    const srv = await R.api.server();
    const record = {
      mode: sess.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance: sess.assurance, proof: sess.proof, method: enrolled.interrupt.method,
      gate: { adapter: gate.id, handle: enrolled.handle }, bindingId: enrolled.bindingId, wrapped, commit,
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      device: { id: sess.device, dsaPk: toB64(dkeys.dsaPk) },
      enrolledAt: new Date().toISOString(), suite: Suite.ID, pending: null, recoveryMode,
      // The statement this device signed, pinned: a server showing less later is caught (V74-01/02).
      modePin: { mode: recoveryMode, version: 1, epoch: 1, prev: mode.prev },
      server: serverRecord(srv, { id: sess.id, registeredAt: new Date().toISOString() }),
    };
    await createIdentity(record);
    sessionKeys(Suite, seed);
    batch(() => {
      S.session.value = sess;
      S.items.value = [];
      S.cardCode.value = sess.cardSet && card ? card.code : null;
      S.recoveryMode.value = { mode: recoveryMode, version: 1, epoch: 1, prev: mode.prev, escrow: sess.cardSet ? ["card"] : [], trusted: true, statement: { mode: recoveryMode, version: 1, epoch: 1, prev: mode.prev } };
      S.enrollStep.value = "done";
    });
    R.api.htp.pinnedKid = srv.kid;
    if (pass) { await wallet().clear(); S.pass.value = null; } // spent: nothing to keep
    await endInterrupt(true, "Your HumID is bound to this device.", 700);
    return true;
  } catch (err) {
    if (enrolled) try { await gate.forget(enrolled.handle); } catch {}
    // The vault refused the pass itself: it's no use to keep, so ask for another code.
    if (["pass_spent", "pass_invalid", "pass_expired", "pass_required"].includes(err?.code)) {
      await wallet().clear();
      batch(() => { S.pass.value = null; S.enrollStep.value = "access"; });
    }
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 2200);
    return false;
  } finally {
    wipe(secret, seed, dseed, both, card?.secret);
    if (keys) Suite.wipeKeys(keys);
    if (dkeys) Suite.wipeKeys(dkeys);
    R.busy = false;
  }
}

export function finishEnroll() { S.cardCode.value = null; S.view.value = "app"; S.tab.value = "vault"; refresh(); loadAlerts(); }

/* ---------------- the recovery card, as a file ---------------- */

const cardText = (code) => [
  "HumID recovery card", "",
  code, "",
  "Your card is one proof. Recovery needs two, for example this card and your witnesses.",
  "On its own it opens nothing. Recovery needs any two of your four kinds of proof (witnesses, your ID chip, a recovery card or a security key), then waits and alerts your devices.",
  "Keep it somewhere safe and offline, away from your ID.",
  "", `Created ${new Date().toLocaleDateString()}`,
].join("\n");

export async function saveCard(code) {
  markPicking();
  try { await saveBytes(utf8(cardText(code)), "HumID recovery card.txt", "text/plain"); toast("Saved your recovery card."); }
  catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}
// No "copy" for the recovery card or ID numbers: other apps (and keyboards, and clipboard
// sync to other devices) can read the clipboard, and nothing can reliably clear it.
