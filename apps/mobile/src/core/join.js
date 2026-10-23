// Joining: a new device for an existing HumID. The new device binds its biometric
// first, then waits (minutes for a link, up to days for two-proof recovery). What it
// needs at the end is wrapped under its gate the whole time: its device seed D, plus
// the link or recovery key seed, or the card. The record is saved, so the wait
// survives restarts. Finishing is one more live check, in which the secure chip makes
// and attests a fresh liveness key for the session that adds the device.
import { batch } from "@preact/signals";
import { toB64, fromB64, toHex } from "@humid/codec";
import { suite, random } from "@humid/crypto";
import { adapter as gateAdapter, ASSURANCE } from "@humid/gate";
import { ml_dsa87, identityId } from "@humid/htp";
import { parseCard, cardTag, formatCode, combine, decodeShare, openCard, openCardPart, openKeyPart, decodeQuorumPart, combineQuorum, QUORUM, KEY_SECRET_BYTES, accountCheck } from "@humid/recovery";
import * as S from "./state.js";
import { PLATFORM } from "./config.js";
import { R, SEED, CARD, wipe, concat, localChallenge } from "./runtime.js";
import { createIdentity, updateIdentity, clearIdentity } from "./identity.js";
import { toast, friendly, cancelled } from "./notify.js";
import { showInterrupt, endInterrupt, waitForHold, holdMessage, gateLabel, sessionKeys } from "./interrupt.js";
import { connectServer, serverPinned, chooseGate, serverRecord } from "./session.js";
import { refresh } from "./vault.js";
import { loadAlerts, demoPassport } from "./recovery.js";
import { readChip } from "./chips.js";
import { readKeyForRecovery } from "./seckey.js";

/*
 * What a two-proof recovery keeps under this device's lock while it waits (layout 2, 4.0):
 *   device seed (64) ‖ recovery key seed (64) ‖ card slot (15) ‖ security key slot (32)
 * A slot is zeros until that proof is added (pending.hasCard / pending.hasKey say which are
 * real). Layout 1 (3.x): device seed ‖ recovery key seed ‖ card (if any).
 */
const QUORUM_LAYOUT = 2;
function quorumSlots(both, p) {
  const dseed = both.subarray(0, SEED), x = both.subarray(SEED, 2 * SEED);
  if (p.layout === QUORUM_LAYOUT) {
    return {
      dseed, x,
      card: p.hasCard ? both.subarray(2 * SEED, 2 * SEED + CARD) : null,
      key: p.hasKey ? both.subarray(2 * SEED + CARD, 2 * SEED + CARD + KEY_SECRET_BYTES) : null,
    };
  }
  return { dseed, x, card: both.length >= 2 * SEED + CARD ? both.subarray(2 * SEED, 2 * SEED + CARD) : null, key: null };
}
function packQuorum({ dseed, x, card, key }) {
  const out = new Uint8Array(2 * SEED + CARD + KEY_SECRET_BYTES);
  out.set(dseed, 0); out.set(x, SEED);
  if (card) out.set(card, 2 * SEED);
  if (key) out.set(key, 2 * SEED + CARD);
  return out;
}

let joinTimer = null;
// Polling backs off: links every 3 s (a person is waiting on the other phone), long
// waits every 30 s, and nothing at all while HumID is off the screen.
const POLL_LINK = 3000, POLL_COLLECT = 5000, POLL_SLOW = 30_000;

export function startJoin() { S.joinStep.value = serverPinned() ? 1 : 0; S.joinMethod.value = null; S.joinStatus.value = null; S.view.value = "join"; if (!S.server.value) connectServer(); }

/**
 * Bind this device and start the chosen route.
 * method: "link" | "quorum" (two proofs) | "card" | "contacts" (older single-proof routes).
 */
export async function beginJoin(method, { useDemo = false, cardInput = "", soleBiometric = false } = {}) {
  let cardSecret = null;
  if (method === "card" || (method === "quorum" && cardInput.trim())) {
    try { cardSecret = parseCard(cardInput); } catch (e) { toast(e.message, "warn"); return; }
  }
  const gate = chooseGate(useDemo);
  if (!gate) return;
  const Suite = suite();
  R.busy = true;
  showInterrupt({ purpose: "enroll", label: "Lock this device to you", state: "scanning", progress: 0.06, needsHold: !!gate.needsHold,
    message: gate.needsHold ? holdMessage : "Look at your phone or touch the sensor. Your HumID will open only for you on this device." });
  let secret, dseed, x, both, dkeys;
  try {
    await waitForHold(gate);
    const e = await gate.enroll({ prompt: "Lock HumID to your face or fingerprint", challenge: localChallenge("bind") });
    secret = e.secret;
    showInterrupt({ needsHold: false, progress: 0.4, message: "Generating this device's keys…" });
    dseed = random(SEED);
    dkeys = Suite.deriveKeys(dseed);
    x = method === "card" ? cardSecret : random(SEED);
    both = method === "quorum" ? packQuorum({ dseed, x, card: cardSecret }) : concat(dseed, x);
    const wrapped = await Suite.wrapSeed(secret, both, fromB64(e.bindingId));
    showInterrupt({ progress: 0.7, message: method === "link" ? "Getting a code for your other device…" : "Asking your vault to start a recovery…" });
    let pending;
    if (method === "link") {
      const lk = Suite.deriveKeys(x);
      // The link names this device's key (PC-02): only this device can join with it once it's approved.
      const r = await R.api.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: PLATFORM, devicePk: dkeys.dsaPk });
      Suite.wipeKeys(lk);
      pending = { method, code: r.code, expiresAt: r.expiresAt };
    } else if (method === "card") {
      const r = await R.api.startRecovery({ method: "card", tag: cardTag(cardSecret), platform: PLATFORM });
      pending = { method, requestId: r.id, account: r.account, releaseAt: r.releaseAt, expiresAt: r.expiresAt };
    } else if (method === "quorum") {
      const rk = Suite.deriveKeys(x);
      const r = await R.api.startRecovery({ method: "quorum", kemPk: rk.kemPk, xPk: rk.xPk, platform: PLATFORM, ...(cardSecret ? { tag: cardTag(cardSecret) } : {}) });
      Suite.wipeKeys(rk);
      pending = { method, requestId: r.id, code: r.code, account: r.account, expiresAt: r.expiresAt, hasCard: !!cardSecret, hasKey: false, layout: QUORUM_LAYOUT };
    } else {
      const rk = Suite.deriveKeys(x);
      const r = await R.api.startRecovery({ method: "contacts", kemPk: rk.kemPk, xPk: rk.xPk, platform: PLATFORM });
      Suite.wipeKeys(rk);
      pending = { method, requestId: r.id, code: r.code, expiresAt: r.expiresAt };
    }
    const srv = await R.api.server();
    const record = {
      mode: e.interrupt.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance: e.interrupt.assurance, method: e.interrupt.method,
      gate: { adapter: gate.id, handle: e.handle }, bindingId: e.bindingId, wrapped,
      suite: Suite.ID, enrolledAt: new Date().toISOString(),
      pending: { ...pending, devicePub: toB64(dkeys.dsaPk), startedAt: Date.now(), soleBiometric }, device: null, pub: null, commit: null,
      server: serverRecord(srv),
    };
    await createIdentity(record);
    batch(() => { S.joinMethod.value = method; S.joinStep.value = 3; S.joinStatus.value = null; });
    R.api.htp.pinnedKid = srv.kid;
    await endInterrupt(true, "This device is bound. Keys wiped from memory.", 650);
    pollJoin();
  } catch (err) {
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 1800);
  } finally {
    wipe(secret, dseed, x, both, cardSecret);
    if (dkeys) Suite.wipeKeys(dkeys);
    R.busy = false;
  }
}

/**
 * A link code expired while the device waited: get a fresh one for the same bound device,
 * without unbinding (the person keeps their first check). Only for the link route.
 */
export async function renewLink() {
  const id = S.identity.value;
  const p = id?.pending;
  if (p?.method !== "link") return false;
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  R.busy = true;
  showInterrupt({ purpose: "link", label: "New code for your other device", state: "scanning", progress: 0.1, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
  let secret, both, x, next;
  try {
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose: "link", prompt: "New code for your other device", challenge: localChallenge("link") });
    secret = rel.secret;
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    x = random(SEED);
    const lk = Suite.deriveKeys(x);
    // A fresh code for the same bound device key (PC-02).
    const r = await R.api.startLink({ kemPk: lk.kemPk, xPk: lk.xPk, platform: PLATFORM, devicePk: fromB64(p.devicePub) });
    Suite.wipeKeys(lk);
    next = concat(both.subarray(0, SEED), x);
    const wrapped = await Suite.wrapSeed(secret, next, fromB64(id.bindingId));
    if (!(await updateIdentity((cur) => { cur.wrapped = wrapped; cur.pending = { ...cur.pending, code: r.code, expiresAt: r.expiresAt, startedAt: Date.now() }; }))) throw cancelledJoin();
    S.joinStatus.value = null;
    await endInterrupt(true, "New code ready.", 500);
    pollJoin();
    return true;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1800);
    return false;
  } finally {
    wipe(secret, both, x, next);
    R.busy = false;
  }
}

/** Check on a join. Pauses while HumID is off the screen. */
export async function pollJoin() {
  clearTimeout(joinTimer);
  const p = S.identity.value?.pending;
  if (!p || S.view.value !== "join") return;
  if (typeof document !== "undefined" && document.hidden) { joinTimer = setTimeout(pollJoin, POLL_SLOW); return; }
  let st;
  try {
    st = p.method === "link" ? await R.api.linkResult(p.code) : await R.api.recoveryStatus(p.requestId);
    S.joinStatus.value = st;
  } catch (e) {
    S.joinStatus.value = { status: "error", message: friendly(e) };
  }
  if (st && ["approved", "released"].includes(st.status)) {
    // Adding a device: the person compares the match code on both screens first.
    if (p.method === "link") { S.joinStatus.value = { ...st, check: accountCheck(st.account) }; return; }
    return finishJoin(st);
  }
  if (st && ["expired", "cancelled", "completed"].includes(st.status)) return;
  const quick = p.method === "link" || (st?.releaseAt && st.releaseAt - Date.now() < 60_000);
  if (p.method === "quorum" && st?.status === "collecting") { joinTimer = setTimeout(pollJoin, POLL_COLLECT); return; }
  joinTimer = setTimeout(pollJoin, quick ? POLL_LINK : POLL_SLOW);
}
if (typeof document !== "undefined") document.addEventListener("visibilitychange", () => { if (!document.hidden && S.view.value === "join") pollJoin(); });

/** The account seed has arrived (sealed, as a card blob, or as contact pieces): unlock it and join. */
async function finishJoin(st) {
  const id = S.identity.value;
  const p = id.pending;
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  const account = st.account;
  R.busy = true;
  showInterrupt({ purpose: "launch", label: "Open your HumID here", state: "scanning", progress: 0.08, needsHold: false, message: "Connecting to your vault…" });
  let secret, both, seed, keys, dkeys, xkeys, released;
  const pieces = [];
  try {
    const sess = await R.api.enrollDevice({
      account, via: p.method, recoveryId: p.requestId, linkCode: p.method === "link" ? p.code : undefined, soleBiometric: !!p.soleBiometric,
      device: { dsaPk: fromB64(p.devicePub), platform: PLATFORM, gateMethod: id.method, assurance: id.assurance },
      sign: async (message, th) => {
        showInterrupt({ progress: 0.2, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)} to finish.` });
        await waitForHold(gate);
        released = await gate.release(id.gate.handle, { purpose: "enroll", prompt: "Open your HumID here", challenge: message, attest: th });
        secret = released.secret;
        both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
        const x = both.subarray(SEED, p.method === "quorum" ? 2 * SEED : undefined);
        showInterrupt({ needsHold: false, progress: 0.4, message: "Unsealing your account key…" });
        if (p.method === "link") {
          xkeys = Suite.deriveKeys(x);
          const opened = await Suite.open(st.envelope, xkeys);
          seed = opened.bytes;
          keys = Suite.deriveKeys(seed);
          if (opened.manifest.signer.mldsa87Pk !== toB64(keys.dsaPk)) throw new Error("The key that arrived was not sealed by its own account. Nothing was added.");
        } else if (p.method === "card") {
          seed = await openCard(x, st.blob, account);
          keys = Suite.deriveKeys(seed);
        } else if (p.method === "quorum") {
          const parts = [];
          if (st.shares?.length) {
            xkeys = Suite.deriveKeys(x);
            for (const env of st.shares) pieces.push(decodeShare((await Suite.open(env, xkeys)).bytes));
            parts.push({ x: QUORUM.witness, y: combine(pieces) });
          }
          const slot = quorumSlots(both, p);
          if (st.blob && slot.card) parts.push(await openCardPart(slot.card, st.blob, account));
          if (st.keyBlob && slot.key) parts.push(await openKeyPart(slot.key, st.keyBlob, account));
          if (st.anchorPart) parts.push(decodeQuorumPart(st.anchorPart));
          seed = combineQuorum(parts);
          for (const pt of parts) wipe(pt.y);
          keys = Suite.deriveKeys(seed);
        } else {
          xkeys = Suite.deriveKeys(x);
          for (const env of st.shares) pieces.push(decodeShare((await Suite.open(env, xkeys)).bytes));
          seed = combine(pieces);
          keys = Suite.deriveKeys(seed);
        }
        // The pieces name the account they were made for: a server can't route this device
        // into another account by handing it someone else's pieces (or its own).
        if (pieces.some((s) => s.owner && s.owner !== account)) throw new Error("Those pieces belong to a different HumID. Nothing was added.");
        if (identityId(keys.dsaPk) !== account) throw new Error("The pieces didn't rebuild this HumID. Ask your witnesses to check the code and try again.");
        dkeys = Suite.deriveKeys(both.subarray(0, SEED));
        if (toB64(dkeys.dsaPk) !== p.devicePub) throw new Error("This device's keys changed while it waited. Start again.");
        showInterrupt({ progress: 0.65, message: "Adding this device to your HumID…" });
        return {
          sigAccount: ml_dsa87.sign(message, keys.dsaSk), sigDevice: ml_dsa87.sign(message, dkeys.dsaSk),
          live: released.live, gateMethod: released.interrupt.method, assurance: released.interrupt.assurance,
        };
      },
    });
    const rewrapped = concat(seed, both.subarray(0, SEED));
    const wrapped = await Suite.wrapSeed(secret, rewrapped, fromB64(id.bindingId));
    wipe(rewrapped);
    const pub = Suite.publicOf(keys);
    const done = {
      wrapped, pending: null,
      commit: toHex(Suite.identityCommit(pub, Suite.sha3_256(dkeys.dsaPk))),
      assurance: sess.assurance, proof: sess.proof,
      mode: sess.assurance === ASSURANCE.NONE ? "demo" : "hardware",
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      device: { id: sess.device, dsaPk: p.devicePub },
    };
    if (!(await updateIdentity((cur) => { Object.assign(cur, done); cur.server = { ...cur.server, id: account, registeredAt: new Date().toISOString() }; }))) throw cancelledJoin();
    sessionKeys(Suite, seed);
    batch(() => {
      S.session.value = sess;
      S.joinStatus.value = null;
      S.view.value = "app";
      S.tab.value = "vault";
    });
    await endInterrupt(true, "Welcome back. This device is part of your HumID.", 900);
    refresh();
    loadAlerts();
    if (p.method !== "link") toast("Recovered. Check your proofs under You, and make a new recovery card if you used it.", "warn");
  } catch (err) {
    await endInterrupt(false, friendly(err), cancelled(err) ? 700 : 2200);
    if (!cancelled(err)) S.joinStatus.value = { ...st, status: "error", message: friendly(err) };
  } finally {
    wipe(secret, both, seed);
    for (const s of pieces) wipe(s.y);
    for (const k of [keys, dkeys, xkeys]) if (k) Suite.wipeKeys(k);
    R.busy = false;
  }
}

/** Two proofs, while waiting: add the recovery card. One live check re-wraps it with this device's keys. */
export async function addCardToJoin(cardInput) {
  const id = S.identity.value;
  const p = id?.pending;
  if (p?.method !== "quorum") return false;
  if (p.hasCard) { toast("Your recovery card is already part of this recovery.", "warn"); return false; }
  let cardSecret;
  try { cardSecret = parseCard(cardInput); } catch (e) { toast(e.message, "warn"); return false; }
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  R.busy = true;
  showInterrupt({ purpose: "card", label: "Add your recovery card", state: "scanning", progress: 0.1, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
  let secret, both, next;
  try {
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose: "card", prompt: "Add your recovery card", challenge: localChallenge("card") });
    secret = rel.secret;
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    next = packQuorum({ ...quorumSlots(both, p), card: cardSecret });
    showInterrupt({ needsHold: false, progress: 0.6, message: "Telling your vault you have your recovery card…" });
    const r = await R.api.recoveryAddCard(p.requestId, cardTag(cardSecret));
    const wrapped = await Suite.wrapSeed(secret, next, fromB64(id.bindingId));
    if (!(await updateIdentity((cur) => { cur.wrapped = wrapped; cur.pending = { ...cur.pending, hasCard: true, layout: QUORUM_LAYOUT, account: r.account }; }))) throw cancelledJoin();
    S.joinStatus.value = { ...(S.joinStatus.value || {}), ...r };
    await endInterrupt(true, "Recovery card added.", 600);
    pollJoin();
    return true;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1800);
    return false;
  } finally {
    wipe(secret, both, next, cardSecret);
    R.busy = false;
  }
}

/**
 * Two proofs, while waiting: a security key (4.0). One tap with its PIN: the key signs the
 * server's challenge for this recovery and gives this device its secret. Then, inside one
 * live check, the proof is sent and the matching secret is kept under this device's lock
 * for the end of the wait. If the app stops between the two, the server counts the key but
 * this device hasn't kept its secret: the screen then asks for one more tap (pending.hasKey
 * is what this device has, not what the server counted).
 * Returns true | { pinError } | false.
 */
export async function addKeyToJoin(pin) {
  const id = S.identity.value;
  const p = id?.pending;
  if (p?.method !== "quorum") return false;
  if (p.hasKey) { toast("Your security key is already part of this recovery.", "warn"); return false; } // kept here; a key the server counted without it may be read again
  const read = await readKeyForRecovery(p.requestId, pin);
  if (!read || read.pinError) return read || false;
  const gate = gateAdapter(id.gate.adapter);
  const Suite = suite(id.suite);
  R.busy = true;
  showInterrupt({ purpose: "key", label: "Add your security key", state: "scanning", progress: 0.1, needsHold: !!gate.needsHold, message: gate.needsHold ? holdMessage : `Confirm with ${gateLabel(id.method)}.` });
  let secret, both, next;
  try {
    await waitForHold(gate);
    const rel = await gate.release(id.gate.handle, { purpose: "key", prompt: "Add your security key", challenge: localChallenge("key") });
    secret = rel.secret;
    both = await Suite.unwrapSeed(secret, id.wrapped, fromB64(id.bindingId));
    showInterrupt({ needsHold: false, progress: 0.6, message: "Showing your vault that your key answered…" });
    const r = await R.api.recoveryAddKey(p.requestId, read.candidates);
    const match = read.candidates.find((c) => c.tag === r.tag);
    if (!match) throw new Error("Your vault matched a key this phone didn't read. Nothing was kept; try again.");
    next = packQuorum({ ...quorumSlots(both, p), key: match.secret });
    const wrapped = await Suite.wrapSeed(secret, next, fromB64(id.bindingId));
    if (!(await updateIdentity((cur) => { cur.wrapped = wrapped; cur.pending = { ...cur.pending, hasKey: true, layout: QUORUM_LAYOUT, account: r.account }; }))) throw cancelledJoin();
    const { tag: _t, ...status } = r;
    S.joinStatus.value = { ...(S.joinStatus.value || {}), ...status };
    await endInterrupt(true, "Security key added.", 600);
    pollJoin();
    return true;
  } catch (e) {
    await endInterrupt(false, friendly(e), cancelled(e) ? 700 : 1800);
    return false;
  } finally {
    wipe(secret, both, next);
    for (const c of read.candidates) wipe(c.secret);
    R.busy = false;
  }
}

/**
 * Two proofs, while waiting: the ID chip, live. The chip must answer a fresh challenge
 * from the server, so a copy of its data isn't enough.
 */
export async function addChipToJoin(source) {
  const p = S.identity.value?.pending;
  if (p?.method !== "quorum") return false;
  try {
    const nonce = await R.api.recoveryChallenge(p.requestId);
    const got = await source(nonce);
    if (!got) return false;
    const { chip, signature } = got;
    if (!signature) throw new Error("This ID's chip can't answer challenges. Verify at a HumID station instead.");
    const r = await R.api.recoveryAddAnchor(p.requestId, { chip, signature });
    S.joinStatus.value = { ...(S.joinStatus.value || {}), ...r };
    toast("Your ID chip is verified.");
    pollJoin();
    return true;
  } catch (e) { if (e?.code !== "cancelled") toast(friendly(e), "error"); return false; }
}

/** Development builds: a demo passport as a live chip source for addChipToJoin. */
export const demoChipSource = (name) => async (nonce) => {
  const c = await demoPassport(name);
  return c ? { chip: c, signature: await c.answer(nonce) } : null;
};

/** A real chip as a live source for addChipToJoin: one read that also answers the nonce. */
export const nfcChipSource = (access) => async (nonce) => {
  const r = await readChip(access, { nonce, purpose: "recover" });
  return r ? { chip: r, signature: r.aaSignature } : null;
};

/** Adding a device: the match code matched the other device's screen. */
export function confirmJoin() {
  const st = S.joinStatus.value;
  if (st?.check && st.status === "approved") return finishJoin(st);
}

/** The match code didn't match: someone else's account was offered. Join nothing. */
export async function rejectJoin() {
  await cancelJoin();
  S.joinStatus.value = { status: "mismatch" };
  S.joinStep.value = 4;
}

/** Give up on a join: forget the half-made device and go back to the start. */
export async function cancelJoin() {
  clearTimeout(joinTimer);
  const id = S.identity.value;
  try { if (id?.gate) await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {}
  await clearIdentity();
  batch(() => { S.identity.value = null; S.joinStatus.value = null; S.joinStep.value = 1; S.joinMethod.value = null; });
}

export const prettyCode = formatCode;
/** The join was given up (cancelJoin cleared the record) while this step ran. */
const cancelledJoin = () => new Error("This device's setup was cancelled. Start again.");
