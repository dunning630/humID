// HumID simulated vault server, for the simulation build (HUMID_SIMULATE=1).
//
// It runs inside the app, but it is not a mock: the app connects to it over
// the real HTP/1 protocol (hybrid ML-KEM-1024 + X25519 handshake, encrypted
// frames, replay window), and it runs the same checks the real gateway,
// identity, vault and ledger services run on every request:
//
//   enrolment   proof of possession of the account key; device key and account
//               key both sign the device statement for this session; the
//               phone's secure-chip liveness key signs it too; the attestation
//               is read (its certificate chain is checked only by a real server)
//   sign-in     a fresh server challenge, signed by the device key AND by the
//               secure chip during a live face or fingerprint match
//   step-ups    open, delete, close…: both signatures over that exact request,
//               at most 60 seconds old
//   sealing     the envelope's ML-DSA-87 signature, its recipient, and the
//               secure chip's signature over the ciphertext hash
//   history     a SHA3 hash chain per account with a signed head, published in a
//               Merkle log with signed checkpoints, all verified by the app
//
// What it can't do: talk to other people or devices (linking, witnesses,
// stations), verify attestation chains against Google's and Apple's roots, or
// hold anything off the phone. Every check it runs is reported through
// `onCheck`, so the app can show them.

import { HtpServer, HtpServerError, createStatics, exportStatics, importStatics } from "@humid/htp/server";
import {
  MEDIA_TYPE, registerMessage, deviceMessage, loginMessage, loginPresenceMessage, stepUpMessage, liveMessage, actionBytes, sealLiveMessage,
  identityId, deviceId, verify, proofHash, STEP_UP_MAX_AGE_MS, STEP_UP_NONCE_MS, CLOCK_SKEW_MS,
  ml_dsa87, sha3_256, toHex, fromHex, b64u, unb64u, utf8, fromUtf8, random,
} from "@humid/htp";
import { GENESIS, entryHash, headMessage, leafHash, treeHash, inclusionProof, consistencyProof, checkpointMessage } from "@humid/audit";
import { suiteForEnvelope } from "@humid/crypto";
import { isEnvelope } from "@humid/codec";
import { p256 } from "@noble/curves/nist.js";
import { parse, kids, int, bool, octets, certExtension, CLASS } from "@humid/attest/der";
import { verifyPass, spentId, parseAccessCode, accessCodeHash, newAccessCode } from "@humid/pass";
import { newSimIssuerKey, simIssuerKey, blindSignJwk } from "@humid/pass/jwk";

const SIZES = { kemPk: 1568, dsaPk: 2592, xPk: 32 };
const DB = "humid-sim";
const LOCKDOWN_COOLOFF_MS = 2 * 60_000; // real servers: 24 h
const QUOTA = 250 * 1024 * 1024;

/* ---------------- storage (IndexedDB, survives restarts) ---------------- */

function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => { r.result.createObjectStore("kv"); r.result.createObjectStore("blobs"); };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
const tx = (db, store, mode, fn) => new Promise((resolve, reject) => {
  const t = db.transaction(store, mode);
  const req = fn(t.objectStore(store));
  t.oncomplete = () => resolve(req?.result);
  t.onerror = () => reject(t.error);
});

/* ---------------- secure-chip signatures (ECDSA P-256, DER) ---------------- */

function liveOk(spki, message, sig) {
  if (!spki || !sig) return false;
  try { return p256.verify(sig, message, spki.subarray(spki.length - 65), { format: "der", lowS: false }); }
  catch { return false; }
}

/**
 * What an Android key attestation says about the liveness key. The certificate
 * chain is NOT verified here (a real server checks it against Google's roots);
 * this reads the hardware's claims so you can see what a server checks.
 */
function readAndroidAttestation(chain, th) {
  const T = { USER_AUTH_TYPE: 504, AUTH_TIMEOUT: 505, NO_AUTH: 503, ROOT_OF_TRUST: 704 };
  const kd = kids(parse(certExtension(chain[0], "1.3.6.1.4.1.11129.2.1.17")));
  const list = (t) => { const m = new Map(); for (const c of kids(t)) if (c.cls === CLASS.context) m.set(c.tag, parse(c.value)); return m; };
  const hw = list(kd[7]);
  const level = int(kd[1]);
  const uat = hw.has(T.USER_AUTH_TYPE) ? int(hw.get(T.USER_AUTH_TYPE)) : 0;
  const timeout = hw.has(T.AUTH_TIMEOUT) ? int(hw.get(T.AUTH_TIMEOUT)) : 0;
  const rot = hw.has(T.ROOT_OF_TRUST) ? kids(hw.get(T.ROOT_OF_TRUST)) : null;
  const challenge = octets(kd[4]);
  return {
    level: ["software", "tee", "strongbox"][level] || "unknown",
    biometricOnly: !!(uat & 2) && !(uat & 1) && !hw.has(T.NO_AUTH),
    perUse: timeout === 0,
    locked: rot ? bool(rot[1]) && int(rot[2]) === 0 : null,
    thisSession: challenge.length === th.length && challenge.every((v, i) => v === th[i]),
    certificates: chain.length,
  };
}

/* ---------------- the server ---------------- */

export async function createSimServer({ onCheck = () => {}, platformPolicy = "biometric" } = {}) {
  const db = await idb();
  const load = (k) => tx(db, "kv", "readonly", (s) => s.get(k));
  const save = (k, v) => tx(db, "kv", "readwrite", (s) => s.put(v, k));

  let statics = await load("statics");
  if (!statics) { statics = exportStatics(createStatics()); await save("statics", statics); }
  const htp = new HtpServer(importStatics(statics));
  let ledgerKey = await load("ledgerKey");
  if (!ledgerKey) { const k = ml_dsa87.keygen(); ledgerKey = { pk: b64u(k.publicKey), sk: b64u(k.secretKey) }; await save("ledgerKey", ledgerKey); }
  const lpk = unb64u(ledgerKey.pk), lsk = unb64u(ledgerKey.sk);
  const ledgerKeyView = { dsa: ledgerKey.pk, fp: toHex(sha3_256(lpk)).slice(0, 32) };

  // accounts, devices, objects (metadata), ledger, log leaves, checkpoints, settings
  const st = (await load("state")) || { accounts: {}, devices: {}, objects: {}, ledger: {}, leaves: [], checkpoints: {}, cards: {}, settings: {} };
  // Anonymous payment, as the access service does it: codes by hash, spent passes by hash, no accounts.
  st.access ||= { codes: {}, spent: {} };
  // Split keys, as the keyshare service keeps them: by document, apart from the envelopes.
  st.keyshare ||= {};
  let passJwk = await load("passKey");
  if (!passJwk) { passJwk = (await newSimIssuerKey()).jwk; await save("passKey", passJwk); }
  const passKey = simIssuerKey(passJwk);
  const persist = () => save("state", st);

  const now = () => Date.now();
  const iso = () => new Date().toISOString();
  const report = (title, checks, extra = {}) => onCheck({ at: now(), title, checks, ...extra });
  const pass = (label, detail) => ({ ok: true, label, detail });
  const fail = (status, code, message, checks = []) => Object.assign(new HtpServerError(status, code, message), { checks });

  /* ---------- ledger + public log ---------- */

  function record(owner, type, detail = {}) {
    const chain = (st.ledger[owner] ||= []);
    const prev = chain.length ? chain[chain.length - 1].hash : GENESIS;
    const seq = chain.length + 1;
    const body = JSON.stringify({ at: iso(), type, detail });
    const hash = entryHash(owner, seq, prev, body);
    chain.push({ seq, body, prev, hash });
    st.leaves.push(b64u(leafHash(owner, seq, hash)));
    return { seq, hash };
  }
  const leafAt = (i) => unb64u(st.leaves[i]);
  function checkpoint() {
    const size = st.leaves.length;
    if (!st.checkpoints[size]) {
      const root = treeHash(leafAt, 0, size);
      const at = now();
      st.checkpoints[size] = { root: toHex(root), at, sig: b64u(ml_dsa87.sign(checkpointMessage(size, root, at), lsk)) };
    }
    const c = st.checkpoints[size];
    return { checkpoint: { size, root: c.root, at: c.at, sig: c.sig }, cosignatures: [], ledgerKey: ledgerKeyView };
  }

  /* ---------- accounts & devices ---------- */

  const accountView = (a, current) => ({
    id: a.id, status: a.status, createdAt: a.createdAt, commit: a.commit,
    dsaFp: toHex(sha3_256(unb64u(a.dsaPk))), kemFp: toHex(sha3_256(unb64u(a.kemPk))),
    devices: Object.values(st.devices).filter((d) => d.account === a.id && !d.revokedAt).map((d) => deviceView(d, current)),
  });
  const deviceView = (d, current) => ({
    id: d.id, platform: d.platform, gateMethod: d.gateMethod, assurance: d.assurance, via: d.via, proof: d.proof,
    enrolledAt: d.enrolledAt, lastSeenAt: d.lastSeenAt, current: d.id === current,
  });

  /** Check and add a device: the same rules as the identity service. */
  function enrolDevice(account, th, dev, via) {
    const checks = [];
    const dsaPk = unb64u(String(dev?.dsaPk || ""));
    if (dsaPk.length !== SIZES.dsaPk) throw fail(400, "bad_key", "Device key has the wrong length");
    const msg = deviceMessage(th, account.id, dsaPk);
    if (!verify(unb64u(String(dev.sigAccount || "")), msg, unb64u(account.dsaPk))) throw fail(401, "bad_proof", "This device was not authorised by the account key.");
    checks.push(pass("Account key authorised this device", "ML-DSA-87 signature over this session's device statement"));
    if (!verify(unb64u(String(dev.sigDevice || "")), msg, dsaPk)) throw fail(401, "bad_proof", "Proof of possession failed for the device key.");
    checks.push(pass("Device key proved possession", "ML-DSA-87 signature by the new device's own key"));
    const gateMethod = String(dev.gateMethod || "unknown").slice(0, 64);
    let proof = "none", livePub = null, assurance = gateMethod === "demo-no-hardware" ? "none" : "os";
    if (dev.live) {
      livePub = unb64u(String(dev.live.pub || ""));
      if (!liveOk(livePub, msg, unb64u(String(dev.live.sig || "")))) throw fail(401, "bad_live_proof", "The device's secure chip did not sign this enrolment.");
      checks.push(pass("Secure chip signed during a live biometric match", "ECDSA P-256 liveness key, usable only right after a live face or fingerprint"));
      const a = dev.live.attestation;
      if (a?.kind === "android-key") {
        try {
          const r = readAndroidAttestation((a.chain || []).map((c) => unb64u(String(c))), th);
          proof = `android-${r.level}`; assurance = "hardware";
          checks.push(pass(`Key lives in ${r.level === "strongbox" ? "StrongBox secure element" : r.level === "tee" ? "the phone's secure hardware (TEE)" : r.level}`, "read from Android key attestation"));
          checks.push({ ok: r.biometricOnly, label: r.biometricOnly ? "Biometric only: no PIN or password can use it" : "Key also accepts a PIN or password", detail: "user authentication type in the attestation" });
          checks.push({ ok: r.perUse, label: r.perUse ? "Needs a live check for every single use" : "Key stays usable after one check", detail: "authentication timeout" });
          if (r.locked !== null) checks.push({ ok: r.locked, label: r.locked ? "Bootloader locked, verified boot" : "Bootloader unlocked or unverified software", detail: "root of trust" });
          checks.push({ ok: r.thisSession, label: r.thisSession ? "Attestation made for this connection" : "Attestation made for another connection", detail: "challenge = this session's transcript" });
          checks.push({ ok: null, label: `Certificate chain (${r.certificates}) to Google's root not checked`, detail: "a real HumID server checks it; the simulation can't" });
          // Refuse what a real server refuses, so the simulation never looks better than the real thing.
          const bad = !r.biometricOnly ? ["pin_allowed", "The key also accepts a PIN or password. HumID needs a live biometric."]
            : !r.perUse ? ["not_per_use", "The key stays usable for a while after one check. HumID needs a check for every use."]
            : r.locked === false ? ["unlocked_device", "The phone's bootloader is unlocked or its software is not verified."]
            : !r.thisSession ? ["wrong_challenge", "The attestation was made for a different session."] : null;
          if (bad) { report("Device refused", checks, { kind: "denied" }); throw fail(403, bad[0], bad[1], checks); }
        } catch (e) { if (e instanceof HtpServerError) throw e; checks.push({ ok: null, label: "Attestation couldn't be read in the simulation", detail: "" }); }
      } else if (a?.kind === "apple-app-attest") {
        proof = "apple-secure-enclave"; assurance = "hardware";
        checks.push({ ok: null, label: "Apple App Attest object received", detail: "a real HumID server verifies it with Apple's root; the simulation can't" });
      } else {
        proof = "unattested-key";
        checks.push({ ok: null, label: "No hardware attestation sent", detail: "" });
      }
    } else if (platformPolicy !== "demo" && gateMethod === "demo-no-hardware") {
      throw fail(403, "device_not_proven", "This device can't prove a live face or fingerprint check.");
    }
    const id = deviceId(dsaPk);
    if (st.devices[id]?.revokedAt) throw fail(409, "device_removed", "This device was removed from the account.");
    const t = iso();
    st.devices[id] = st.devices[id] || {
      id, account: account.id, dsaPk: b64u(dsaPk), livePub: livePub ? b64u(livePub) : null, proof, assurance, gateMethod,
      platform: String(dev.platform || "unknown").slice(0, 40), via, enrolledAt: t, lastSeenAt: t, revokedAt: null,
    };
    return { device: st.devices[id], checks };
  }

  function bind(s, account, device) {
    Object.assign(s, {
      subject: account.id, deviceId: device.id, dsaPk: unb64u(device.dsaPk), livePub: device.livePub ? unb64u(device.livePub) : null,
      proof: device.proof, assurance: device.assurance, gateMethod: device.gateMethod, platform: device.platform,
      dsaFp: toHex(sha3_256(unb64u(account.dsaPk))), kemFp: toHex(sha3_256(unb64u(account.kemPk))),
    });
  }
  const sessionView = (s, extra = {}) => ({ id: s.subject, device: s.deviceId, assurance: s.assurance, proof: s.proof, gateMethod: s.gateMethod, expiresAt: s.expiresAt, idleTimeoutMs: htp.idleMs, ...extra });
  const account = (s) => {
    const a = st.accounts[s.subject];
    if (!a || a.status !== "active") throw fail(404, "unknown_identity", "No such identity");
    return a;
  };
  const lockedDown = (s) => s.duress || !!st.accounts[s.subject]?.lockdownAt;
  const busy = () => fail(503, "busy", "HumID is busy right now. Try again in a few minutes.");
  const needStepUp = (su, what) => { if (!su) throw fail(403, "step_up_required", `${what} needs a fresh biometric check.`); };

  /* ---------- routes (the gateway's, plus the services behind it) ---------- */

  const ROUTES = [];
  const route = (m, p, h, opts = {}) => ROUTES.push({ m, p: new RegExp(`^${p}$`), h, ...opts });
  const OBJ = "([0-9a-f-]{36})";
  const NOT_HERE = (what) => () => { throw fail(501, "not_in_simulation", `${what} needs other people or devices, so it isn't part of the simulation.`); };

  route("GET", "/pass/keys", () => [200, { suite: "RSABSSA-SHA384-PSS-Randomized", keys: [{ ...passKey.publicView, issuing: true }] }]);
  route("POST", "/pass/issue", (s, r) => {
    if (s.subject) throw fail(400, "signed_in", "Get access passes from a session that isn't signed in.");
    const code = parseAccessCode(r.code);
    if (!code) throw fail(400, "code_invalid", "That access code isn't valid. Check it and try again.");
    if (r.kid !== passKey.id) throw fail(409, "key_changed", "The pass key changed. Try again.");
    const h = accessCodeHash(code), row = st.access.codes[h];
    if (!row) throw fail(403, "code_unknown", "This access code wasn't issued by this vault.");
    if (row.used && row.blinded !== r.blinded) throw fail(409, "code_used", "This access code has already been used.");
    const sig = blindSignJwk(passKey, unb64u(String(r.blinded || "")));
    st.access.codes[h] = { used: true, blinded: r.blinded };
    s.closeAfterReply = true;
    report("Access code swapped for a blind pass", [
      pass("Access code is genuine and unused", "only its hash is stored, with no account"),
      pass("Signed without seeing the pass", "RFC 9474 blind RSA: the vault can't recognise this pass later"),
    ], { kind: "pass" });
    return [200, { kid: passKey.id, blindSig: b64u(sig) }];
  });

  route("POST", "/auth/register", (s, r) => {
    // An access pass first, checked and spent the way the access service does it.
    const passChecks = [];
    let spent = null;
    if (!r.pass) throw fail(402, "pass_required", "Creating a HumID needs an access pass.");
    if (!verifyPass(passKey.pub, r.pass)) throw fail(403, "pass_invalid", "This access pass isn't valid.");
    spent = spentId(r.pass);
    if (st.access.spent[spent]) throw fail(409, "pass_spent", "This access pass has already been used.");
    passChecks.push(pass("Access pass is genuine and unspent", "the vault's own signature, on a pass it has never seen before"));
    const keys = {};
    for (const k of Object.keys(SIZES)) { keys[k] = unb64u(String(r[k] || "")); if (keys[k].length !== SIZES[k]) throw fail(400, "bad_key", `${k} has the wrong length`); }
    if (!/^[0-9a-f]{64}$/.test(String(r.commit || ""))) throw fail(400, "bad_commit", "Identity commit must be 64 hex characters");
    if (!verify(unb64u(String(r.sig || "")), registerMessage(s.th, keys, r.commit), keys.dsaPk)) throw fail(401, "bad_proof", "Proof of possession failed: the device does not hold this identity key.");
    const id = identityId(keys.dsaPk);
    const created = !st.accounts[id];
    if (created) st.accounts[id] = { id, kemPk: b64u(keys.kemPk), dsaPk: b64u(keys.dsaPk), xPk: b64u(keys.xPk), commit: r.commit, status: "active", createdAt: iso() };
    const a = st.accounts[id];
    let enrolled;
    try { enrolled = enrolDevice(a, s.th, r.device, "register"); }
    catch (e) { if (created) delete st.accounts[id]; throw e; } // nothing half-made, and the pass stays unspent
    const { device, checks } = enrolled;
    if (created) st.access.spent[spent] = new Date().toISOString().slice(0, 10); // a day, never a time; never an account
    checks.unshift(...passChecks, pass("Account key proved possession", "ML-DSA-87 signature over your public keys and this session"));
    bind(s, a, device);
    if (created) record(id, "identity.created", { platform: s.platform, method: s.gateMethod, assurance: s.assurance });
    record(id, "device.added", { device: device.id, platform: s.platform, via: "register", method: s.gateMethod, assurance: s.assurance, level: s.proof, soleBiometric: r.soleBiometric === true, checks: checks.filter((c) => c.ok).length });
    record(id, "session.opened", { device: device.id, platform: s.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)) });
    let cardSet = false;
    if (created && r.card?.tag) { st.cards[id] = { tag: r.card.tag, blob: r.card.blob, createdAt: iso(), scheme: unb64u(r.card.blob).length === 12 + 65 + 16 ? "quorum" : "full" }; cardSet = true; record(id, "recovery.card_set", { at: "setup", scheme: st.cards[id].scheme }); }
    report("Your HumID was registered", checks, { kind: "enrol" });
    return [created ? 201 : 200, sessionView(s, { created, cardSet })];
  });

  route("POST", "/auth/device", NOT_HERE("Adding a device or recovering"));

  route("POST", "/auth/challenge", (s, r) => {
    s.challenge = { id: r.id, device: r.device, nonce: random(32), exp: now() + 120_000 };
    return [200, { challenge: b64u(s.challenge.nonce), expiresAt: s.challenge.exp }];
  });

  route("POST", "/auth/login", (s, r) => {
    const c = s.challenge; s.challenge = null;
    if (!c || c.id !== r.id || c.device !== r.device || now() > c.exp) throw fail(400, "challenge_invalid", "Request a new challenge");
    const a = st.accounts[r.id];
    if (!a || a.status !== "active") throw fail(404, "unknown_identity", "This vault doesn't know this HumID.");
    const d = st.devices[r.device];
    if (!d || d.account !== a.id) throw fail(404, "unknown_device", "This device is not part of the identity.");
    if (d.revokedAt) { record(a.id, "access.denied", { reason: "device_removed", device: d.id }); throw fail(403, "device_removed", "This device was removed from your HumID."); }
    // As the real gateway: the liveness key signs the challenge, the device key signs it with the duress flag.
    const reported = r.d === 0 || r.d === 1;
    const liveMsg = loginMessage(s.th, `${r.id}/${r.device}`, c.nonce);
    const message = reported ? loginPresenceMessage(s.th, `${r.id}/${r.device}`, c.nonce, r.d) : liveMsg;
    const checks = [pass("Fresh one-time challenge from the server", "32 random bytes, valid for 2 minutes, bound to this encrypted session")];
    if (!verify(unb64u(String(r.sig || "")), message, unb64u(d.dsaPk))) {
      record(a.id, "access.denied", { reason: "bad_login_proof", device: d.id });
      report("Sign-in refused", [...checks, { ok: false, label: "Device key signature didn't verify" }], { kind: "denied" });
      throw fail(401, "bad_proof", "Sign-in proof was rejected.");
    }
    checks.push(pass("Signed by this device's key", "ML-DSA-87 (post-quantum), released only by your biometric"));
    if (d.livePub) {
      if (!liveOk(unb64u(d.livePub), liveMsg, r.live ? unb64u(String(r.live)) : null)) {
        record(a.id, "access.denied", { reason: "no_live_biometric", device: d.id });
        report("Sign-in refused", [...checks, { ok: false, label: "No live biometric signature from the secure chip" }], { kind: "denied" });
        throw fail(401, "bad_live_proof", "Sign-in needs a live face or fingerprint check on this device.");
      }
      checks.push(pass("Signed by the secure chip during a live match", "the same challenge, signed by the phone's liveness key"));
    }
    d.lastSeenAt = iso();
    bind(s, a, d);
    s.gateMethod = String(r.interrupt?.method || d.gateMethod).slice(0, 64);
    record(a.id, "session.opened", { device: d.id, platform: d.platform, method: s.gateMethod, assurance: s.assurance, level: s.proof, proof: proofHash(unb64u(r.sig)), checks: checks.length });
    report("Signed in", checks, { kind: "login" });
    if (reported && r.d === 1) duressSignal(s);
    return [200, sessionView(s)];
  });

  function duressSignal(s) {
    if (s.duress) return;
    s.duress = true;
    const a = account(s);
    a.lockdownAt ||= iso(); a.lastDuressAt = iso();
    record(a.id, "duress.signaled", { device: s.deviceId, platform: s.platform });
    report("Duress signal received", [pass("Account locked down", "devices, recovery and closing your HumID now fail like a busy server"), pass("This session shows only decoy documents")], { kind: "duress", quiet: true });
  }

  route("POST", "/auth/logout", (s) => {
    if (s.subject) record(s.subject, "session.closed", { device: s.deviceId });
    s.closeAfterReply = true;
    return [200, { closed: true }];
  });

  // a step-up approval for one action (method + path), this device, single use, 60 s
  route("POST", "/auth/step-up", (s, r) => {
    const m = String(r.m || "").toUpperCase(), p = String(r.p || "");
    if (!["GET", "POST", "PUT", "DELETE"].includes(m) || !p.startsWith("/") || p.length > 512) throw fail(400, "bad_action", "Unknown action");
    s.stepUps ||= new Map();
    while (s.stepUps.size >= 8) s.stepUps.delete(s.stepUps.keys().next().value);
    const nonce = random(16), exp = now() + STEP_UP_NONCE_MS;
    s.stepUps.set(b64u(nonce), { m, p, exp });
    return [200, { nonce: b64u(nonce), exp, device: s.deviceId }];
  }, { auth: true });

  // Older apps' after-the-fact presence report: the flag is ignored, as by the real gateway.
  route("POST", "/auth/presence", () => [200, { ok: true }], { auth: true });

  route("GET", "/auth/duress", (s) => {
    if (s.duress) return [200, { lockdown: false }];
    const a = account(s);
    const last = a.lastDuressAt ? Date.parse(a.lastDuressAt) : null;
    return [200, { lockdown: !!a.lockdownAt, since: a.lockdownAt || null, lastDuressAt: a.lastDuressAt || null, clearableAt: last ? last + LOCKDOWN_COOLOFF_MS : null }];
  }, { auth: true });

  route("POST", "/auth/duress/clear", (s, r, su) => {
    needStepUp(su, "Lifting lockdown");
    if (s.duress) throw busy();
    const a = account(s);
    if (!a.lockdownAt) return [200, { cleared: false, lockdown: false }];
    if (now() < Date.parse(a.lastDuressAt) + LOCKDOWN_COOLOFF_MS) throw fail(409, "too_soon", "Lockdown can be lifted once it has been calm for a while.");
    const since = a.lockdownAt; a.lockdownAt = null;
    record(a.id, "duress.cleared", { device: s.deviceId, since, proof: su.proof });
    return [200, { cleared: true, lockdown: false, since }];
  }, { auth: true });

  route("GET", "/identity/me", (s) => [200, accountView(account(s), s.deviceId)], { auth: true });

  route("DELETE", "/identity/devices/(dev_[0-9a-f]{24})", (s, r, su, m) => {
    needStepUp(su, "Removing a device");
    const d = st.devices[m[1]];
    if (!d || d.account !== s.subject || d.revokedAt) throw fail(404, "unknown_device", "No such device on your HumID.");
    if (d.id === s.deviceId) throw fail(400, "current_device", "You can't remove the device you're using. Remove it from another device.");
    d.revokedAt = iso();
    record(s.subject, "device.removed", { device: d.id, platform: d.platform, proof: su.proof });
    return [200, { removed: true, device: deviceView(d, s.deviceId) }];
  }, { auth: true, guard: true });

  route("DELETE", "/identity/me", (s, r, su) => {
    needStepUp(su, "Closing your identity");
    const a = account(s);
    let n = 0;
    for (const o of Object.values(st.objects)) if (o.owner === a.id) { delete st.objects[o.id]; delete st.keyshare[o.id]; tx(db, "blobs", "readwrite", (b) => b.delete(o.id)); n++; }
    record(a.id, "vault.erased", { count: n, proof: su.proof });
    delete st.cards[a.id];
    a.status = "closed";
    for (const d of Object.values(st.devices)) if (d.account === a.id) d.revokedAt ||= iso();
    record(a.id, "identity.closed", { proof: su.proof });
    s.closeAfterReply = true;
    return [200, { closed: true, erasedItems: n }];
  }, { auth: true, guard: true });

  /* vault */
  const objView = (o) => ({ id: o.id, size: o.size, index: o.index, sealedAt: o.sealedAt, uploadedAt: o.uploadedAt, updatedAt: o.updatedAt, interruptMethod: o.method, assurance: o.assurance });
  const usage = (owner) => { const mine = Object.values(st.objects).filter((o) => o.owner === owner); return { count: mine.length, bytes: mine.reduce((n, o) => n + o.size, 0), quota: QUOTA }; };
  const own = (s, id) => { const o = st.objects[id]; if (!o || o.owner !== s.subject) throw fail(404, "not_found", "No such item in your vault"); return o; };
  const indexOf = (h) => { const v = h["x-humid-index"]; if (!v) throw fail(400, "missing_index", "Encrypted index entry is required"); const b = unb64u(String(v)); if (b.length < 28 || b.length > 4096) throw fail(400, "bad_index", "Index entry has an invalid size"); return String(v); };

  route("GET", "/vault/objects", (s) => [200, { items: Object.values(st.objects).filter((o) => o.owner === s.subject).sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt)).map(objView), usage: usage(s.subject) }], { auth: true });

  route("POST", "/vault/objects", async (s, r, su, m, body, headers) => {
    if (!isEnvelope(body)) throw fail(400, "not_envelope", "Upload must be a sealed HumID envelope");
    const v = suiteForEnvelope(body).verify(body);
    if (!v.ok) throw fail(400, "bad_signature", "Envelope signature or ciphertext hash is invalid");
    const checks = [pass("Envelope signature verified", "ML-DSA-87 over the encrypted document and its manifest")];
    const signerFp = toHex(sha3_256(Uint8Array.from(atob(v.manifest.signer.mldsa87Pk), (c) => c.charCodeAt(0))));
    if (signerFp !== s.dsaFp) throw fail(403, "not_signer", "Envelope was not signed by your identity");
    checks.push(pass("Signed by your account key", ""));
    if (v.manifest.recipient?.kemPkFp !== s.kemFp) throw fail(403, "not_recipient", "Envelope is not sealed to your identity");
    checks.push(pass("Sealed to your keys only", "ML-KEM-1024 + X25519; the server can't open it"));
    if (s.livePub) {
      const live = v.manifest.interrupt?.live;
      if (!liveOk(s.livePub, sealLiveMessage(v.manifest.ciphertext.sha3_512), live ? unb64u(String(live)) : null)) {
        record(s.subject, "access.denied", { path: "/vault/objects", reason: "no_live_seal" });
        throw fail(403, "no_live_seal", "This document wasn't sealed with a live face or fingerprint check on this device.");
      }
      checks.push(pass("Sealed during a live biometric match", "the secure chip signed this exact ciphertext"));
    }
    const index = indexOf(headers);
    let share = null;
    if (headers["x-humid-share"]) {
      try { share = unb64u(String(headers["x-humid-share"])); } catch {}
      if (!share || share.length !== 32) throw fail(400, "bad_share", "A document key is 32 bytes.");
      checks.push(pass("Its second key went to the keyshare service", "the vault never sees it; the account keys alone can't open this document"));
    }
    if (usage(s.subject).bytes + body.length > QUOTA) throw fail(507, "quota_exceeded", "Your vault is full");
    const id = crypto.randomUUID(), t = iso();
    if (share) st.keyshare[id] = { owner: s.subject, share: b64u(share) };
    await tx(db, "blobs", "readwrite", (b) => b.put(body, id));
    st.objects[id] = { id, owner: s.subject, size: body.length, index, sealedAt: v.manifest.created, uploadedAt: t, updatedAt: t, method: v.manifest.interrupt?.method || null, assurance: v.manifest.interrupt?.assurance || null };
    record(s.subject, "object.sealed", { id, size: body.length, split: !!share, checks: checks.length });
    report("Document stored", checks, { kind: "seal" });
    return [201, objView(st.objects[id])];
  }, { auth: true });

  route(`GET`, `/vault/objects/${OBJ}`, async (s, r, su, m) => {
    needStepUp(su, "Opening a document");
    const o = own(s, m[1]);
    const k = st.keyshare[o.id];
    record(s.subject, "object.opened", { id: o.id, split: !!k, proof: su.proof, method: su.method, assurance: su.assurance });
    report("Document released", [...su.checks, ...(k ? [pass("Its second key released for this document only", "inside this same live check")] : [])], { kind: "open", quiet: true });
    return [200, await tx(db, "blobs", "readonly", (b) => b.get(o.id)), { "content-type": MEDIA_TYPE, "x-humid-size": String(o.size), ...(k ? { "x-humid-share": k.share } : {}) }];
  }, { auth: true });

  route("PATCH", `/vault/objects/${OBJ}`, (s, r, su, m, body, headers) => {
    const o = own(s, m[1]);
    o.index = indexOf(headers); o.updatedAt = iso();
    record(s.subject, "object.updated", { id: o.id });
    return [200, objView(o)];
  }, { auth: true });

  route("DELETE", `/vault/objects/${OBJ}`, async (s, r, su, m) => {
    needStepUp(su, "Deleting a document");
    const o = own(s, m[1]);
    delete st.objects[o.id];
    delete st.keyshare[o.id];
    await tx(db, "blobs", "readwrite", (b) => b.delete(o.id));
    record(s.subject, "object.deleted", { id: o.id, proof: su.proof, method: su.method, assurance: su.assurance });
    return [200, { deleted: o.id }];
  }, { auth: true });

  /* ledger + public log */
  route("GET", "/ledger/events", (s, r, su, m, body, headers, q) => {
    const limit = Math.min(Math.max(Number(q.get("limit")) || 200, 1), 1000);
    const rows = (st.ledger[s.subject] || []).slice(-limit);
    const last = rows[rows.length - 1];
    const signedAt = now();
    const head = last ? { seq: last.seq, hash: last.hash, signedAt, sig: b64u(ml_dsa87.sign(headMessage(s.subject, last.seq, last.hash, signedAt), lsk)) } : null;
    return [200, { owner: s.subject, entries: rows, head, ledgerKey: ledgerKeyView }];
  }, { auth: true });
  route("GET", "/ledger/tlog/checkpoint", () => [200, checkpoint()], { auth: true });
  route("GET", "/ledger/tlog/inclusion", (s) => {
    const cp = checkpoint();
    const chain = st.ledger[s.subject] || [];
    const lastE = chain[chain.length - 1];
    if (!lastE) throw fail(404, "not_in_log", "That entry isn't in the public log yet.");
    const leaf = b64u(leafHash(s.subject, lastE.seq, lastE.hash));
    const index = st.leaves.lastIndexOf(leaf);
    return [200, { ...cp, owner: s.subject, seq: lastE.seq, hash: lastE.hash, index, proof: inclusionProof(leafAt, index, 0, cp.checkpoint.size).map(toHex) }];
  }, { auth: true });
  route("GET", "/ledger/tlog/consistency", (s, r, su, m, body, headers, q) => {
    const size = st.leaves.length;
    const to = Math.min(Number(q.get("to") ?? size), size), from = Math.min(Number(q.get("from")), to);
    return [200, { from, to, proof: consistencyProof(leafAt, from, to).map(toHex) }];
  }, { auth: true });

  /* recovery: the parts one person on one phone can do */
  route("GET", "/recovery/card", (s) => { const c = st.cards[s.subject]; return [200, c ? { exists: true, createdAt: c.createdAt, scheme: c.scheme } : { exists: false }]; }, { auth: true });
  route("PUT", "/recovery/card", (s, r, su) => {
    needStepUp(su, "Making a seal card");
    const scheme = unb64u(String(r.blob || "")).length === 12 + 65 + 16 ? "quorum" : "full";
    st.cards[s.subject] = { tag: r.tag, blob: r.blob, createdAt: iso(), scheme };
    record(s.subject, "recovery.card_set", { scheme, proof: su.proof });
    return [200, { createdAt: st.cards[s.subject].createdAt, replaced: true, scheme }];
  }, { auth: true, guard: true });
  route("DELETE", "/recovery/card", (s, r, su) => {
    needStepUp(su, "Removing your seal card");
    const had = !!st.cards[s.subject]; delete st.cards[s.subject];
    record(s.subject, "recovery.card_removed", { proof: su.proof });
    return [200, { removed: had }];
  }, { auth: true, guard: true });
  route("GET", "/recovery/contacts", () => [200, { n: 0, guardians: [] }], { auth: true });
  route("GET", "/recovery/anchor", () => [200, { available: false, exists: false }], { auth: true });
  route("GET", "/recovery/settings", (s) => [200, { duressAlert: !!st.settings[s.subject]?.duressAlert }], { auth: true });
  route("PUT", "/recovery/settings", (s, r, su) => {
    needStepUp(su, "Changing settings");
    st.settings[s.subject] = { duressAlert: !!r.duressAlert };
    record(s.subject, "settings.changed", { duressAlert: !!r.duressAlert, proof: su.proof });
    return [200, { duressAlert: !!r.duressAlert }];
  }, { auth: true, guard: true });
  route("GET", "/recovery/alerts", () => [200, { alerts: [] }], { auth: true });
  route("GET", "/recovery/protecting", () => [200, { shares: [] }], { auth: true });
  route("GET", "/recovery/protecting/alerts", () => [200, { alerts: [] }], { auth: true });
  route("GET", "/recovery/station", () => [200, { station: false, countries: 0 }], { auth: true });
  route("GET", "/recovery/keys", () => [200, { keys: [], max: 4 }], { auth: true });
  for (const [m, p, what] of [
    ["POST", "/recovery/links", "Adding a device"], ["GET", "/recovery/links/.*", "Adding a device"], ["POST", "/recovery/links/.*", "Adding a device"],
    ["POST", "/recovery/offers", "Being someone's witness"], ["GET", "/recovery/offers/.*", "Choosing witnesses"], ["PUT", "/recovery/contacts", "Choosing witnesses"],
    ["POST", "/recovery/requests.*", "Recovering"], ["GET", "/recovery/requests/.*", "Recovering"], ["GET", "/recovery/help/.*", "Helping someone recover"], ["POST", "/recovery/help/.*", "Helping someone recover"],
    ["PUT", "/recovery/anchor", "Anchoring your ID"],
    ["POST", "/recovery/keys.*", "Adding a security key"], ["DELETE", "/recovery/keys/.*", "Removing a security key"],
  ]) route(m, p, NOT_HERE(what));

  /* ---------- a step-up: both signatures over this exact request ---------- */

  function stepUp(s, seq, meta, body) {
    const p = meta.proof;
    const at = Number(p.at);
    const where = meta.p.replace(/[0-9a-f-]{36}/, ":id");
    if (!Number.isSafeInteger(at) || now() - at > STEP_UP_MAX_AGE_MS || at - now() > CLOCK_SKEW_MS) throw fail(403, "step_up_stale", "Biometric check is too old. Try again.");
    const key = typeof p.nonce === "string" ? p.nonce : "";
    const issued = key && s.stepUps?.get(key);
    if (!issued) throw fail(403, "step_up_unknown", key ? "That approval was already used or never issued. Try again." : "Update HumID to approve this.");
    s.stepUps.delete(key);
    if (issued.m !== meta.m || issued.p !== meta.p) throw fail(403, "step_up_mismatch", "That approval was for a different action.");
    if (issued.exp < now() || Number(p.exp) !== issued.exp) throw fail(403, "step_up_stale", "Biometric check is too old. Try again.");
    const action = actionBytes({ method: meta.m, path: meta.p, device: s.deviceId, nonce: unb64u(key), exp: issued.exp });
    const checks = [pass("Approval is for this exact action", `${meta.m} ${where}, this device, a single-use approval issued for it, under a minute old`)];
    const sig = unb64u(String(p.sig));
    if (!verify(sig, stepUpMessage(s.th, seq, meta.m, meta.p, body, at, action), s.dsaPk)) {
      record(s.subject, "access.denied", { path: where, reason: "bad_step_up" });
      report("Request refused", [...checks, { ok: false, label: "Device key signature didn't verify" }], { kind: "denied" });
      throw fail(401, "bad_proof", "Biometric proof was rejected.");
    }
    checks.push(pass("Signed by this device's key", "ML-DSA-87 over the request and its body"));
    if (s.livePub) {
      let live = null;
      try { live = p.live ? unb64u(String(p.live)) : null; } catch {}
      if (!liveOk(s.livePub, liveMessage(s.th, seq, meta.m, meta.p, at, action), live)) {
        record(s.subject, "access.denied", { path: where, reason: "no_live_biometric" });
        report("Request refused", [...checks, { ok: false, label: "No live biometric signature from the secure chip" }], { kind: "denied" });
        throw fail(401, "bad_live_proof", "This needs a live face or fingerprint check on this device.");
      }
      checks.push(pass("Signed by the secure chip during a live match", "this request slot was signed inside the biometric check"));
    }
    return { at, proof: proofHash(sig), method: String(p.interrupt?.method || s.gateMethod).slice(0, 64), assurance: s.assurance, checks };
  }

  async function dispatch(s, seq, meta, body) {
    const url = new URL(String(meta.p || "/"), "http://inner");
    const r = ROUTES.find((x) => x.m === meta.m && x.p.test(url.pathname));
    if (!r) throw fail(404, "not_found", "No such endpoint");
    if (r.auth && !s.subject) throw fail(401, "sign_in_required", "Sign in first");
    let su = null;
    if (meta.proof) {
      if (!s.subject) throw fail(401, "sign_in_required", "Sign in first");
      su = stepUp(s, seq, meta, body);
    }
    if (r.guard && s.subject && lockedDown(s)) {
      record(s.subject, "access.denied", { path: url.pathname, reason: "lockdown" });
      throw busy();
    }
    const isJson = (meta.h?.["content-type"] || "").startsWith("application/json") || (!meta.h?.["content-type"] && body.length && body[0] === 0x7b);
    const parsed = isJson ? (() => { try { return JSON.parse(fromUtf8(body)); } catch { return {}; } })() : {};
    const out = await r.h(s, parsed, su, url.pathname.match(r.p), body, meta.h || {}, url.searchParams);
    if (su && su.checks && !["GET"].includes(meta.m)) report("Request approved", su.checks, { kind: "stepup", quiet: true });
    return out;
  }

  /* ---------- HTTP surface: what HtpClient fetches ---------- */

  const jsonRes = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

  async function call(frame) {
    let opened;
    try { opened = await htp.open(frame); }
    catch (e) { if (e instanceof HtpServerError) return jsonRes(e.status, { error: e.code, message: e.message }); throw e; }
    const { session: s, seq, meta, body } = opened;
    let status, headers = { "content-type": "application/json" }, out;
    try {
      const [st0, data, hdrs] = await dispatch(s, seq, meta, body);
      status = st0;
      if (data instanceof Uint8Array) { out = data; headers = hdrs || {}; }
      else out = utf8(JSON.stringify(data));
    } catch (e) {
      status = e.status || 500;
      out = utf8(JSON.stringify({ error: e.code || "internal", message: e instanceof HtpServerError ? e.message : `Simulated server error: ${e.message}` }));
    }
    await persist();
    const sealed = await htp.seal(s, seq, status, headers, out);
    if (s.closeAfterReply) htp.drop(s);
    return new Response(sealed, { status: 200, headers: { "content-type": MEDIA_TYPE } });
  }

  async function fetchFn(input, init = {}) {
    const path = new URL(String(input), "sim://humid").pathname;
    await new Promise((r) => setTimeout(r, 60 + Math.random() * 90)); // a little network latency
    if (path.endsWith("/htp/v1/keys")) return jsonRes(200, { ...htp.publicKeys(), policy: { devicePolicy: platformPolicy, registration: "pass", splitKeys: true } });
    if (path.endsWith("/htp/v1/hello")) {
      try { return jsonRes(200, htp.hello(JSON.parse(init.body))); }
      catch (e) { return jsonRes(e.status || 400, { error: e.code || "handshake_failed", message: e.message }); }
    }
    if (path.endsWith("/htp/v1/call")) return call(new Uint8Array(init.body instanceof ArrayBuffer ? init.body : init.body.buffer ? init.body : await new Response(init.body).arrayBuffer()));
    return jsonRes(404, { error: "not_found" });
  }

  /** Wipe the simulated server (Security → Simulation → Reset). */
  async function reset() {
    await tx(db, "kv", "readwrite", (s) => s.clear());
    await tx(db, "blobs", "readwrite", (s) => s.clear());
  }

  /** "Use a demo access code": what a counter or an online store would sell you. */
  function demoAccessCode() {
    const code = newAccessCode();
    st.access.codes[accessCodeHash(parseAccessCode(code))] = { used: false };
    persist();
    return code;
  }

  return { fetch: fetchFn, kid: htp.kid, fingerprint: htp.fingerprint, reset, demoAccessCode };
}
