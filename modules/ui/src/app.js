// @humid/ui — screen controller. It only talks to the other modules through
// their public interfaces: crypto via suite(), the biometric via a gate
// adapter, persistence via the store, file output via io.

import "./fonts.css";
import "./styles.css";
import { toB64, fromB64, toHex, isEnvelope, EXTENSION, MEDIA_TYPE } from "@humid/codec";
import { suite, suiteForEnvelope, random } from "@humid/crypto";
import { adapter as gateAdapter, bestHardwareGate, demoGate, CANCELLED, ASSURANCE } from "@humid/gate";
import { openStore } from "@humid/store";
import { saveBytes, readFile } from "@humid/io";

const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const fmtSize = (n) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
const fmtTime = (t) => new Date(t).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" });
const wipe = (...b) => { for (const x of b) if (x && x.fill) x.fill(0); };

const MAX_FILE = 512 * 1048576;
const IDLE_LOCK_MS = 300 * 1000;

const state = { store: null, hw: null, identity: null, unlocked: false, staged: [], log: [], idleTimer: null, busy: false, picking: false };

const isDemo = (method) => method === "demo-no-hardware";
const assuranceOf = (id) => id?.assurance || (id?.mode === "demo" ? ASSURANCE.NONE : ASSURANCE.HARDWARE);

/* ---------------- screens ---------------- */

function show(screen) {
  document.body.dataset.view = screen;
  for (const s of document.querySelectorAll("[data-screen]")) s.hidden = s.dataset.screen !== screen;
}

function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg;
  t.dataset.kind = kind;
  t.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.hidden = true; }, 4200);
}

function logEvent(entry) {
  state.log.unshift(entry);
  state.log = state.log.slice(0, 40);
  renderLog();
}

/* ---------------- biological interrupt ---------------- */

function openInterrupt(label, needsHold) {
  const box = $("#interrupt");
  $("#int-purpose").textContent = label;
  $("#int-status").textContent = needsHold
    ? "Demo mode has no hardware gate. Press and hold to stand in for the sensor read."
    : "Confirm with your device biometric when the system prompt appears.";
  $("#int-hold").hidden = !needsHold;
  box.dataset.state = "waiting";
  box.hidden = false;
  return {
    done(ok) {
      box.dataset.state = ok ? "pass" : "fail";
      setTimeout(() => { box.hidden = true; }, ok ? 650 : 1400);
    },
    status(msg) { $("#int-status").textContent = msg; },
  };
}

function holdToConfirm() {
  return new Promise((resolve, reject) => {
    const hold = $("#int-hold"), cancel = $("#int-cancel");
    let timer = null;
    const cleanup = () => {
      hold.onpointerdown = hold.onpointerup = hold.onpointerleave = cancel.onclick = hold.onkeydown = hold.onkeyup = null;
      hold.classList.remove("holding");
    };
    const start = () => {
      hold.classList.add("holding");
      timer = setTimeout(() => { cleanup(); resolve(); }, 1400);
    };
    const stop = () => { clearTimeout(timer); hold.classList.remove("holding"); };
    hold.onpointerdown = start;
    hold.onpointerup = stop;
    hold.onpointerleave = stop;
    hold.onkeydown = (e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); start(); } };
    hold.onkeyup = stop;
    cancel.onclick = () => { stop(); cleanup(); reject(new Error(CANCELLED)); };
  });
}

const notSatisfied = (e) => e?.name === "NotAllowedError" || e?.message === CANCELLED;

async function interrupt(purpose, label) {
  state.busy = true;
  const gate = gateAdapter(state.identity.gate.adapter);
  const ui = openInterrupt(label, !!gate.needsHold);
  const cancel = $("#int-cancel");
  try {
    if (gate.needsHold) { cancel.hidden = false; await holdToConfirm(); }
    else { cancel.onclick = null; cancel.hidden = true; }
    const r = await gate.release(state.identity.gate.handle, purpose, label);
    ui.done(true);
    return r;
  } catch (e) {
    ui.status(notSatisfied(e) ? "The biometric check was cancelled or timed out." : e.message);
    ui.done(false);
    logEvent({ purpose, label, ok: false, error: notSatisfied(e) ? "interrupt not satisfied" : e.message, interrupt: { at: new Date().toISOString() } });
    throw e;
  } finally {
    setTimeout(() => { state.busy = false; }, 800);
  }
}

/** Run fn with the full key set, which exists only for the length of this call. */
async function withKeys(purpose, label, fn) {
  const { secret, interrupt: rec } = await interrupt(purpose, label);
  const S = suite(state.identity.suite);
  let seed, keys;
  try {
    seed = await S.unwrapSeed(secret, state.identity.wrapped, fromB64(state.identity.bindingId));
    keys = S.deriveKeys(seed);
    if (toB64(keys.dsaPk) !== state.identity.pub.dsaPk) throw new Error("Unlocked keys do not match the enrolled identity.");
    const out = await fn(keys, rec);
    logEvent({ purpose, label, ok: true, interrupt: rec });
    return out;
  } catch (e) {
    logEvent({ purpose, label, ok: false, error: e.message, interrupt: rec });
    throw e;
  } finally {
    wipe(secret, seed);
    S.wipeKeys(keys);
  }
}

/* ---------------- enrol / unlock / lock ---------------- */

async function enroll(gate) {
  const buttons = document.querySelectorAll("#enroll button");
  buttons.forEach((b) => (b.disabled = true));
  state.busy = true;
  $("#enroll-msg").textContent = gate.needsHold ? "Generating keys…" : "Waiting for your device biometric…";
  let secret, seed, keys;
  try {
    const S = suite();
    const e = await gate.enroll();
    secret = e.secret;
    seed = random(64);
    const wrapped = await S.wrapSeed(secret, seed, fromB64(e.bindingId));
    keys = S.deriveKeys(seed);
    const pub = S.publicOf(keys);
    const assurance = e.interrupt.assurance;
    state.identity = {
      mode: assurance === ASSURANCE.NONE ? "demo" : "hardware",
      assurance,
      method: e.interrupt.method,
      gate: { adapter: gate.id, handle: e.handle },
      bindingId: e.bindingId,
      wrapped,
      commit: toHex(S.identityCommit(pub, S.sha3_256(fromB64(e.bindingId)))),
      pub: { kemPk: toB64(pub.kemPk), dsaPk: toB64(pub.dsaPk), xPk: toB64(pub.xPk) },
      enrolledAt: new Date().toISOString(),
      suite: S.ID,
    };
    await state.store.putIdentity(state.identity);
    logEvent({ purpose: "enroll", label: "Identity bound to this device", ok: true, interrupt: e.interrupt });
    enterVault();
  } catch (err) {
    $("#enroll-msg").textContent = notSatisfied(err) ? "The biometric prompt was cancelled or timed out. Try again." : err.message;
  } finally {
    wipe(secret, seed);
    if (keys) suite().wipeKeys(keys);
    buttons.forEach((b) => (b.disabled = false));
    if (gate !== state.hw?.adapter) $("#btn-enroll-hw").disabled = !state.hw?.probe.available;
    state.busy = false;
  }
}

async function unlock() {
  $("#gate-msg").textContent = "";
  try {
    await withKeys("launch", "Open HumID", async () => {});
    enterVault();
  } catch (e) {
    $("#gate-msg").textContent = notSatisfied(e) ? "Presence was not confirmed. HumID stays locked." : e.message;
  }
}

function enterVault() {
  state.unlocked = true;
  show("vault");
  renderIdentity();
  renderVault();
  resetIdle();
}

function lock(reason) {
  if (!state.unlocked) return;
  state.unlocked = false;
  state.staged = [];
  renderStaged();
  clearTimeout(state.idleTimer);
  renderGate();
  if (reason) $("#gate-msg").textContent = reason;
}

function resetIdle() {
  clearTimeout(state.idleTimer);
  if (state.unlocked) state.idleTimer = setTimeout(() => lock("Locked after 5 minutes without activity."), IDLE_LOCK_MS);
}

function renderGate() {
  show("gate");
  const id = state.identity;
  const a = assuranceOf(id);
  $("#enroll").hidden = !!id;
  $("#verify").hidden = !id;
  $("#gate-mode").textContent = !id ? "No identity on this device"
    : a === ASSURANCE.NONE ? "Demo identity · no hardware gate"
    : a === ASSURANCE.OS ? "OS-verified biometric on this device"
    : "Hardware-gated identity on this device";
  $("#gate-mode").dataset.mode = !id ? "none" : a === ASSURANCE.NONE ? "demo" : a === ASSURANCE.OS ? "os" : "hardware";
  const hw = state.hw;
  $("#btn-enroll-hw").disabled = !hw?.probe.available;
  $("#cap-reason").textContent = hw?.probe.available ? "" : hw?.probe.reason || "";
  $("#cap-reason").hidden = !$("#cap-reason").textContent;
  $("#spec-gate").textContent = hw?.probe.available
    ? `${hw.probe.label}, ${hw.probe.assurance === ASSURANCE.HARDWARE ? "hardware-held key released per read" : "OS-verified match, keyring-held key"}`
    : "No biometric gate on this device (demo mode only)";
}

/* ---------------- staging & sealing ---------------- */

function stage(files) {
  for (const f of files) {
    if (f.size > MAX_FILE) { toast(`${f.name} is ${fmtSize(f.size)}. This build seals files up to 512 MB.`, "warn"); continue; }
    state.staged.push(f);
  }
  renderStaged();
}

async function sealStaged() {
  if (!state.staged.length) return;
  const files = state.staged.slice();
  const btn = $("#btn-seal");
  btn.disabled = true;
  const progress = $("#seal-progress");
  try {
    const loaded = [];
    for (const f of files) loaded.push({ f, bytes: await readFile(f) });
    const envelopes = loaded.filter((x) => isEnvelope(x.bytes));
    const plain = loaded.filter((x) => !isEnvelope(x.bytes));
    const myKemPk = fromB64(state.identity.pub.kemPk);

    for (const { f, bytes } of envelopes) {
      let S;
      try { S = suiteForEnvelope(bytes); } catch (e) { toast(`${f.name}: ${e.message}`, "warn"); continue; }
      const v = S.verify(bytes);
      const toMe = S.isAddressedTo(v.manifest, myKemPk);
      await state.store.putItem({
        id: crypto.randomUUID(), name: f.name.replace(/\.humid$/, ""), type: "envelope", size: null,
        sealedAt: v.manifest.created, importedAt: new Date().toISOString(), envelope: bytes,
        sigOk: v.ok, toMe, source: "imported",
        interruptMethod: v.manifest.interrupt?.method || "unknown",
        assurance: v.manifest.interrupt?.assurance,
        signerFp: S.fingerprint(fromB64(v.manifest.signer.mldsa87Pk)),
      });
      toast(v.ok ? `${f.name}: ML-DSA-87 signature valid${toMe ? "" : ", sealed to another identity"}.` : `${f.name}: signature check failed.`, v.ok ? "" : "warn");
    }

    if (plain.length) {
      const label = plain.length === 1 ? `Seal ${plain[0].f.name}` : `Seal ${plain.length} files`;
      await withKeys("seal", label, async (keys, rec) => {
        const S = suite(state.identity.suite);
        const recipient = { kemPk: myKemPk, xPk: fromB64(state.identity.pub.xPk) };
        let i = 0;
        for (const { f, bytes } of plain) {
          i++;
          progress.hidden = false;
          progress.textContent = `Sealing ${i} of ${plain.length}: ${f.name}`;
          await new Promise((r) => setTimeout(r, 0));
          const { envelope, manifest, plainHash } = await S.seal({ bytes, name: f.name, type: f.type }, keys, recipient, { identityCommit: state.identity.commit, interrupt: rec });
          wipe(bytes);
          await state.store.putItem({
            id: crypto.randomUUID(), name: f.name, type: f.type || "application/octet-stream", size: f.size,
            sealedAt: manifest.created, envelope, plainHash, sigOk: true, toMe: true, source: "sealed",
            interruptMethod: rec.method, assurance: rec.assurance, signerFp: S.fingerprint(keys.dsaPk),
          });
        }
      });
      toast(plain.length === 1 ? `${plain[0].f.name} sealed. The original was not stored.` : `${plain.length} files sealed under one interrupt. Originals were not stored.`);
    }
    state.staged = [];
    renderStaged();
    renderVault();
  } catch (e) {
    if (!notSatisfied(e)) toast(e.message, "warn");
  } finally {
    btn.disabled = false;
    progress.hidden = true;
  }
}

async function exportBytes(bytes, name, type) {
  try {
    const r = await saveBytes(bytes, name, type);
    if (r.saved && r.where) toast(`Saved ${name}.`);
  } catch (e) {
    toast(`Could not save ${name}: ${e.message || e}`, "warn");
  }
}

async function decrypt(item) {
  try {
    await withKeys("decrypt", `Decrypt ${item.name}`, async (keys) => {
      const { meta, bytes } = await suiteForEnvelope(item.envelope).open(item.envelope, keys);
      await exportBytes(bytes, meta.name, meta.type);
      toast(`${meta.name} decrypted and verified against its SHA3-512 hash.`);
    });
  } catch (e) {
    if (!notSatisfied(e)) toast(e.message, "warn");
  }
}

function showManifest(item) {
  const { manifest } = suiteForEnvelope(item.envelope).verify(item.envelope);
  const m = structuredClone(manifest);
  m.kem.mlkem1024Ct = m.kem.mlkem1024Ct.slice(0, 32) + `… (${fromB64(manifest.kem.mlkem1024Ct).length} bytes)`;
  m.signer.mldsa87Pk = m.signer.mldsa87Pk.slice(0, 32) + `… (${fromB64(manifest.signer.mldsa87Pk).length} bytes)`;
  $("#manifest-title").textContent = item.name;
  $("#manifest-body").textContent = JSON.stringify(m, null, 2);
  $("#manifest").hidden = false;
  $("#manifest-close").focus();
}

/* ---------------- rendering ---------------- */

function renderIdentity() {
  const id = state.identity;
  const a = assuranceOf(id);
  $("#id-commit").textContent = id.commit.match(/.{4}/g).slice(0, 8).join(" ");
  $("#id-mode").textContent = a === ASSURANCE.NONE ? "Demo · no hardware" : a === ASSURANCE.OS ? "OS biometric" : "Hardware gate";
  $("#id-mode").dataset.mode = id.mode;
  $("#id-mode").dataset.assurance = a;
  $("#demo-banner").hidden = a !== ASSURANCE.NONE;
}

function renderStaged() {
  const list = $("#staged");
  list.replaceChildren();
  for (const [i, f] of state.staged.entries()) {
    const row = el("li", "staged-row");
    row.append(el("span", "fname", f.name), el("span", "mono dim", fmtSize(f.size)));
    const x = el("button", "icon-btn", "×");
    x.setAttribute("aria-label", `Remove ${f.name}`);
    x.onclick = () => { state.staged.splice(i, 1); renderStaged(); };
    row.append(x);
    list.append(row);
  }
  const n = state.staged.length;
  $("#staged-wrap").hidden = !n;
  $("#btn-seal").textContent = n === 1 ? "Seal 1 file" : `Seal ${n} files`;
  $("#staged-total").textContent = `${n} staged · ${fmtSize(state.staged.reduce((s, f) => s + f.size, 0))}`;
}

function provenanceChip(item) {
  if (!item.sigOk) return el("span", "chip chip-bad", "Signature invalid");
  if (isDemo(item.interruptMethod)) return el("span", "chip chip-demo", "Signed · demo");
  if (item.assurance === ASSURANCE.OS) return el("span", "chip chip-os", "ML-DSA-87 ✓ · OS biometric");
  return el("span", "chip chip-ok", "ML-DSA-87 ✓ · human");
}

async function renderVault() {
  const items = (await state.store.listVault()).sort((a, b) => (b.importedAt || b.sealedAt).localeCompare(a.importedAt || a.sealedAt));
  const rows = $("#vault-rows");
  rows.replaceChildren();
  $("#vault-empty").hidden = items.length > 0;
  $("#vault-table").hidden = items.length === 0;
  $("#vault-count").textContent = `${items.length} sealed · ${fmtSize(items.reduce((s, i) => s + i.envelope.length, 0))} on device`;
  for (const item of items) {
    const tr = el("tr");
    const name = el("td", "cell-name");
    name.append(el("div", "fname", item.name), el("div", "mono dim small", `${item.source === "imported" ? "Imported envelope" : fmtSize(item.size)} · ${fmtTime(item.sealedAt)}`));
    const prov = el("td");
    prov.append(provenanceChip(item));
    if (!item.toMe) prov.append(el("div", "dim small", "Sealed to another identity"));
    const size = el("td", "mono num", fmtSize(item.envelope.length));
    const actions = el("td", "actions");
    const dec = el("button", "btn ghost", "Decrypt");
    dec.disabled = !item.toMe || !item.sigOk;
    dec.onclick = () => decrypt(item);
    const exp = el("button", "btn ghost", "Export");
    exp.onclick = () => exportBytes(item.envelope, `${item.name}${EXTENSION}`, MEDIA_TYPE);
    const man = el("button", "btn ghost", "Manifest");
    man.onclick = () => showManifest(item);
    const del = el("button", "icon-btn", "×");
    del.setAttribute("aria-label", `Remove ${item.name} from vault`);
    del.onclick = async () => { await state.store.delItem(item.id); renderVault(); };
    actions.append(dec, exp, man, del);
    tr.append(name, prov, size, actions);
    rows.append(tr);
  }
}

function renderLog() {
  const list = $("#log");
  if (!list) return;
  list.replaceChildren();
  for (const e of state.log) {
    const row = el("li", `log-row ${e.ok ? "" : "log-fail"}`);
    row.append(el("span", "log-dot"), el("span", "log-label", e.label));
    const it = e.interrupt;
    const detail = isDemo(it?.method) ? "demo hold"
      : it?.method ? `${it.method} · UV ${it.uv ? "✓" : "✗"}${it.signCount != null ? ` · count ${it.signCount}` : ""}`
      : "";
    row.append(el("span", "mono dim small", `${e.ok ? detail : e.error} · ${new Date(it?.at || Date.now()).toLocaleTimeString()}`));
    list.append(row);
  }
  $("#log-empty").hidden = state.log.length > 0;
}

/* ---------------- boot ---------------- */

export async function start() {
  state.store = await openStore();
  $("#memory-banner").hidden = state.store.persistent;
  $("#preview-banner").hidden = globalThis.top === globalThis || !!globalThis.__TAURI_INTERNALS__;
  state.hw = await bestHardwareGate();
  try { state.identity = await state.store.getIdentity(); }
  catch (e) { state.identity = null; $("#enroll-msg").textContent = e.message; }
  renderGate();

  $("#btn-enroll-hw").onclick = () => state.hw?.probe.available && enroll(state.hw.adapter);
  $("#btn-enroll-demo").onclick = () => enroll(demoGate());
  $("#btn-verify").onclick = unlock;
  $("#btn-lock").onclick = () => lock("Locked.");
  $("#btn-seal").onclick = sealStaged;
  $("#btn-clear").onclick = () => { state.staged = []; renderStaged(); };
  $("#manifest-close").onclick = () => { $("#manifest").hidden = true; };
  $("#btn-reset").onclick = () => { $("#reset-confirm").hidden = false; };
  $("#reset-no").onclick = () => { $("#reset-confirm").hidden = true; };
  $("#reset-yes").onclick = async () => {
    const id = state.identity;
    await state.store.clearVault();
    await state.store.clearIdentity();
    if (id) { try { await gateAdapter(id.gate.adapter).forget(id.gate.handle); } catch {} }
    state.identity = null;
    state.log = [];
    $("#reset-confirm").hidden = true;
    lock();
    renderGate();
  };

  const input = $("#file-input");
  input.onchange = () => { state.picking = false; stage(input.files); input.value = ""; };
  const drop = $("#dropzone");
  const pick = () => { state.picking = true; input.click(); };
  addEventListener("focus", () => setTimeout(() => { state.picking = false; }, 1500));
  drop.onclick = pick;
  drop.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); stage(e.dataTransfer.files); };

  for (const ev of ["pointerdown", "keydown"]) document.addEventListener(ev, resetIdle, { passive: true });
  // Lock when the app leaves the screen, but not while the OS biometric sheet
  // or file picker (which also hide the page on mobile) is up.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && !state.busy && !state.picking) lock("Locked when HumID left the screen.");
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#manifest").hidden = true; });
  renderLog();
}

start();
