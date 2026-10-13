// Shared UI pieces: interrupt overlay, toasts, sheets, tab bar, formatting.
import { useEffect, useRef, useState } from "preact/hooks";
import { Mark } from "./brand.jsx";
import { Icon } from "./icons.jsx";
import * as S from "./core/state.js";
import { holdComplete, holdCancel, dismissChipRead } from "./core/controller.js";
import qrcode from "qrcode-generator";
import { qrPayload, parseQr } from "@humid/recovery";
import { DEMO_BUILD } from "@humid/gate";
import { setDemoHolder, demoChipHint } from "./core/nfc.js";

export const fmtSize = (n) => n == null ? "" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB` : `${(n / 1048576).toFixed(1)} MB`;
export const fmtDate = (t) => new Date(t).toLocaleDateString([], { month: "short", day: "numeric", year: new Date(t).getFullYear() === new Date().getFullYear() ? undefined : "numeric" });
export const fmtTime = (t) => new Date(t).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
export function fmtAgo(t) {
  const s = (Date.now() - new Date(t)) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return fmtDate(t);
}
export function dayLabel(t) {
  const d = new Date(t), today = new Date();
  const y = new Date(); y.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" });
}
export const groupKey = (s) => (s || "").match(/.{1,4}/g) || [];

/* ---------------- biological interrupt ---------------- */

export function InterruptOverlay() {
  const it = S.interrupt.value;
  const [holding, setHolding] = useState(false);
  const timer = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);
  if (!it) return null;
  const start = () => { setHolding(true); timer.current = setTimeout(() => { setHolding(false); holdComplete(); }, 1200); };
  const stop = () => { clearTimeout(timer.current); setHolding(false); };
  const title = it.state === "verified" ? "Verified" : it.state === "failed" ? "Not verified" : "Biological interrupt";
  return (
    <div class="interrupt" data-state={it.state} role="dialog" aria-modal="true" aria-labelledby="int-title" aria-live="polite">
      <div class="eyebrow">{title}</div>
      <Mark state={it.state} progress={it.progress} />
      <h2 id="int-title">{it.label}</h2>
      <p>{it.message}</p>
      {it.needsHold && (
        <>
          <button class={`hold${holding ? " holding" : ""}`} onPointerDown={start} onPointerUp={stop} onPointerLeave={stop} onPointerCancel={stop}
            onKeyDown={(e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); start(); } }} onKeyUp={stop}>
            <span>Press and hold</span>
          </button>
          <button class="link" onClick={() => { stop(); holdCancel(); }}>Cancel</button>
        </>
      )}
    </div>
  );
}

/* ---------------- toasts ---------------- */

export function Toasts() {
  return (
    <div class="toasts" role="status" aria-live="polite">
      {S.toasts.value.map((t) => (
        <div class="toast" data-kind={t.kind} key={t.id}>
          <Icon name={t.kind === "error" ? "alert" : t.kind === "warn" ? "info" : "check"} />
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------------- sheet ---------------- */

export function Sheet({ children, onClose, label }) {
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") onClose?.(); };
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, []);
  return (
    <>
      <div class="scrim" onClick={onClose} />
      <section class="sheet" role="dialog" aria-modal="true" aria-label={label}>
        <div class="grab" />
        {children}
      </section>
    </>
  );
}

/* ---------------- tab bar ---------------- */

const TABS = [
  { id: "vault", label: "Vault", icon: "vault" },
  { id: "activity", label: "Activity", icon: "activity" },
  { id: "security", label: "Security", icon: "shield" },
];

export function TabBar() {
  return (
    <div class="tabbar">
      <nav aria-label="Sections">
        {TABS.map((t) => (
          <button aria-current={S.tab.value === t.id ? "page" : undefined} onClick={() => { S.sheet.value = null; S.tab.value = t.id; window.scrollTo({ top: 0 }); }}>
            <Icon name={t.icon} />
            {t.label}
          </button>
        ))}
      </nav>
    </div>
  );
}

export function Steps({ steps, current }) {
  return (
    <div class="steps">
      {steps.map((label, i) => (
        <div class="step" data-s={i < current ? "done" : i === current ? "active" : "todo"}>
          <span class="dot">{i < current && <Icon name="check" />}</span>
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}

export function AssurancePill({ assurance }) {
  if (assurance === "hardware") return <span class="pill mint"><Icon name="shield" />Live check · chip-proven</span>;
  if (assurance === "os") return <span class="pill amber"><Icon name="fingerprint" />Live biometric · OS</span>;
  return <span class="pill amber"><Icon name="info" />Demo · no sensor</span>;
}

const PROOF = {
  "android-strongbox": "Android StrongBox chip attested the key",
  "android-tee": "Android secure chip attested the key",
  "apple-secure-enclave": "Apple Secure Enclave attested the key",
};
/** What the server verified about a device's live check. */
export const proofLabel = (proof, assurance) =>
  PROOF[proof] || (assurance === "os" ? "Biometric only, not hardware-proven" : assurance === "none" ? "No sensor (development only)" : "Not proven");

/* ---------------- codes, cards, countdowns ---------------- */

/** Re-render every second; returns now. */
export function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}

/** "2 d 4 h", "3 h 12 min", "4:05" */
export function fmtLeft(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

/** A 12-character code to read from one screen and type on another. */
export function CodeBox({ code, label }) {
  const groups = (code || "").replace(/-/g, "").match(/.{1,4}/g) || [];
  return (
    <div class="codebox" aria-label={label || "Code"} role="group">
      {groups.map((g, i) => <span key={i}>{g}</span>)}
    </div>
  );
}

/** The recovery card, as it should be written down. */
export function CardBox({ code }) {
  const [prefix, ...groups] = (code || "").split("-");
  return (
    <div class="cardbox" role="group" aria-label="Recovery card">
      <div class="eyebrow">Recovery card</div>
      <div class="cardcode"><b>{prefix}</b>{groups.map((g, i) => <span key={i}>{g}</span>)}</div>
    </div>
  );
}

/* ---------------- QR codes: show and scan ---------------- */
// A QR carries the same 12-character code you could type. The code is what
// commits to the keys, so scanning is only a convenience.


/** A QR code for a code: kind is link | recover | contact. */
export function QrCode({ kind, code, size = 184 }) {
  let q;
  try { q = qrcode(0, "M"); q.addData(qrPayload(kind, code)); q.make(); }
  catch { return null; }
  const n = q.getModuleCount();
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
  return (
    <div class="qr" role="img" aria-label="QR code with the same code">
      <svg viewBox={`0 0 ${n + 8} ${n + 8}`} width={size} height={size} shape-rendering="crispEdges">
        <rect width={n + 8} height={n + 8} fill="#f4f7f2" rx="2" />
        <path d={d} fill="#06150b" />
      </svg>
    </div>
  );
}

/**
 * Point the camera at a HumID QR code. Calls onCode({ kind, code }).
 * Uses the platform's barcode detector where there is one, jsQR otherwise.
 * Typing the code always works too, so a missing camera is never a dead end.
 */
export function Scanner({ onCode, onCancel, expect }) {
  const video = useRef(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    let stream = null, stop = false, timer = null, detector = null, jsqr = null;
    const canvas = document.createElement("canvas");
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw new Error("This device can't open its camera here. Type the code instead.");
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
        if (stop) return;
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        if ("BarcodeDetector" in globalThis) {
          try { detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] }); } catch { detector = null; }
        }
        if (!detector) jsqr = (await import("jsqr")).default;
        const tick = async () => {
          if (stop) return;
          const v = video.current;
          if (v && v.readyState >= 2) {
            let text = null;
            try {
              if (detector) text = (await detector.detect(v))[0]?.rawValue || null;
              else {
                const w = Math.min(640, v.videoWidth), h = Math.round((w / v.videoWidth) * v.videoHeight);
                canvas.width = w; canvas.height = h;
                const g = canvas.getContext("2d", { willReadFrequently: true });
                g.drawImage(v, 0, 0, w, h);
                text = jsqr(g.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: "dontInvert" })?.data || null;
              }
            } catch { /* keep looking */ }
            const hit = text && parseQr(text);
            if (hit && (!expect || !hit.kind || hit.kind === expect)) { stop = true; onCode(hit); return; }
          }
          timer = setTimeout(tick, 180);
        };
        tick();
      } catch (e) {
        setErr(e?.name === "NotAllowedError" ? "Camera access was declined. Type the code instead." : e?.message || "The camera isn't available. Type the code instead.");
      }
    })();
    return () => { stop = true; clearTimeout(timer); stream?.getTracks().forEach((t) => t.stop()); };
  }, []);
  return (
    <div class="scanner">
      {err ? <div class="banner warn"><span class="b-ico"><Icon name="info" /></span><div><strong>Can't scan</strong><span>{err}</span></div></div>
        : <div class="scan-frame"><video ref={video} playsInline muted /><i /></div>}
      <button class="btn ghost block" style={{ marginTop: 12 }} onClick={onCancel}>Type the code instead</button>
    </div>
  );
}

/** A code field with a Scan button. */
export function CodeInput({ id, label, value, onInput, expect }) {
  const [scan, setScan] = useState(false);
  if (scan) return <Scanner expect={expect} onCancel={() => setScan(false)} onCode={(c) => { setScan(false); onInput(c.code); }} />;
  return (
    <div class="field">
      <label for={id}>{label}</label>
      <div class="code-input">
        <input id={id} class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="XXXX-XXXX-XXXX" value={value} onInput={(e) => onInput(e.currentTarget.value)} />
        <button class="btn quiet sm" type="button" onClick={() => setScan(true)} aria-label="Scan a QR code"><Icon name="scan" />Scan</button>
      </div>
    </div>
  );
}

/** A labelled on/off switch. */
export function Toggle({ checked, onChange, label, hint, disabled }) {
  return (
    <label class="toggle">
      <span><strong>{label}</strong>{hint && <span>{hint}</span>}</span>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.currentTarget.checked)} />
      <i aria-hidden="true" />
    </label>
  );
}

/** The three kinds of proof, and which ones a recovery or an account has. */
export const PROOFS = [
  { id: "witness", icon: "users", title: "Witnesses", short: "witnesses" },
  { id: "anchor", icon: "passport", title: "ID chip", short: "ID chip" },
  { id: "card", icon: "idcard", title: "Seal card", short: "seal card" },
];
export function ProofMeter({ have }) {
  const n = PROOFS.filter((p) => have.includes(p.id)).length;
  return (
    <div class="proofmeter" aria-label={`${n} of 2 proofs`}>
      {PROOFS.map((p) => <span data-on={have.includes(p.id) ? "1" : "0"}><Icon name={p.icon} />{p.title}</span>)}
    </div>
  );
}

/** How long a recovery with these proofs waits, in words (mirrors quorumDelay on the server). */
export function tierText(kinds, anchorMode) {
  const k = new Set(kinds || []);
  if (k.size < 2) return null;
  if (k.has("anchor") && anchorMode === "station") return "about 24 hours";
  if (k.has("witness")) return "about 72 hours";
  return "about 7 days";
}

/* ---------------- ID chips ---------------- */

const yymmdd = (iso) => (iso ? iso.slice(2, 4) + iso.slice(5, 7) + iso.slice(8, 10) : "");

/**
 * What opens a chip: the passport details from the photo page (document number,
 * birth date, expiry), or an ID card's 6-digit CAN. Kept only in this form and
 * the read; never saved. onChange(access | null).
 */
export function ChipAccess({ onChange, title = "Details from the document" }) {
  const [mode, setMode] = useState("mrz");
  const [num, setNum] = useState("");
  const [birth, setBirth] = useState("");
  const [expiry, setExpiry] = useState("");
  const [can, setCan] = useState("");
  useEffect(() => {
    const n = num.toUpperCase().replace(/[^0-9A-Z]/g, "");
    if (mode === "can") onChange(/^\d{6}$/.test(can.replace(/\D/g, "")) ? { can: can.replace(/\D/g, "") } : null);
    else onChange(n.length >= 6 && birth && expiry ? { number: n, birth: yymmdd(birth), expiry: yymmdd(expiry) } : null);
  }, [mode, num, birth, expiry, can]);
  return (
    <div class="chip-access">
      <div class="eyebrow" style={{ marginTop: 14 }}>{title}</div>
      <div class="cats" role="tablist" style={{ marginTop: 8 }}>
        <button role="tab" aria-pressed={mode === "mrz"} onClick={() => setMode("mrz")}><Icon name="passport" />Passport or ID</button>
        <button role="tab" aria-pressed={mode === "can"} onClick={() => setMode("can")}><Icon name="idcard" />ID card number (CAN)</button>
      </div>
      {mode === "mrz" ? (
        <>
          <div class="field"><label for="doc-num">Document number</label><input id="doc-num" class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} value={num} maxLength={22} onInput={(e) => setNum(e.currentTarget.value)} /></div>
          <div class="split">
            <div class="field"><label for="doc-birth">Date of birth</label><input id="doc-birth" type="date" value={birth} onInput={(e) => setBirth(e.currentTarget.value)} /></div>
            <div class="field"><label for="doc-exp">Expiry date</label><input id="doc-exp" type="date" value={expiry} onInput={(e) => setExpiry(e.currentTarget.value)} /></div>
          </div>
        </>
      ) : (
        <div class="field"><label for="doc-can">6-digit card access number</label><input id="doc-can" class="mono" inputMode="numeric" autocomplete="off" maxLength={7} value={can} onInput={(e) => setCan(e.currentTarget.value)} />
          <span class="hint">Printed on the front of most European and many other ID cards.</span></div>
      )}
      {DEMO_SIM && <DemoChipFill onFill={(h) => { setMode("mrz"); setNum(h.number); setBirth(`19${h.birth.slice(0, 2)}-${h.birth.slice(2, 4)}-${h.birth.slice(4)}`); setExpiry(`20${h.expiry.slice(0, 2)}-${h.expiry.slice(2, 4)}-${h.expiry.slice(4)}`); }} />}
      <p class="small muted" style={{ marginTop: 6 }}>These only open the chip. HumID doesn't keep them, and never reads your photo.</p>
    </div>
  );
}

const DEMO_SIM = DEMO_BUILD && typeof globalThis.__TAURI_INTERNALS__?.invoke !== "function";

/** Development builds in a browser: pick the demo passport holder and fill in their details. */
function DemoChipFill({ onFill }) {
  const [name, setName] = useState("Demo Person");
  return (
    <div class="field">
      <label for="demo-chip-holder">Development build: simulated chip for</label>
      <div class="code-input">
        <input id="demo-chip-holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
        <button class="btn quiet sm" type="button" onClick={async () => { setDemoHolder(name); onFill(await demoChipHint(name)); }}>Fill details</button>
      </div>
    </div>
  );
}

/** Progress while a chip is being read (the phone's own sheet may sit on top on iPhone). */
export function ChipReadOverlay() {
  const r = S.chipRead.value;
  if (!r) return null;
  const pct = Math.round((r.fraction || 0) * 100);
  return (
    <div class="interrupt chip-read" data-state={r.stage === "error" ? "failed" : r.stage === "done" ? "verified" : "scanning"} role="dialog" aria-modal="true" aria-labelledby="chip-title" aria-live="polite">
      <div class="eyebrow">{r.kind === "reader" ? "Card reader" : "Chip reader"}</div>
      <div class="chip-ico"><Icon name="passport" /></div>
      <h2 id="chip-title">{r.stage === "waiting" ? "Hold your document to read it" : r.stage === "error" ? "Couldn't read the chip" : r.stage === "done" ? "Chip read" : "Reading your chip"}</h2>
      <p>{r.message}</p>
      {r.stage === "reading" && <div class="bar" aria-label={`${pct}%`}><i style={{ width: `${pct}%` }} /></div>}
      {r.stage === "error" && <button class="btn primary" onClick={dismissChipRead}>Close</button>}
    </div>
  );
}

/* ---------------- simulation build ---------------- */

/** A strip across the top: this is a simulation, and what the server last checked. */
export function SimStrip() {
  const last = S.simLog.value[0];
  return (
    <button class="sim-strip" onClick={() => (S.simShow.value = last || { title: "Simulation", checks: [], empty: true })}>
      <span class="dot" aria-hidden="true" />
      <span><b>Simulation</b> · vault server runs on this phone</span>
      {last && <span class="sim-last">{last.checks.filter((c) => c.ok).length} checks ✓</span>}
    </button>
  );
}

const MARK = { true: "check", false: "x", null: "info" };

/** What the simulated server checked for one action, one line per check. */
export function ChecksSheet() {
  const r = S.simShow.value;
  if (!r) return null;
  const close = () => (S.simShow.value = null);
  const okCount = r.checks.filter((c) => c.ok === true).length;
  return (
    <Sheet onClose={close} label="Server checks">
      <div class="eyebrow">Simulated vault server · {fmtTime(r.at || Date.now())}</div>
      <h2 style={{ marginTop: 6 }}>{r.title}</h2>
      {r.empty ? (
        <p class="lede" style={{ marginTop: 10 }}>This build runs HumID's vault server inside the app. Your phone connects to it over the real post-quantum channel (HTP/1: ML-KEM-1024 + X25519), and it checks every sign-in and sensitive action the way a real server does. Create your HumID or unlock to see the checks.</p>
      ) : (
        <>
          <p class="small muted" style={{ marginTop: 6 }}>{okCount} of {r.checks.length} checks passed{r.checks.some((c) => c.ok === null) ? " · notes marked ⓘ" : ""}</p>
          <div class="checks">
            {r.checks.map((c) => (
              <div class="check-row" data-ok={String(c.ok)}>
                <span class="c-ico"><Icon name={MARK[String(c.ok)]} /></span>
                <div><strong>{c.label}</strong>{c.detail && <span>{c.detail}</span>}</div>
              </div>
            ))}
          </div>
        </>
      )}
      {S.simLog.value.length > 1 && (
        <>
          <div class="eyebrow" style={{ marginTop: 18 }}>Earlier</div>
          <div class="rows">
            {S.simLog.value.slice(0, 12).filter((x) => x !== r).map((x) => (
              <button class="row linkrow" onClick={() => (S.simShow.value = x)}>
                <span class="k">{x.title}</span><span class="v">{x.checks.filter((c) => c.ok).length} ✓ · {fmtTime(x.at)}</span>
              </button>
            ))}
          </div>
        </>
      )}
      <div class="actions"><button class="btn secure block" onClick={close}>Done</button></div>
    </Sheet>
  );
}
