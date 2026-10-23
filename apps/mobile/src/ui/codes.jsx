// Codes, cards, QR codes, the scanner, chip details, proofs, the location stamp.
// Carried from 2.x where the logic was right; re-dressed for 3.0.
import { useEffect, useRef, useState } from "preact/hooks";
import qrcode from "qrcode-generator";
import { qrPayload, parseQr } from "@humid/recovery";
import { DEMO_BUILD } from "@humid/gate";
import { Icon } from "../brand/icons.jsx";
import * as S from "../core/state.js";
import { IN_APP } from "../core/config.js";
import { setDemoHolder, demoChipHint } from "../core/nfc.js";
import { watchPlace, formatCoords, formatAccuracy, REASONS } from "../core/place.js";
import { Toggle } from "./kit.jsx";

/** A 12- or 16-character code to read from one screen and type on another. */
export function CodeBox({ code, label }) {
  const groups = (code || "").replace(/-/g, "").match(/.{1,4}/g) || [];
  return (
    <div class="codebox" aria-label={label || "Code"} role="group">
      {label && <div class="eyebrow" style={{ marginBottom: 6 }}>{label}</div>}
      <div class="code">{groups.map((g, i) => <span key={i}>{g}</span>)}</div>
    </div>
  );
}

/** The recovery card, as it should be written down. */
export function CardBox({ code }) {
  const [prefix, ...groups] = (code || "").split("-");
  return (
    <div class="codebox" role="group" aria-label="Recovery card">
      <div class="eyebrow" style={{ marginBottom: 6 }}>Recovery card</div>
      <div class="code"><b>{prefix}</b>{groups.map((g, i) => <span key={i}>{g}</span>)}</div>
    </div>
  );
}

/** Checks the person really has a copy of their recovery card: type back one random group. */
export function CardConfirm({ code, onChange }) {
  const groups = (code || "").split("-").slice(1);
  const [n] = useState(() => 1 + Math.floor(Math.random() * Math.max(1, groups.length)));
  const [v, setV] = useState("");
  // Crockford base32: O reads as 0, I and L as 1, so a handwriting slip still matches.
  const norm = (s) => String(s || "").toUpperCase().replace(/[^0-9A-Z]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  const ok = groups.length > 0 && norm(v) === norm(groups[n - 1]);
  useEffect(() => { onChange?.(ok); }, [ok]);
  return (
    <div class="field" style={{ marginTop: 14 }}>
      <label for="card-check">To check your copy, type group {n} of {groups.length}</label>
      <input autocorrect="off" id="card-check" class="input code" maxLength={7} autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="XXXXX"
        value={v} onInput={(e) => setV(e.currentTarget.value)} />
      {ok ? <span class="hint mint"><Icon name="check" /> That matches</span>
        : norm(v).length >= 5 ? <span class="hint amber">That isn't group {n}. Check what you wrote.</span>
        : <span class="hint">Write it on paper. It's shown once.</span>}
    </div>
  );
}

/** Printing works in a browser and in the Windows and Linux apps; phones and the Mac app have no print dialog here. */
const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
export const CAN_PRINT = typeof window !== "undefined" && typeof window.print === "function"
  && !/iPhone|iPad|iPod|Android/.test(ua) && !(IN_APP && /Macintosh/.test(ua));

/** The card as it prints: only this shows on paper (see @media print in base.css). */
export function PrintableCard({ code }) {
  return (
    <div class="print-sheet" aria-hidden="true">
      <h1>HumID recovery card</h1>
      <p style={{ fontFamily: "monospace", fontSize: "18pt", letterSpacing: "0.1em" }}>{code}</p>
      <p>One of the proofs that bring your vault back if you lose every device. On its own it opens nothing:
        recovery also needs your witnesses or your ID chip, then waits while your devices can veto.</p>
      <p>Keep it somewhere safe and offline, away from your ID. Printed {new Date().toLocaleDateString()}.</p>
    </div>
  );
}

/* ---------------- QR codes: show and scan ---------------- */
// A QR carries the same 12-character code you could type, what it's for and when it
// expires. The code is what commits to the keys, so scanning is only a convenience:
// what's scanned is checked like a typed code, never opened or run.

export function QrCode({ kind, code, expiresAt, size = 184, payload = null }) {
  let q;
  try { q = qrcode(0, "M"); q.addData(payload || qrPayload(kind, code, expiresAt)); q.make(); }
  catch { return null; }
  const n = q.getModuleCount();
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
  return (
    <div class="qr" role="img" aria-label="QR code with the same code">
      <svg viewBox={`0 0 ${n + 8} ${n + 8}`} width={size} height={size} shape-rendering="crispEdges">
        <rect width={n + 8} height={n + 8} fill="#fff" rx="2" />
        <path d={d} fill="#0B1410" />
      </svg>
    </div>
  );
}

const QR_FOR = { link: "adding a device", recover: "a recovery", contact: "a witness offer", admin: "a server change" };

/**
 * Point the camera at a HumID QR code of the `expect` kind. Calls onCode({ kind, code }).
 * Anything else is ignored with a hint; nothing scanned is acted on until the code is checked.
 * Uses the platform's barcode detector where there is one, jsQR otherwise. Frames are
 * analysed at 640 px wide, five times a second: enough for a QR, light on the battery.
 */
export function Scanner({ onCode, onCancel, expect, parse = null }) {
  const video = useRef(null);
  const [err, setErr] = useState(null);
  const [hint, setHint] = useState(null);
  useEffect(() => {
    let stream = null, stop = false, timer = null, detector = null, zx = null;
    const canvas = document.createElement("canvas");
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw new Error("This device can't open its camera here. Type the code instead.");
        // The long side only, never a crop (a width and a height cut a portrait frame square),
        // at a modest frame rate: a QR code needs few pixels and the look runs every 200 ms.
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment", width: { ideal: 1280 }, frameRate: { ideal: 15, max: 30 }, resizeMode: "none" }, audio: false });
        if (stop) return;
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        if ("BarcodeDetector" in globalThis) {
          try { detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] }); } catch { detector = null; }
        }
        // No native detector (iOS WebViews): the same zxing-cpp reader the ID scanner uses,
        // already bundled and loaded from this origin. One decoder, no second dependency.
        if (!detector) zx = await (await import("../core/scan.js")).qrReader();
        const tick = async () => {
          if (stop) return;
          const v = video.current;
          if (v && v.readyState >= 2 && !document.hidden) {
            let text = null;
            try {
              if (detector) text = (await detector.detect(v))[0]?.rawValue || null;
              else {
                const w = Math.min(640, v.videoWidth), h = Math.round((w / v.videoWidth) * v.videoHeight);
                canvas.width = w; canvas.height = h;
                const g = canvas.getContext("2d", { willReadFrequently: true });
                g.drawImage(v, 0, 0, w, h);
                text = (await zx.read(g.getImageData(0, 0, w, h)))[0] || null;
              }
            } catch { /* keep looking */ }
            if (text) {
              // parse: a screen's own reader (4.0 invite codes); otherwise HumID's 12-character codes
              const hit = parse ? parse(text) : parseQr(text);
              if (!hit) setHint("That isn't a HumID code. Type the code instead.");
              else if (!parse && hit.kind !== expect) setHint(`That code is for ${QR_FOR[hit.kind]}, not this.`);
              else if (hit.expiresAt <= Date.now()) setHint("That code has expired. Start again on the other device.");
              else { stop = true; onCode(hit); return; }
            }
          }
          timer = setTimeout(tick, 200);
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
      {err ? <div class="banner amber"><Icon name="info" /><div><strong>Can't scan</strong><span>{err}</span></div></div>
        : <div class="scan-frame"><video ref={video} playsInline muted /><i /></div>}
      {hint && !err && <p class="fine center" role="status" style={{ marginTop: 8 }}>{hint}</p>}
      <button class="btn ghost block" style={{ marginTop: 12 }} data-back onClick={onCancel}>Type the code instead</button>
    </div>
  );
}

/** A code field with a Scan button. A scanned code is handed back at once (no second tap). */
export function CodeInput({ id, label, value, onInput, expect, onScanned }) {
  const [scan, setScan] = useState(false);
  if (scan) return <Scanner expect={expect} onCancel={() => setScan(false)} onCode={(c) => { setScan(false); onInput(c.code); onScanned?.(c.code); }} />;
  return (
    <div class="field">
      <label for={id}>{label}</label>
      <div class="row-x">
        <input autocorrect="off" id={id} class="input code grow" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="XXXX-XXXX-XXXX" value={value} onInput={(e) => onInput(e.currentTarget.value)} />
        <button class="btn quiet" type="button" onClick={() => setScan(true)} aria-label="Scan a QR code"><Icon name="scan" />Scan</button>
      </div>
    </div>
  );
}

/* ---------------- the location stamp ---------------- */

/**
 * The location stamp on a seal screen. 3.0: off until the person turns it on, and the
 * choice is remembered on this device (prefs.placeStamp); the phone's location is
 * watched only while it's on. Returns { take, element }.
 */
export function usePlaceStamp(setPref) {
  const [on, setOnState] = useState(() => !!S.prefs.value.placeStamp);
  const [st, setSt] = useState({ reason: "waiting" });
  const watch = useRef(null);
  const setOn = (v) => { setOnState(v); setPref?.({ placeStamp: v }); };
  useEffect(() => {
    if (!on) return;
    const w = watchPlace({ onChange: setSt });
    watch.current = w;
    setSt(w.status);
    return () => { w.stop(); if (watch.current === w) watch.current = null; };
  }, [on]);
  const hint = !on ? "Off. Turn it on to seal where this was, inside the encrypted index: your vault never sees it."
    : st.stamp ? `Here: ${formatCoords(st.stamp)} · ${formatAccuracy(st.stamp.accuracy)}`
    : REASONS[st.reason] || REASONS.waiting;
  const element = <Toggle checked={on} onChange={setOn} label="Location stamp" hint={hint} />;
  return { take: () => (on ? watch.current : null), element };
}

/* ---------------- proofs ---------------- */

export const PROOFS = [
  { id: "witness", icon: "users", title: "Witnesses", short: "witnesses" },
  { id: "anchor", icon: "passport", title: "ID chip", short: "ID chip" },
  { id: "card", icon: "idcard", title: "Recovery card", short: "recovery card" },
  { id: "key", icon: "seckey", title: "Security key", short: "security key" },
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
/** The wait for each pair of proofs, for the "what you'll need" screen. */
export const WAITS = [
  { pair: "ID chip at a station + anything", wait: "about 24 hours" },
  { pair: "Witnesses + your recovery card, security key or ID chip", wait: "about 72 hours" },
  { pair: "Any two of recovery card, security key, ID chip read on your phone", wait: "about 7 days" },
];

/* ---------------- ID chips ---------------- */

const yymmdd = (iso) => (iso ? iso.slice(2, 4) + iso.slice(5, 7) + iso.slice(8, 10) : "");

/** What opens a chip: the passport details from the photo page, or an ID card's 6-digit CAN. Never saved. */
export function ChipAccess({ onChange, title = "Details from the document", initial = null, note = "These only open the chip. HumID doesn't keep them, and never reads your photo." }) {
  const [mode, setMode] = useState("mrz");
  const [num, setNum] = useState(initial?.number || "");
  const [birth, setBirth] = useState(initial?.birth || "");
  const [expiry, setExpiry] = useState(initial?.expiry || "");
  const [can, setCan] = useState("");
  useEffect(() => {
    const n = num.toUpperCase().replace(/[^0-9A-Z]/g, "");
    if (mode === "can") onChange(/^\d{6}$/.test(can.replace(/\D/g, "")) ? { can: can.replace(/\D/g, "") } : null);
    else onChange(n.length >= 6 && birth && expiry ? { number: n, birth: yymmdd(birth), expiry: yymmdd(expiry) } : null);
  }, [mode, num, birth, expiry, can]);
  return (
    <div class="stack" style={{ marginTop: 14 }}>
      <div class="eyebrow">{title}</div>
      <div class="seg" role="tablist">
        <button role="tab" aria-pressed={mode === "mrz"} onClick={() => setMode("mrz")}>Passport or ID</button>
        <button role="tab" aria-pressed={mode === "can"} onClick={() => setMode("can")}>Card number (CAN)</button>
      </div>
      {mode === "mrz" ? (
        <>
          <div class="field"><label for="doc-num">Document number</label><input autocorrect="off" id="doc-num" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} value={num} maxLength={22} onInput={(e) => setNum(e.currentTarget.value)} /></div>
          <div class="row-x" style={{ alignItems: "stretch" }}>
            <div class="field grow"><label for="doc-birth">Date of birth</label><input id="doc-birth" class="input" type="date" value={birth} onInput={(e) => setBirth(e.currentTarget.value)} /></div>
            <div class="field grow"><label for="doc-exp">Expiry date</label><input id="doc-exp" class="input" type="date" value={expiry} onInput={(e) => setExpiry(e.currentTarget.value)} /></div>
          </div>
        </>
      ) : (
        <div class="field"><label for="doc-can">6-digit card access number</label><input autocorrect="off" spellcheck={false} id="doc-can" class="input code" inputMode="numeric" autocomplete="off" maxLength={7} value={can} onInput={(e) => setCan(e.currentTarget.value)} />
          <span class="hint">Printed on the front of most European and many other ID cards.</span></div>
      )}
      {DEMO_SIM && <DemoChipFill onFill={(h) => { setMode("mrz"); setNum(h.number); setBirth(`19${h.birth.slice(0, 2)}-${h.birth.slice(2, 4)}-${h.birth.slice(4)}`); setExpiry(`20${h.expiry.slice(0, 2)}-${h.expiry.slice(2, 4)}-${h.expiry.slice(4)}`); }} />}
      <p class="small muted">{note}</p>
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
      <div class="row-x">
        <input autocorrect="off" spellcheck={false} autocomplete="off" id="demo-chip-holder" class="input grow" value={name} onInput={(e) => setName(e.currentTarget.value)} />
        <button class="btn quiet" type="button" onClick={async () => { setDemoHolder(name); onFill(await demoChipHint(name)); }}>Fill details</button>
      </div>
    </div>
  );
}
