// Shared UI pieces: interrupt overlay, toasts, sheets, tab bar, formatting.
import { useEffect, useRef, useState } from "preact/hooks";
import { Mark } from "./brand.jsx";
import { Icon } from "./icons.jsx";
import * as S from "./core/state.js";
import { holdComplete, holdCancel } from "./core/controller.js";

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
  if (assurance === "hardware") return <span class="pill mint"><Icon name="shield" />Hardware-bound</span>;
  if (assurance === "os") return <span class="pill amber"><Icon name="fingerprint" />OS biometric</span>;
  return <span class="pill amber"><Icon name="info" />Demo · no sensor</span>;
}

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
