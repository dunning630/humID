// HumID 3.0 UI kit: the handful of pieces every screen is built from. Each is one
// element with one job; layout and meaning come from brand/base.css. Nothing here
// talks to the server or holds a key: the kit renders what core/ tells it to.
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../brand/icons.jsx";
import { Mark } from "../brand/mark.jsx";
import * as S from "../core/state.js";
import { holdComplete, holdCancel, dismissChipRead } from "../core/index.js";
import { checkPromise } from "./labels.js";

/* ---------- time ---------- */
/** Re-render every `ms`; returns now. Stops while the page is hidden (battery). */
export function useNow(ms = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    let t = null;
    const start = () => { clearInterval(t); setNow(Date.now()); t = setInterval(() => setNow(Date.now()), ms); };
    const onVis = () => (document.hidden ? clearInterval(t) : start());
    start();
    document.addEventListener("visibilitychange", onVis);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", onVis); };
  }, [ms]);
  return now;
}

/* ---------- modal layers: focus in, everything else inert, focus back (APP-12) ---------- */
// A sheet, a pushed screen, the viewer, the check and the chip reader each take the screen. While
// one is open, everything outside it is `inert` (no Tab stop, no screen-reader cursor, no taps),
// focus moves into it, and when it closes focus goes back where it was. Layers stack: the check
// can open over a sheet, and the viewer can open while the check is still fading out.
const modals = [];                  // open layers, oldest first: { el, self }
const held = new Map();             // element → how many open layers hold it inert
// Never made inert: the scrim (a tap on it closes its sheet), toasts (they must still be heard),
// and the check overlay, which is always on top.
const NEVER_INERT = ".scrim, .toasts, .interrupt";
const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const usable = (el) => !!el && el.isConnected && !el.closest("[inert]");
function focusInto(m) {
  const target = (!m.self && [...m.el.querySelectorAll(FOCUSABLE)].find((x) => !x.closest("[inert]"))) || m.el;
  if (target === m.el && !m.el.hasAttribute("tabindex")) m.el.tabIndex = -1;
  target.focus({ preventScroll: true });
}
/** Tab and Shift+Tab go round the top layer's controls instead of out past its last one. */
function wrapTab(e) {
  if (e.key !== "Tab" || !modals.length) return;
  const top = modals[modals.length - 1].el;
  const list = [...top.querySelectorAll(FOCUSABLE)].filter((x) => !x.closest("[inert]") && x.getClientRects().length);
  if (!list.length) { e.preventDefault(); top.focus(); return; }
  const first = list[0], last = list[list.length - 1], at = document.activeElement;
  if (e.shiftKey && (at === first || !top.contains(at))) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && (at === last || !top.contains(at))) { e.preventDefault(); first.focus(); }
}
/** Everything outside `el`, up to the body: its siblings, its parent's siblings, and so on. */
function outside(el) {
  const out = [];
  for (let n = el; n.parentElement && n !== document.body; n = n.parentElement) {
    for (const sib of n.parentElement.children) if (sib !== n && !sib.matches(NEVER_INERT)) out.push(sib);
  }
  return out;
}
/**
 * Make the element in `ref` a modal layer while `active`. `self`: focus the layer itself rather
 * than its first control (the check overlay, so a screen reader reads what's happening).
 */
export function useModal(ref, active = true, { self = false } = {}) {
  // before the layer is painted, so focus never shows behind it for a frame
  useLayoutEffect(() => {
    const el = ref.current;
    if (!active || !el) return;
    const before = document.activeElement;
    const m = { el, self };
    const inerted = outside(el);
    for (const x of inerted) { held.set(x, (held.get(x) || 0) + 1); x.inert = true; }
    if (!modals.length) document.addEventListener("keydown", wrapTab);
    modals.push(m);
    // Under an open check, a new layer waits (focus comes to it when the check closes); a layer
    // whose own sheet opened with it (they mount together, the sheet first) leaves focus there.
    if (!modals.some((o) => o !== m && (o.self || el.contains(o.el)))) focusInto(m);
    return () => {
      for (const x of inerted) { const n = (held.get(x) || 1) - 1; if (n > 0) held.set(x, n); else { held.delete(x); x.inert = false; } }
      modals.splice(modals.indexOf(m), 1);
      if (!modals.length) document.removeEventListener("keydown", wrapTab);
      const lost = !document.activeElement || document.activeElement === document.body || el.contains(document.activeElement);
      if (!lost) return;
      if (usable(before)) before.focus({ preventScroll: true });
      else if (modals.length) focusInto(modals[modals.length - 1]);
    };
  }, [active]);
}

/* ---------- the check (the biological interrupt) ---------- */
// Sending and opening a conversation: the same check, shown as a compact card (core/interrupt.js COMPACT).
const COMPACT_CHECKS = new Set(["send", "read"]);
export function Interrupt() {
  const it = S.interrupt.value;
  const [holding, setHolding] = useState(false);
  const timer = useRef(null);
  const root = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);
  // The check takes the screen: focus moves to it, so a screen reader says what's happening.
  useModal(root, !!it, { self: true });
  if (!it) return null;
  const start = () => { setHolding(true); timer.current = setTimeout(() => { setHolding(false); holdComplete(); }, 1200); };
  const stop = () => { clearTimeout(timer.current); setHolding(false); };
  const title = it.state === "verified" ? "It's you" : it.state === "failed" ? "Not verified" : "Checking it's you";
  return (
    <div class="interrupt" data-state={it.state} data-compact={COMPACT_CHECKS.has(it.purpose) ? "" : undefined} role="dialog" aria-modal="true" aria-labelledby="int-title" aria-live="polite" tabIndex={-1} ref={root}>
      <div class="eyebrow">{title}</div>
      <Mark state={it.state} progress={it.progress} size={COMPACT_CHECKS.has(it.purpose) ? 72 : 168} />
      <h2 id="int-title">{it.label}</h2>
      <p>{it.message}</p>
      {it.needsHold && (
        <>
          <button class={`hold${holding ? " holding" : ""}`} onPointerDown={start} onPointerUp={stop} onPointerLeave={stop} onPointerCancel={stop}
            onKeyDown={(e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); start(); } }} onKeyUp={stop}>
            <span>Press and hold</span>
          </button>
          <button class="link muted" onClick={() => { stop(); holdCancel(); }}>Cancel</button>
        </>
      )}
    </div>
  );
}

const READ_TITLES = {
  chip: { waiting: "Hold your document to the phone", error: "Couldn't read the chip", done: "Chip read", reading: "Reading the chip" },
  key: { waiting: "Hold your security key to the phone", error: "Couldn't use the key", done: "Done with the key", reading: "Talking to your key" },
};

/** Progress while an ID chip, a card or a security key is read over NFC. */
export function ChipReadOverlay() {
  const r = S.chipRead.value;
  const root = useRef(null);
  useModal(root, !!r);
  if (!r) return null;
  const pct = Math.round((r.fraction || 0) * 100);
  const words = READ_TITLES[r.subject === "key" ? "key" : "chip"];
  return (
    <div class="interrupt" data-state={r.stage === "error" ? "failed" : r.stage === "done" ? "verified" : "scanning"} role="dialog" aria-modal="true" aria-labelledby="chip-title" aria-live="polite" ref={root}>
      <div class="eyebrow">{r.kind === "reader" ? "Card reader" : r.subject === "key" ? "Security key" : "Chip reader"}</div>
      <span class="icon-btn" style={{ width: 72, height: 72, background: "var(--surface-2)", color: r.stage === "error" ? "var(--danger)" : "var(--amber)" }}><Icon name={r.subject === "key" ? "seckey" : "nfc"} /></span>
      <h2 id="chip-title">{words[r.stage] || words.reading}</h2>
      <p>{r.message}</p>
      {r.stage === "reading" && <div class="stepper" style={{ width: 200 }} aria-label={`${pct}%`}><i class="on" style={{ flex: `${pct} 0 0` }} /><i style={{ flex: `${100 - pct} 0 0` }} /></div>}
      {r.stage === "error" && <button class="btn primary" data-back onClick={dismissChipRead}>Close</button>}
    </div>
  );
}

/* ---------- toasts ---------- */
export function Toasts() {
  return (
    <div class={`toasts${S.view.value === "app" ? " above-tabs" : ""}`} role="status" aria-live="polite">
      {S.toasts.value.map((t) => (
        <div class="toast" data-kind={t.kind} key={t.id}>
          <Icon name={t.kind === "error" ? "alert" : t.kind === "warn" ? "info" : "check"} />
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------- sheets, pushed screens, menus ---------- */
export function Sheet({ children, onClose, label, title, eyebrow }) {
  const root = useRef(null);
  useModal(root);
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") onClose?.(); };
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, []);
  return (
    <>
      <div class="scrim" onClick={onClose} />
      <section class="sheet" role="dialog" aria-modal="true" aria-label={label || title} ref={root}>
        <div class="grab" />
        {(title || eyebrow) && (
          <header class="row-x" style={{ marginBottom: 12 }}>
            <div class="grow">{eyebrow && <div class="eyebrow">{eyebrow}</div>}{title && <h2>{title}</h2>}</div>
            {onClose && <button class="icon-btn" aria-label="Close" data-back onClick={onClose}><Icon name="x" /></button>}
          </header>
        )}
        {children}
      </section>
    </>
  );
}

/** A full-screen step pushed over the tabs, with a back control the Android Back key also reaches. */
export function Pushed({ children, title, onBack, trailing, class: cls = "" }) {
  const root = useRef(null);
  useModal(root);
  return (
    <section class={`pushed ${cls}`} role="dialog" aria-modal="true" aria-label={title} ref={root}>
      <div class="screen">
        <header class="top">
          <button class="icon-btn" aria-label="Back" data-back onClick={onBack}><Icon name="back" /></button>
          <h1 class="ellipsis" style={{ fontSize: "var(--t-xl)" }}>{title}</h1>
          {trailing || <span class="spacer" />}
        </header>
        {children}
      </div>
    </section>
  );
}

export function Menu({ items, onClose }) {
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, []);
  return (
    <>
      <div class="scrim" style={{ background: "transparent" }} onClick={onClose} />
      <div class="menu" role="menu">
        {items.filter(Boolean).map((it) => (
          <button role="menuitem" class={it.danger ? "danger" : ""} onClick={() => { onClose(); it.onSelect(); }}><Icon name={it.icon} />{it.label}</button>
        ))}
      </div>
    </>
  );
}

/* ---------- confirm: destructive actions say what happens, then ask ---------- */
export function Confirm({ title, text, action, danger = true, onConfirm, onClose, typed }) {
  const [v, setV] = useState("");
  const ok = !typed || v.trim().toUpperCase() === typed;
  return (
    <Sheet onClose={onClose} title={title}>
      <p class="t2">{text}</p>
      {typed && (
        <div class="field" style={{ marginTop: 14 }}>
          <label for="confirm-typed">Type {typed} to continue</label>
          <input id="confirm-typed" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} value={v} onInput={(e) => setV(e.currentTarget.value)} />
        </div>
      )}
      <div class="actions row">
        <button class="btn quiet" onClick={onClose}>Cancel</button>
        <button class={`btn ${danger ? "danger solid" : "primary"}`} disabled={!ok} onClick={() => { onClose(); onConfirm(); }}>{action}</button>
      </div>
    </Sheet>
  );
}

/* ---------- tab bar ---------- */
// Messages appears only when the server runs a messaging relay (4.0).
export const TABS = [
  { id: "vault", label: "Vault", icon: "vault" },
  { id: "messages", label: "Messages", icon: "chat", when: () => S.messagingOn.value },
  { id: "activity", label: "Activity", icon: "activity" },
  { id: "you", label: "You", icon: "person" },
];
export function TabBar() {
  const n = S.msg.value?.newCount || 0;
  return (
    <nav class="tabbar" aria-label="Sections" role="tablist">
      {TABS.filter((t) => !t.when || t.when()).map((t) => (
        <button role="tab" aria-selected={S.tab.value === t.id} aria-current={S.tab.value === t.id ? "page" : undefined}
          onClick={() => { S.sheet.value = null; S.tab.value = t.id; window.scrollTo({ top: 0 }); }}>
          <span class="tab-ico"><Icon name={t.icon} />{t.id === "messages" && n > 0 && <span class="badge" aria-label={`${n} new`}>{n > 9 ? "9+" : n}</span>}</span>
          {t.label}
        </button>
      ))}
    </nav>
  );
}

/* ---------- rows, banners, empties ---------- */
export function Row({ icon, tone, title, sub, trail, onClick, danger, chevron = !!onClick, href }) {
  const Tag = onClick ? "button" : href ? "a" : "div";
  return (
    <Tag class={`row${icon ? "" : " no-lead"}${danger ? " danger" : ""}`} onClick={onClick} href={href}>
      {icon && <span class={`lead ${tone || ""}`}><Icon name={icon} /></span>}
      <span class="body"><span class="title">{title}</span>{sub && <span class="sub">{sub}</span>}</span>
      <span class="trail">{trail}{chevron && <Icon name="chevron" />}</span>
    </Tag>
  );
}
export function Banner({ tone = "", icon = "info", title, text, action, onAction, role = "status" }) {
  return (
    <div class={`banner ${tone}`} role={role}>
      <Icon name={icon} />
      <div><strong>{title}</strong>{text && <span>{text}</span>}</div>
      {action && <button class="btn sm primary" onClick={onAction}>{action}</button>}
    </div>
  );
}
export function Empty({ icon = "folder", title, text, children }) {
  return (
    <div class="empty">
      <Icon name={icon} />
      <h2 class="h3">{title}</h2>
      {text && <p class="small">{text}</p>}
      {children}
    </div>
  );
}
export function Toggle({ checked, onChange, label, hint, disabled }) {
  return (
    <button class="toggle" role="switch" aria-checked={!!checked} disabled={disabled} onClick={() => onChange(!checked)}>
      <span><span class="title">{label}</span>{hint && <span class="hint" style={{ display: "block" }}>{hint}</span>}</span>
      <span class="switch" aria-hidden="true" />
    </button>
  );
}
export function Steps({ steps, current }) {
  return (
    <div class="steps">
      {steps.map((label, i) => (
        <div class="step" data-s={i < current ? "done" : i === current ? "active" : "todo"}>
          <span class="dot" />
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}
export const SEAL_STEPS = ["Sealing on this phone", "Sending", "Stored"];

/** A plain progress line across the top of a multi-step flow. */
export function Stepper({ step, steps, label = "Progress" }) {
  return (
    <div class="stepper" role="progressbar" aria-label={label} aria-valuemin={1} aria-valuemax={steps} aria-valuenow={step + 1} aria-valuetext={`Step ${step + 1} of ${steps}`}>
      {Array.from({ length: steps }, (_, i) => <i class={i < step ? "done" : i === step ? "on" : ""} />)}
    </div>
  );
}

/* ---------- assurance ---------- */
export { proofLabel } from "./labels.js";
/** How a check was proven. `mine`: it was this device's (otherwise "a phone's", "a computer"). */
export function AssurancePill({ assurance, mine = true }) {
  if (assurance === "hardware") return <span class="pill mint"><Icon name="shield" />{mine ? "Proven by this phone's secure chip" : "Proven by a phone's secure chip"}</span>;
  if (assurance === "os") return <span class="pill amber"><Icon name="fingerprint" />{mine ? "Software-protected on this computer" : "Software-protected, on a computer"}</span>;
  return <span class="pill amber"><Icon name="info" />Demo · no sensor</span>;
}

/* ---------- how HumID protects you ---------- */
// The first promise is said only as strongly as this device can keep it (ui/labels.js): a
// computer's checks aren't chip-proven, and the web app can't check at all.
export const protection = () => [
  { icon: "fingerprint", title: "A live check, every time", text: checkPromise() },
  { icon: "lock", title: "Sealed on this phone first", text: "Every document is encrypted here before it goes anywhere." },
  { icon: "server", title: "Your vault can't read it", text: "Not your documents, not even their names. It stores sealed copies, and each new document's second key lives on a separate service." },
  { icon: "shield", title: "Post-quantum encryption", text: "Sealed with a new and a proven kind of encryption together, so a copy taken today stays sealed even against the quantum computers of the future." },
  { icon: "chain", title: "Every access on the record", text: "Activity is a tamper-evident log your phone checks for itself." },
];
export function HowProtected({ onClose }) {
  return (
    <Sheet onClose={onClose} eyebrow="Safe. Secure. Simple." title="How HumID protects you">
      <div class="rows">
        {protection().map((p) => <Row icon={p.icon} tone="mint" title={p.title} sub={p.text} chevron={false} />)}
      </div>
      <div class="actions"><button class="btn primary mint block" onClick={onClose}>Got it</button></div>
    </Sheet>
  );
}
export function HowProtectedLink({ class: cls = "link" }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button class={cls} type="button" onClick={() => setOpen(true)}>How HumID protects you</button>
      {open && <HowProtected onClose={() => setOpen(false)} />}
    </>
  );
}
