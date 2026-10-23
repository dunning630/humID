// Small pieces the You screens share. Nothing here talks to the kernel.
import { useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { useNow } from "../../ui/kit.jsx";
import { fmtLeft } from "../../ui/format.js";
import * as S from "../../core/state.js";

/** One choice out of a few, as a segmented radiogroup. */
export function Choice({ id, label, hint, value, options, onPick }) {
  return (
    <div class="stack" style={{ gap: 6, paddingBlock: 10 }}>
      <div id={`${id}-label`}><strong style={{ fontSize: "var(--t-sm)" }}>{label}</strong>{hint && <span class="hint small muted" style={{ display: "block", marginTop: 2 }}>{hint}</span>}</div>
      <div class="seg" role="radiogroup" aria-labelledby={`${id}-label`}>
        {options.map(([v, text]) => (
          <button type="button" role="radio" aria-checked={value === v} data-pref={`${id}:${v}`} onClick={() => onPick(v)}
            style={value === v ? { background: "var(--surface-3)", color: "var(--text)" } : undefined}>{text}</button>
        ))}
      </div>
    </div>
  );
}

/** A checkbox line in a checklist. */
export function Check({ checked, onChange, children, id }) {
  return (
    <label class="row-x" style={{ minHeight: "var(--tap)", alignItems: "flex-start", gap: 12, cursor: "pointer" }}>
      <input id={id} type="checkbox" checked={!!checked} onChange={(e) => onChange(e.currentTarget.checked)} style={{ width: 22, height: 22, marginTop: 2, flex: "none", accentColor: "var(--mint-deep)" }} />
      <span class="small">{children}</span>
    </label>
  );
}

/** A heading line inside a card: title left, something (a pill, a button) right. */
export function Head({ title, children, level: H = "h3" }) {
  return <div class="row-x" style={{ justifyContent: "space-between", gap: 8 }}><H>{title}</H>{children}</div>;
}

/** "in 2 h 4 min" — a leaf that ticks on its own, so its parent never re-renders for it. */
export function Countdown({ until, prefix = "", suffix = "", offsetMs = 0, expired = "now" }) {
  const now = useNow(until ? 1000 : 3_600_000) + offsetMs;
  const left = until - now;
  return <>{prefix}{left > 0 ? human(left) : expired}{suffix}</>;
}
/** "4 min", "1 h 12 min", "2 d 4 h": never a clock-looking "4:05". */
export const human = (ms) => {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.ceil(s / 60)} min`;
  return fmtLeft(ms);
};

/** A collapsed-by-default block. */
export function Disclosure({ title, sub, children, open: initial = false }) {
  const [open, setOpen] = useState(initial);
  return (
    <div class="card">
      <button class="row-x" style={{ width: "100%", textAlign: "left", minHeight: "var(--tap)" }} aria-expanded={open} onClick={() => setOpen(!open)}>
        <span class="grow"><strong>{title}</strong>{sub && <span class="small muted" style={{ display: "block" }}>{sub}</span>}</span>
        <Icon name="chevron" style={{ transform: open ? "rotate(90deg)" : undefined, transition: "transform var(--d-fast)" }} />
      </button>
      {open && <div style={{ marginTop: 12 }}>{children}</div>}
    </div>
  );
}

/** A fact line: key left, value right. */
/** A label and a value. `stacked` puts a long value (a key, a fingerprint) under its label instead of beside it. */
export function Fact({ k, v, stacked = false }) {
  if (stacked) return <div class="row no-lead"><span class="body"><span class="title" style={{ fontWeight: 500 }}>{k}</span><span class="sub selectable" style={{ wordBreak: "break-all" }}>{v}</span></span></div>;
  return <div class="row no-lead"><span class="body"><span class="title" style={{ fontWeight: 500 }}>{k}</span></span><span class="trail" style={{ textAlign: "right", whiteSpace: "normal", flex: "0 1 60%", justifyContent: "flex-end" }}>{v}</span></div>;
}

/** A whole code: 12 characters, or 16 for a recovery request (CRYPTO-08). */
export const twelve = (code) => [12, 16].includes(String(code || "").replace(/[^0-9a-z]/gi, "").length);
/** Push one of the You detail screens. */
export const go = (type, extra = {}) => { S.push.value = { type, ...extra }; };
export const back = () => { S.push.value = null; };
