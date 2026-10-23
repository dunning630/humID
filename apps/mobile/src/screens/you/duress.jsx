// Duress: if you're ever forced to unlock, a gesture opens HumID showing only chosen
// documents while your vault quietly locks itself. Everything here is staged and saved
// with one Save (one check at most: only "Tell my witnesses" needs the server).
// Practice runs the gesture against this screen only: nothing is sent anywhere.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Mark } from "../../brand/mark.jsx";
import { Pushed, Sheet, Row, Toggle, Empty } from "../../ui/kit.jsx";
import * as S from "../../core/state.js";
import { saveDuress, loadDuress, setWitnessAlert, setDecoys as applyDecoys, createTapCounter, createHoldTimer, isDuressHold, describeTaps, TAP_WINDOW_MS, DURESS_HOLD_MS } from "../../core/index.js";
import { back, Check } from "./common.jsx";

const HOLD_S = Math.round(DURESS_HOLD_MS / 1000);
const GESTURES = [
  { id: "taps", icon: "sparkle", title: "Tap the mark three times", desc: "Instead of pressing Unlock, tap the HumID mark three times quickly." },
  { id: "hold", icon: "fingerprint", title: `Hold Unlock for ${HOLD_S} seconds`, desc: `Press and hold the Unlock button for ${HOLD_S} seconds, then let go.` },
];

export function Duress() {
  const decoy = S.decoy.value;
  const info = S.duressInfo.value;
  const d = decoy ? { enabled: false, gesture: "taps" } : info?.setting || { enabled: false, gesture: "taps" };
  const [enabled, setEnabled] = useState(!!d.enabled);
  const [gesture, setGesture] = useState(d.gesture || "taps");
  const [alert, setAlert] = useState(!!info?.alert);
  // In a decoy session S.items holds only the decoys, so the list looks like any account's.
  // Saving there changes nothing anywhere (saveDuress and setDecoys know the session).
  const items = S.items.value;
  const [decoys, setDecoys] = useState(() => new Set(items.filter((i) => i.decoy).map((i) => i.id)));
  const [preview, setPreview] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => { loadDuress(); }, []);
  const off = !!S.offline.value;
  const changedAlert = !decoy && alert !== !!info?.alert;
  const save = async () => {
    setBusy(true);
    try {
      if (!(await saveDuress({ enabled, gesture }))) return;
      if (!(await applyDecoys(items.map((it) => ({ item: it, on: decoys.has(it.id) }))))) return;
      if (changedAlert && !(await setWitnessAlert(alert))) return;
      back();
    } finally { setBusy(false); }
  };
  return (
    <Pushed title="Duress gesture" onBack={back}>
      <p class="t2 small">Unlock with your duress gesture and HumID opens normally, but shows only the documents you chose. Meanwhile your vault locks devices, recovery and closing your account for 24 hours, and any recovery waits twice as long for 14 days. <b>Nothing on screen will say so</b>, to you or to anyone watching.</p>

      <div class="card" style={{ marginTop: 14 }}>
        <Toggle label="Duress gesture" hint="Set on this device. Each device has its own." checked={enabled} onChange={setEnabled} />
        {enabled && (
          <div class="options" style={{ marginTop: 10 }} role="radiogroup" aria-label="Gesture">
            {GESTURES.map((g) => (
              <button class="option" role="radio" aria-checked={gesture === g.id} onClick={() => setGesture(g.id)}>
                <span class="lead"><Icon name={g.icon} /></span>
                <span><span class="title">{g.title}</span><span class="sub" style={{ display: "block" }}>{g.desc}</span></span>
                {gesture === g.id ? <Icon name="check" /> : <span />}
              </button>
            ))}
          </div>
        )}
        {!decoy && <Toggle label="Tell my witnesses" hint="They see a duress alert next time they open HumID. Only turn this on if they'd know what to do." checked={alert} onChange={setAlert} disabled={off} />}
      </div>

      {enabled && <Practice gesture={gesture} />}

      <div class="card" style={{ marginTop: 12 }}>
        <div class="row-x" style={{ justifyContent: "space-between" }}><h3>Decoy documents</h3><span class="pill">{decoys.size ? `${decoys.size} shown` : "None"}</span></div>
        <p class="small muted" style={{ marginTop: 4 }}>What someone sees if you unlock with the gesture. Choose things that look ordinary.</p>
        {items.length === 0 ? <p class="small muted" style={{ marginTop: 8 }}>Nothing in your vault yet. Seal a document first, then choose it here.</p> : (
          <div class="checklist">
            {items.map((it) => (
              <Check key={it.id} checked={decoys.has(it.id)} onChange={(v) => { const s = new Set(decoys); v ? s.add(it.id) : s.delete(it.id); setDecoys(s); }}>{it.name}</Check>
            ))}
          </div>
        )}
        {items.length > 0 && <button class="link" style={{ marginTop: 8 }} onClick={() => setPreview(true)}><Icon name="eye" />Preview the decoy view</button>}
      </div>

      <p class="small muted" style={{ marginTop: 10 }}>Your face or fingerprint still unlocks either way, so no one can tell from watching. HumID records the signal in your ledger, where only a normal unlock shows it.</p>
      <div class="actions">
        <button class="btn primary block" disabled={busy || (off && changedAlert)} onClick={save}>{changedAlert && <Icon name="fingerprint" />}Save</button>
        <button class="btn ghost block" data-back onClick={back}>Cancel</button>
      </div>

      {preview && (
        <Sheet onClose={() => setPreview(false)} eyebrow="Preview" title="What a forced unlock shows">
          {decoys.size === 0 ? <Empty icon="vault" title="An empty vault" text="With no decoys chosen, a forced unlock shows nothing at all, which may itself look suspicious." /> : (
            <div class="rows">{items.filter((i) => decoys.has(i.id)).map((i) => <Row key={i.id} icon="lock" chevron={false} title={i.name} />)}</div>
          )}
          <p class="fine" style={{ marginTop: 12 }}>Activity, devices and recovery look calm and ordinary in that session.</p>
          <div class="actions"><button class="btn primary mint block" onClick={() => setPreview(false)}>Got it</button></div>
        </Sheet>
      )}
    </Pushed>
  );
}

/**
 * Try the gesture here. Nothing leaves the phone; the result is a line of text. The taps and
 * the hold are recognised by the same code as the Lock screen (core/gesture.js), and the
 * line says how far apart the taps were.
 */
function Practice({ gesture }) {
  const [result, setResult] = useState(null); // { yes, text }
  const [holding, setHolding] = useState(false);
  const taps = useRef(null);
  if (!taps.current) taps.current = createTapCounter({ onDone: (r) => setResult({ yes: r.duress, text: describeTaps(r) }) });
  const press = useRef(null);
  if (!press.current) press.current = createHoldTimer();
  const timer = useRef(null);
  useEffect(() => () => { taps.current.cancel(); clearTimeout(timer.current); }, []);
  const onMark = () => taps.current.tap();
  const down = () => { press.current.down(); setHolding(true); clearTimeout(timer.current); timer.current = setTimeout(() => setHolding(false), DURESS_HOLD_MS); };
  const up = () => {
    const held = press.current.up();
    if (held == null) return;
    setHolding(false); clearTimeout(timer.current);
    setResult(isDuressHold(held)
      ? { yes: true, text: "That would have opened the decoy view." }
      : { yes: false, text: `That would have been a normal unlock: you held for ${(held / 1000).toFixed(1)} s. Hold for ${HOLD_S} seconds.` });
  };
  const hint = gesture === "taps" ? `Tap the mark three times, each within ${(TAP_WINDOW_MS / 1000).toFixed(1)} s of the last.` : `Press and hold for ${HOLD_S} seconds, then let go.`;
  return (
    <div class="card" style={{ marginTop: 12 }}>
      <h3>Practice</h3>
      <p class="small muted" style={{ marginTop: 4 }}>Try it here as many times as you like. This sends nothing to your vault and locks nothing.</p>
      <div class="hero" style={{ padding: "12px 0" }}>
        {gesture === "taps"
          ? <button class="icon-btn" style={{ width: "auto", height: "auto", borderRadius: 999 }} aria-label="The HumID mark (tap it three times)" onClick={onMark}><Mark size={120} /></button>
          : <button class="btn primary lg block" style={{ opacity: holding ? 0.8 : 1 }} onPointerDown={down} onPointerUp={up} onPointerLeave={up} onPointerCancel={up} onContextMenu={(e) => e.preventDefault()}><Icon name="fingerprint" />Unlock (practice)</button>}
        <p class="small" role="status" aria-live="polite" data-practice={result ? (result.yes ? "decoy" : "normal") : ""} style={{ minHeight: 22, color: result?.yes ? "var(--mint)" : result ? "var(--amber)" : "var(--muted)" }}>
          {result ? result.text : hint}
        </p>
      </div>
    </div>
  );
}
