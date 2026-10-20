// What the camera tells the person while it scans: the step it is on, in plain words
// (core/scanflow.js has the machine; this only draws it). One card above the shutter:
// the steps (Find · Steady · Read · Verify · Done), the current state's title and a
// short line on what to do, a progress bar, and, when it can't go on by itself, the
// one-tap ways forward (Try again, Take photo, Light on). The
// card is itself the live region: each change is read out once (the step is held for a
// moment before it changes, so a flickering look isn't chatter).
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { calmer } from "../core/scanflow.js";

const ICON = { starting: "scan", looking: "scan", steady: "scan", reading: "scan", verifying: "shield", done: "check", problem: "alert", unreadable: "alert", timeout: "clock" };

/** The view to show: ordinary steps held for a moment, so the card (the one live region) is calm. */
export function useCalm(view) {
  const c = useRef(null);
  c.current ||= calmer();
  const [, tick] = useState(0);
  const shown = c.current.show(view, Date.now());
  // a held-back step is shown when its moment has passed
  useEffect(() => {
    if (shown.id === view.id) return;
    const t = setTimeout(() => tick((n) => n + 1), 400);
    return () => clearTimeout(t);
  });
  return shown;
}

/**
 * The scan card.
 *   view      core/scanflow.js describe()
 *   notice    a one-off message (a photo that wasn't kept, a read that failed: noticeTitle says which), shown as a problem for a few seconds
 *   onRetry   Try again          onShoot   Take the photo myself      onTorch   Light on (when the camera has one)
 */
export function ScanState({ view: latest, notice, noticeTitle, error, onRetry, onShoot, onTorch, torch }) {
  const view = useCalm(latest);
  const tone = error || notice ? "warn" : view.tone;
  const title = error ? "Camera problem" : notice ? noticeTitle || "Couldn't keep that photo" : view.title;
  const detail = error || notice || view.detail;
  const icon = error ? "alert" : notice ? "alert" : ICON[view.id] || "scan";
  const pct = Math.round(Math.max(0, Math.min(1, view.progress || 0)) * 100);
  // the step row: where we are, in order; a failure stays on the step it stopped at
  const steps = view.steps;
  return (
    <div class="dc-status dc-state" data-tone={tone} data-state={error ? "error" : notice ? "notice" : view.id} data-fail={view.fail || undefined}>
      {!error && (
        <ol class="dc-steps" aria-hidden="true">
          {steps.map((s, i) => <li data-on={i === view.step ? "1" : undefined} data-past={view.step > i || view.id === "done" ? "1" : undefined}><i />{s.label}</li>)}
        </ol>
      )}
      <div class="dc-msg">
        <span class="dc-ico" data-spin={view.busy && !notice && !error ? "1" : undefined}><Icon name={icon} /></span>
        <div class="dc-words" role="status" aria-atomic="true" aria-live={error || notice || view.assertive ? "assertive" : "polite"}><strong>{title}</strong><span>{detail}</span></div>
      </div>
      {!error && !notice && (view.id === "steady" || view.busy) && view.id !== "done" && (
        <div class="dc-bar-track" role="progressbar" aria-label={view.title} aria-valuemin={0} aria-valuemax={100} aria-valuenow={view.busy && view.id !== "steady" ? undefined : pct} data-indeterminate={view.busy && view.id !== "steady" ? "1" : undefined}>
          <i style={view.id === "steady" ? { transform: `scaleX(${pct / 100})` } : undefined} />
        </div>
      )}
      {!error && (view.action || view.manual) && (
        <div class="dc-actions">
          {view.action === "light" && onTorch && <button type="button" class="dc-act" onClick={onTorch} aria-pressed={!!torch}><Icon name="torch" />{torch ? "Light off" : "Light on"}</button>}
          {view.action === "retry" && <button type="button" class="dc-act primary" onClick={onRetry}><Icon name="rotate" />Try again</button>}
          {(view.action === "retry" || view.manual) && <button type="button" class="dc-act" onClick={onShoot}><Icon name="camera" />Take photo</button>}
        </div>
      )}
    </div>
  );
}
