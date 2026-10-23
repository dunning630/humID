// The Lock screen: the mark, Unlock, and the plain truth (no password exists).
// Both duress gestures are always listened for — tapping the mark three times, or
// holding Unlock for three seconds — because which one (if any) is the duress gesture
// is sealed and only known after the check. Nothing on screen changes either way.
// 3.0: a tap on the mark responds at once; a plain click (screen readers, switch control)
// unlocks. The taps are recognised by core/gesture.js, the same code Duress Practice uses,
// and the unlock waits for its window. For people who can't make the gestures, the duress
// unlock is a control too: named for what it does, drawn when focused, and behind "More ways
// to unlock", so the straight Tab path never reaches it (APP-06).
import { useEffect, useRef, useState } from "preact/hooks";
import { Mark, Wordmark } from "../brand/mark.jsx";
import { Icon } from "../brand/icons.jsx";
import { Banner } from "../ui/kit.jsx";
import * as S from "../core/state.js";
import { unlock, resetLocal, createTapCounter, createHoldTimer, isDuressHold } from "../core/index.js";
import { serverHost } from "../core/config.js";

const ISSUES = {
  server_identity_changed: (host) => ({
    title: "Your vault server's identity changed",
    text: `The server at ${host} presented a different post-quantum key than the one this phone trusts, so HumID refused to connect. This happens if the server was rebuilt, or if someone is impersonating it.`,
    warn: true,
  }),
  unknown_identity: (host) => ({ title: "Your vault doesn't know this HumID", text: `The server at ${host} has no record of this identity. It may have been reset or replaced, or this HumID came from an earlier test version.` }),
  device_not_proven: () => ({ title: "Your vault needs a chip-proven check", text: "This vault server now accepts only devices whose secure chip proves every live check. Open HumID on your phone, or add this device again once it qualifies." }),
  key_invalidated: () => ({
    title: "This phone's HumID key is gone",
    text: "Android and iOS delete HumID's key when the phone's fingerprints or face change, or when HumID is reinstalled, and nothing can bring it back. Your vault and documents are safe. Set HumID up again on this phone, then use I already have HumID to get back in with another device or your recovery proofs.",
  }),
  device_removed: () => ({ title: "This device was removed from your HumID", text: "Someone removed it from another of your devices. It can no longer open your vault. If that was you, set this device up again with I already have HumID." }),
};
/** Issues nothing on this phone can fix: the only way on is to set HumID up again. */
const TERMINAL = new Set(["key_invalidated", "device_removed"]);

function useUnlockGestures() {
  const [pressed, setPressed] = useState(false);
  // One recognizer with Duress Practice (core/gesture.js). The unlock starts only once the
  // tap window has closed, so the check overlay never opens over a second or third tap.
  const taps = useRef(null);
  if (!taps.current) taps.current = createTapCounter({ onDone: ({ duress }) => { setPressed(false); unlock(duress ? "taps" : false); } });
  useEffect(() => () => taps.current.cancel(), []);
  const hold = useRef(null);
  if (!hold.current) hold.current = createHoldTimer();
  const fired = useRef(false);
  const onMark = () => { setPressed(true); taps.current.tap(); };
  const button = {
    onPointerDown: () => { hold.current.down(); fired.current = false; },
    onPointerUp: () => { const held = hold.current.up(); if (held == null) return; fired.current = true; unlock(isDuressHold(held) ? "hold" : false); },
    onPointerLeave: () => { hold.current.cancel(); fired.current = false; },
    // a synthesised click (screen reader, switch control, keyboard) with no pointer sequence
    onClick: () => { if (fired.current) { fired.current = false; return; } unlock(false); },
    onContextMenu: (e) => e.preventDefault(),
  };
  return { onMark, button, pressed };
}

/** The duress unlock for screen readers, switch control and keyboards. Not drawn until focused. */
function MoreWays() {
  const [open, setOpen] = useState(false);
  // Focus stays on the disclosure: Enter twice must not be a duress unlock.
  return (
    <>
      <button class="sr" aria-expanded={open} aria-controls="lock-more" onClick={() => setOpen(!open)}>More ways to unlock</button>
      <div id="lock-more" hidden={!open}>
        <button class="sr" onClick={() => unlock(true)}>Unlock with your duress gesture (shows only decoys, locks your vault)</button>
      </div>
    </>
  );
}

export function Lock() {
  const id = S.identity.value;
  const [confirm, setConfirm] = useState(false);
  const [checked, setChecked] = useState(false);
  const issue = S.lockIssue.value;
  const g = useUnlockGestures();
  const down = S.link.value.state === "down" || !S.online.value || !!S.serverError.value;
  if (issue) {
    const x = (ISSUES[issue] || ISSUES.unknown_identity)(serverHost(id?.server?.url));
    const terminal = TERMINAL.has(issue);
    const impersonation = issue === "server_identity_changed";
    return (
      <main class="screen">
        <div class="hero" style={{ flex: "0 0 auto", marginTop: "8vh" }}><Mark state="failed" size={140} /></div>
        <h1 class="center" style={{ marginTop: 18 }}>{x.title}</h1>
        <p class="lede center" style={{ margin: "10px auto 0" }}>{x.text}</p>
        {x.warn && <div style={{ marginTop: 18 }}><Banner tone="amber" icon="alert" title="Don't continue unless you expected this" text="Check with whoever runs your vault server before setting up again." /></div>}
        <div class="foot">
          {impersonation && !checked && <button class="btn quiet block" onClick={() => setChecked(true)}>I checked with my server operator</button>}
          {(!impersonation || checked) && !confirm && <button class={`btn ${terminal ? "primary" : "quiet"} block`} onClick={() => setConfirm(true)}>Set up HumID again</button>}
          {confirm && <button class="btn danger solid block" onClick={resetLocal}>Remove this identity from this phone</button>}
          {confirm && <p class="fine">Your documents stay in your vault. Get back in with another device, your recovery card or your witnesses.</p>}
          {confirm && terminal && <button class="btn ghost block" data-back onClick={() => setConfirm(false)}>Not now</button>}
          {!terminal && <button class="btn primary block" data-back onClick={() => { S.lockIssue.value = null; setConfirm(false); setChecked(false); }}>Back</button>}
        </div>
      </main>
    );
  }
  return (
    <main class="screen">
      <div class="hero" style={{ flex: "1 0 auto", justifyContent: "center" }}>
        <button class="icon-btn" style={{ width: "auto", height: "auto", borderRadius: 999, transform: g.pressed ? "scale(0.97)" : undefined, transition: "transform var(--d-fast)" }} aria-label="Unlock HumID" onClick={g.onMark}><Mark size={220} /></button>
        <Wordmark height={30} />
        <p class="lede">Safe. Secure. Simple.</p>
      </div>
      <div class="foot stack">
        <button class="btn primary lg block" {...g.button}><Icon name="fingerprint" />Unlock</button>
        {/* For screen readers, switch control and keyboards, which can't make the gestures:
            the same choice, spoken, drawn only when focused, never on the straight Tab path. */}
        <MoreWays />
        {down && S.offlineReady.value && <p class="fine center" role="status">No connection. You can still unlock to see your vault, read only.</p>}
        <p class="fine center">No password exists. It opens only after a live face or fingerprint check.{id?.mode === "demo" ? " (Demo identity · no hardware sensor.)" : ""}{id?.server ? ` · ${serverHost(id.server.url)}` : ""}</p>
      </div>
    </main>
  );
}
