// The shell around the screens: the connection strip, the restored-draft offer, and the
// simulation strip with its checks sheet (development builds only). Nothing here holds a
// key; it renders what core/ tells it to.
import { useState } from "preact/hooks";
import { Icon } from "../brand/icons.jsx";
import { Sheet, useNow } from "./kit.jsx";
import { fmtTime } from "./format.js";
import * as S from "../core/state.js";
import { retryConnection, keptDraft, takeDraft } from "../core/index.js";

/**
 * The vault can't be reached. In the flow of the page (3.0): it pushes the screen down
 * instead of covering its title. The clock runs only while the strip is up.
 */
export function ConnectionBar() {
  const l = S.link.value;
  const down = l.state === "down" && !S.offline.value && S.view.value !== "boot";
  const now = useNow(down ? 1000 : 3_600_000);
  if (!down || now - l.since < 1500) return null;
  const wait = Math.max(0, Math.ceil((l.nextAt - now) / 1000));
  const noNet = l.reason === "offline" || !S.online.value;
  return (
    <div class="linkbar" role="status" aria-live="polite">
      <span class="dot" aria-hidden="true" />
      <span class="grow">
        <strong>{noNet ? "No internet connection" : "Can't reach your vault"}</strong>
        <span>{noNet ? "HumID reconnects by itself when you're back online." : wait > 0 ? `Trying again in ${wait} s` : "Reconnecting…"}</span>
      </span>
      {!noNet && <button class="btn sm quiet" onClick={retryConnection} disabled={wait === 0}>Reconnect now</button>}
    </div>
  );
}

/**
 * After an unlock: the form the person was in the middle of when the app locked (UX-17).
 * Offered once; the draft rides inside the unlocked session and is never written to disk.
 */
export function DraftOffer() {
  const d = keptDraft.value;
  if (!d || S.view.value !== "app" || S.decoy.value) return null;
  const what = { add: "adding to your vault", witnesses: "adding witnesses", card: "a card", id: "an ID" }[d.kind] || "what you were doing";
  const resume = () => {
    const draft = takeDraft();
    if (!draft) return;
    if (draft.kind === "add") S.push.value = { type: "add", draft };
    else if (draft.kind === "witnesses") { S.tab.value = "you"; S.push.value = { type: "recovery", draft }; }
  };
  return (
    <Sheet onClose={() => takeDraft()} eyebrow="Welcome back" title="Pick up where you left off?">
      <p class="t2">HumID locked while you were {what}. What you'd typed is still here, on this phone only.</p>
      <div class="actions">
        <button class="btn primary block" onClick={resume}>Continue</button>
        <button class="btn ghost block" onClick={() => takeDraft()}>Start fresh</button>
      </div>
    </Sheet>
  );
}

/* ---------------- simulation (development builds only) ---------------- */

export function SimStrip() {
  const last = S.simLog.value[0];
  return (
    <button class="sim-strip" onClick={() => (S.simShow.value = last || { title: "Simulation", checks: [], empty: true })}>
      <span class="dot" aria-hidden="true" />
      <span><b>Simulation</b> · vault server runs on this phone</span>
      {last && <span class="sim-last">{last.checks.filter((c) => c.ok).length} verifications ✓</span>}
    </button>
  );
}

const MARK = { true: "check", false: "x", null: "info" };

/** What the simulated server verified for one action, one line each. */
export function ChecksSheet() {
  const r = S.simShow.value;
  const [, force] = useState(0);
  if (!r) return null;
  const close = () => (S.simShow.value = null);
  const okCount = r.checks.filter((c) => c.ok === true).length;
  return (
    <Sheet onClose={close} eyebrow={`Simulated vault server · ${fmtTime(r.at || Date.now())}`} title={r.title}>
      {r.empty ? (
        <p class="lede">This build runs HumID's vault server inside the app. Your phone connects to it the real, post-quantum way, and it verifies every sign-in and sensitive action the way a real server does. Create your HumID or unlock to see the verifications.</p>
      ) : (
        <>
          <p class="small muted">{okCount} of {r.checks.length} verifications passed{r.checks.some((c) => c.ok === null) ? " · notes marked ⓘ" : ""}</p>
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
              <button class="row no-lead" onClick={() => { S.simShow.value = x; force((n) => n + 1); }}>
                <span class="body"><span class="title">{x.title}</span><span class="sub">{x.checks.filter((c) => c.ok).length} ✓ · {fmtTime(x.at)}</span></span>
                <span class="trail"><Icon name="chevron" /></span>
              </button>
            ))}
          </div>
        </>
      )}
      <div class="actions"><button class="btn primary mint block" onClick={close}>Done</button></div>
    </Sheet>
  );
}
