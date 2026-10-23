// The shell around the screens: the connection strip, the restored-draft offer, and the
// simulation strip with its checks sheet (development builds only). Nothing here holds a
// key; it renders what core/ tells it to.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../brand/icons.jsx";
import { Sheet, Banner, useNow } from "./kit.jsx";
import { fmtTime } from "./format.js";
import * as S from "../core/state.js";
import { retryConnection, keptDraft, takeDraft, resumeNewCard, CARD_DRAFT, answerReaders } from "../core/index.js";

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
  const here = !!d && S.view.value === "app" && !S.decoy.value;
  // A new recovery card isn't offered: it comes straight back, since it's the only copy.
  useEffect(() => { if (here && d.kind === CARD_DRAFT) resumeNewCard(takeDraft()); }, [here, d]);
  if (!here || d.kind === CARD_DRAFT) return null;
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

/**
 * Another app can read the screen (APP-09): before a document, a card or messages are shown,
 * which apps, by name, and what they could do. The holder decides; nothing is shown until then.
 */
export function ReaderWarning() {
  const w = S.readerWarning.value;
  if (!w) return null;
  const names = w.services.map((s) => s.label);
  const list = names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  const acts = w.services.some((s) => s.canAct);
  return (
    <Sheet onClose={() => answerReaders(false)} eyebrow="Before you see it" title="Another app can read your screen">
      <Banner tone="amber" icon="alert" role="alert" title={`${list} ${names.length === 1 ? "is turned on as an accessibility service" : "are turned on as accessibility services"}`}
        text={`${names.length === 1 ? "It" : "They"} can read everything HumID shows, including ${w.what}${acts ? ", and tap buttons for you" : ""}. HumID can't block this.`} />
      <p class="t2 small mt-3">If you didn't turn {names.length === 1 ? "it" : "them"} on yourself, or don't know what {names.length === 1 ? "it is" : "they are"}, don't go on: turn {names.length === 1 ? "it" : "them"} off in Settings › Accessibility first.</p>
      <div class="actions">
        <button class="btn quiet block" onClick={() => answerReaders(false)}>Not now</button>
        <button class="btn primary block" onClick={() => answerReaders(true)}>Show {w.what}</button>
      </div>
    </Sheet>
  );
}
