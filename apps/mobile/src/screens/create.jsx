// Create my HumID: (connect, when the build doesn't pin a server) · (access pass, when
// the server needs one) · how you get back in (the recovery mode) · lock it to you ·
// your recovery card, or for holder-only your second device · you're in.
import { useState } from "preact/hooks";
import { Mark, Wordmark } from "../brand/mark.jsx";
import { Icon } from "../brand/icons.jsx";
import { Stepper, Banner, AssurancePill, Row } from "../ui/kit.jsx";
import { CardBox, CardConfirm, PrintableCard, CAN_PRINT } from "../ui/codes.jsx";
import { CARD_IS_ONE, RECOVERY_RULE } from "../ui/labels.js";
import * as S from "../core/state.js";
import { enroll, finishEnroll, connectServer, saveCard, redeemAccessCode, resumePass, demoAccessCode, serverPinned, toast, HOLDER_ONLY, HARDENED } from "../core/index.js";
import { parseAccessCode } from "@humid/pass";
import { serverHost, SERVER_URL } from "../core/config.js";
import { openExternal } from "../core/external.js";

export function TopBar({ step, steps, onBack }) {
  return (
    <>
      <header class="top">
        {onBack ? <button class="icon-btn" aria-label="Back" data-back onClick={onBack}><Icon name="back" /></button> : <span class="spacer" />}
        <span class="grow" />
        <Wordmark height={22} />
      </header>
      <Stepper step={step} steps={steps} label="Setup progress" />
    </>
  );
}

/** Which vault server, and its pinned post-quantum key. Only when the build doesn't pin one. */
export function ConnectStep({ eyebrow, onNext }) {
  const srv = S.server.value;
  const [showKey, setShowKey] = useState(false);
  return (
    <>
      <div class="eyebrow">{eyebrow}</div>
      <h1 style={{ marginTop: 8 }}>Your vault server</h1>
      <p class="lede" style={{ marginTop: 10 }}>HumID stores sealed copies at <b>{serverHost(SERVER_URL)}</b> and remembers its post-quantum key. If that key ever changes, HumID refuses to connect.</p>
      <div class="card" style={{ marginTop: 22 }}>
        {srv ? (
          <>
            <Row icon="server" tone="mint" chevron={false} title={serverHost(SERVER_URL)} sub="Answering, with a post-quantum key" />
            <button class="link" type="button" aria-expanded={showKey} onClick={() => setShowKey(!showKey)}>{showKey ? "Hide its key" : "Show its key"}</button>
            {showKey && <p class="mono small t2 selectable" style={{ wordBreak: "break-all" }}>{srv.fingerprint}<br /><span class="muted">Compare it with the key on your server's setup page.</span></p>}
          </>
        ) : S.serverError.value ? <Banner tone="danger" icon="wifi_off" title="Can't reach your vault server" text={S.serverError.value} />
          : <span class="muted small">Contacting your vault server…</span>}
      </div>
      <div class="foot">
        {srv ? <button class="btn primary block" onClick={onNext}>Trust this server</button>
          : <button class="btn quiet block" onClick={connectServer}>Try again</button>}
      </div>
    </>
  );
}

/**
 * HumID can't see whose faces or fingers the phone has enrolled, only that a live match
 * happened. So it asks, once, and records the answer with this device in your ledger.
 */
export function SoleBiometric({ checked, onChange, id = "sole" }) {
  const hw = S.hwGate.value;
  const what = hw?.probe.label && !/demo/i.test(hw.probe.label) ? hw.probe.label : "Face ID / fingerprint";
  const [why, setWhy] = useState(false);
  return (
    <div class="card" id={id} style={{ marginBottom: 12 }}>
      <button class="toggle" role="checkbox" aria-checked={!!checked} onClick={() => onChange(!checked)}>
        <span><span class="title">Only I use {what} on this phone</span></span>
        <span class="lead" style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: checked ? "var(--mint)" : "var(--surface-3)", color: "var(--mint-ink)" }}>{checked && <Icon name="check" />}</span>
      </button>
      <button class="link muted" type="button" aria-expanded={why} onClick={() => setWhy(!why)}>What does this mean?</button>
      {why && <p class="small muted" style={{ marginTop: 6 }}>HumID can't see whose faces or fingers this phone knows, only that a live match happened. If anyone else's is enrolled, they could open your vault, so HumID asks once and records your answer in your activity. If another one is added later, this phone has to be added to your HumID again; your vault is safe.</p>}
    </div>
  );
}

/**
 * The first check. Never a dead grey button: without the confirmation above, a tap
 * points at it instead of doing nothing.
 */
export function BindButtons({ onBind, label, sole, soleId = "sole" }) {
  const hw = S.hwGate.value;
  const demo = S.demoAllowed.value;
  const policy = S.server.value?.policy?.devicePolicy || "attested";
  const guard = (fn) => () => {
    if (sole) return fn();
    const el = document.getElementById(soleId);
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
    el?.querySelector("button")?.focus({ preventScroll: true });
    toast("First confirm nobody else's face or fingerprint is enrolled on this phone.", "warn");
  };
  return (
    <>
      {!hw?.probe.available && hw?.probe.reason && <Banner tone="amber" title="Open HumID in the app" text={`${hw.probe.reason} ${demo ? "This development server also allows demo mode." : "PINs and passwords are never accepted."}`} />}
      {hw?.probe.available && !hw.probe.proof && policy === "attested" && <Banner tone="amber" title="Use your phone" text="This vault accepts only phones whose secure chip can prove each live check. Set up HumID on your iPhone or Android phone first." />}
      {hw?.probe.available && (hw.probe.proof || policy !== "attested") && <button class="btn primary lg block" onClick={guard(() => onBind(false))}><Icon name="fingerprint" />{label} with {hw.probe.label}</button>}
      {demo && <button class={`btn ${hw?.probe.available ? "ghost" : "primary"} block`} onClick={guard(() => onBind(true))}>Use demo mode (no sensor)</button>}
    </>
  );
}

export function Create() {
  const step = S.enrollStep.value;
  const hw = S.hwGate.value;
  const [sole, setSole] = useState(false);
  const steps = [...(serverPinned() ? [] : ["connect"]), ...(S.passNeeded.value ? ["access"] : []), "mode", "bind", "done", "in"];
  const idx = steps.indexOf(step);
  const at = Math.max(0, idx);
  const go = (i) => (S.enrollStep.value = steps[i]);
  const next = () => go(Math.min(idx + 1, steps.length - 1));
  const back = step !== "done" && step !== "in" ? () => (idx <= 0 ? (S.view.value = "welcome") : go(idx - 1)) : null;
  const n = (s) => `Step ${steps.indexOf(s) + 1} of ${steps.length}`;
  return (
    <main class="screen">
      <TopBar step={at} steps={steps.length} onBack={back} />
      {step === "connect" && <ConnectStep eyebrow={n("connect")} onNext={next} />}
      {step === "access" && <AccessStep eyebrow={n("access")} onNext={next} />}
      {step === "mode" && <ModeStep eyebrow={n("mode")} onNext={next} />}
      {step === "bind" && (
        <>
          <div class="eyebrow">{n("bind")} · Lock it to you</div>
          <h1 style={{ marginTop: 8 }}>Your body becomes the key</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your keys are made on this phone and locked behind {hw?.probe.available ? hw.probe.label : "your face or fingerprint"}. They never leave it, and HumID never sees your face or fingerprint.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0 6px" }}><Mark size={150} /></div>
          <div class="foot">
            <SoleBiometric checked={sole} onChange={setSole} />
            <BindButtons onBind={(demo) => enroll(demo, { soleBiometric: sole, recoveryMode: S.setupMode.value })} label="Create" sole={sole} />
          </div>
        </>
      )}
      {step === "done" && (S.recoveryMode.value?.mode === HOLDER_ONLY ? <SecondDeviceStep onNext={() => go(steps.indexOf("in"))} /> : <RecoveryCardStep onNext={() => go(steps.indexOf("in"))} />)}
      {step === "in" && <YoureIn />}
    </main>
  );
}

/** Pay without being identified: an access code becomes a pass the vault signs blind. */
function AccessStep({ eyebrow, onNext }) {
  const [text, setText] = useState("");
  const rec = S.pass.value;
  const busy = S.passBusy.value;
  const buyUrl = S.server.value?.policy?.passBuyUrl;
  const demo = S.demoAllowed.value || S.server.value?.simulated;
  const valid = !!parseAccessCode(text);
  const typed = text.replace(/[^0-9a-z]/gi, "").length;
  return (
    <>
      <div class="eyebrow">{eyebrow} · Your access pass</div>
      <h1 style={{ marginTop: 8 }}>Pay without being known</h1>
      <p class="lede" style={{ marginTop: 10 }}>An access code becomes a pass the vault signs without seeing it. When you create your HumID, the vault can check the pass is real, but it can't tell which code, purchase or person it came from.</p>
      <div class="card" style={{ marginTop: 18 }}>
        <Row icon="key" tone="mint" chevron={false} title="Where to get one" sub={buyUrl ? "Buy an access code online, or with cash at a counter: cash leaves no trace at all." : "Ask whoever runs your vault server for an access code, or buy one with cash at a counter."} />
        {buyUrl && <button class="btn quiet sm" style={{ marginTop: 8 }} type="button" onClick={() => openExternal(buyUrl)}><Icon name="out" />Buy an access code</button>}
      </div>
      {rec?.state === "ready" ? <div style={{ marginTop: 16 }}><Banner tone="mint" icon="check" title="Access pass ready" text="Kept sealed on this phone until you create your HumID. Your access code is no longer stored." /></div>
        : rec?.state === "draft" ? <div style={{ marginTop: 16 }}><Banner tone="amber" icon="clock" title="Finishing your pass" text="Your code was sent but the answer didn't arrive. It's saved sealed here, so nothing is lost." /></div>
        : (
          <div class="field" style={{ marginTop: 16 }}>
            <label for="access">Access code</label>
            <input autocorrect="off" id="access" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              value={text} onInput={(e) => setText(e.currentTarget.value)} disabled={busy} />
            {valid && <span class="hint mint">Code looks right</span>}
            {!valid && typed >= 24 && <span class="hint amber">That code has a typo. Check each character.</span>}
          </div>
        )}
      <div class="foot">
        {rec?.state === "ready" ? <button class="btn primary block" onClick={onNext}>Continue</button>
          : rec?.state === "draft" ? <button class="btn primary block" disabled={busy} onClick={resumePass}>{busy ? "Finishing…" : "Try again"}</button>
          : <>
              <button class="btn primary block" disabled={!valid || busy} onClick={async () => { if (await redeemAccessCode(text)) setText(""); }}><Icon name="key" />{busy ? "Getting your pass…" : "Get my access pass"}</button>
              {demo && <button class="btn ghost block" disabled={busy} onClick={demoAccessCode}>Use a demo access code</button>}
            </>}
      </div>
    </>
  );
}

/**
 * How you get back in if you lose every device: the recovery mode. Hardened is selected and
 * labelled recommended; holder-only is a real choice with its consequence said plainly.
 * The choice is signed by the account key during the next step's check.
 */
export const MODE_CHOICES = [
  {
    id: HARDENED, icon: "shield", title: "A safe way back in", tag: "Recommended",
    text: "Set up two ways to prove it's you later: people you trust, your passport or ID card, a recovery card, a security key. To get back in you use any two of them, then there's a wait during which any device you still have can cancel it.",
    cost: "More ways back in, but some of that proof is kept on HumID's servers, locked so they can't open it on their own.",
  },
  {
    id: HOLDER_ONLY, icon: "key", title: "Only my own devices", tag: "Most private",
    text: "Your documents open only on a phone or computer you've already set up. If you lose every one of them, no one can get your documents back: not your friends, not your ID, not HumID.",
    cost: "There's nothing anyone could be forced or tricked into handing over. You'll need a second device, set up now, so one lost phone is never the end.",
  },
];

function ModeStep({ eyebrow, onNext }) {
  const pick = S.setupMode.value;
  const [sure, setSure] = useState(false);
  const holderOnly = pick === HOLDER_ONLY;
  return (
    <>
      <div class="eyebrow">{eyebrow} · Getting back in</div>
      <h1 style={{ marginTop: 8 }}>If you lose every device</h1>
      <p class="lede" style={{ marginTop: 10 }}>How do you want to be able to get back in? You can change this later under You → Recovery.</p>
      <div class="options" style={{ marginTop: 18 }} role="radiogroup" aria-label="How you get back in">
        {MODE_CHOICES.map((c) => (
          <button class="option" role="radio" aria-checked={pick === c.id} data-mode={c.id} onClick={() => { S.setupMode.value = c.id; setSure(false); }}>
            <span class="lead"><Icon name={c.icon} /></span>
            <span>
              <span class="title">{c.title} <span class={`pill ${c.id === HARDENED ? "mint" : ""}`} style={{ marginLeft: 6 }}>{c.tag}</span></span>
              <span class="sub" style={{ display: "block" }}>{c.text}</span>
              <span class="sub muted" style={{ display: "block", marginTop: 4 }}>{c.cost}</span>
            </span>
            {pick === c.id ? <Icon name="check" /> : <span />}
          </button>
        ))}
      </div>
      {holderOnly && (
        <div class="card" style={{ marginTop: 14 }} id="mode-sure">
          <Banner tone="danger" icon="alert" title="Lose every device, lose your vault" text="HumID will keep no way to bring it back. Not even we can help, by design." />
          <button class="toggle" role="checkbox" aria-checked={sure} onClick={() => setSure(!sure)} style={{ marginTop: 8 }}>
            <span><span class="title">I understand. I'll set up a second device</span></span>
            <span class="lead" style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: sure ? "var(--mint)" : "var(--surface-3)", color: "var(--mint-ink)" }}>{sure && <Icon name="check" />}</span>
          </button>
        </div>
      )}
      <div class="foot">
        <button class="btn primary block" onClick={() => {
          if (holderOnly && !sure) {
            const el = document.getElementById("mode-sure");
            el?.scrollIntoView({ block: "center", behavior: "smooth" });
            el?.querySelector("[role=checkbox]")?.focus({ preventScroll: true });
            return toast("First confirm you understand: only your own devices can bring your vault back.", "warn");
          }
          onNext();
        }}>Next: lock it to you</button>
        <p class="fine center">{holderOnly ? "Only your own devices · no recovery kept anywhere" : "Two proofs, a wait, and a veto from your devices"}</p>
      </div>
    </>
  );
}

/** Holder-only: the second device is the only safety net, so setup asks for it now, loudly. */
function SecondDeviceStep({ onNext }) {
  const [later, setLater] = useState(false);
  return (
    <>
      <div class="eyebrow">Only your own devices · do this now</div>
      <h1 style={{ marginTop: 8 }}>Add a second device</h1>
      <p class="lede" style={{ marginTop: 10 }}>Right now this phone is the only way into your vault. If it's lost, broken or stolen, your documents are gone for good. A second phone, tablet or computer you keep somewhere else fixes that.</p>
      <div class="rows" style={{ marginTop: 16 }}>
        <Row icon="key" tone="mint" chevron={false} title="On the other device" sub="Install HumID, then choose I already have HumID → From another device. It shows a code." />
        <Row icon="fingerprint" tone="mint" chevron={false} title="On this phone" sub="Open your vault, then You → Devices → Add a device, and type or scan that code." />
      </div>
      <div style={{ marginTop: 14 }}><Banner tone="danger" icon="alert" title="Until then, one lost phone is the end" text="HumID keeps no recovery for you: no card, no witnesses, nothing on our servers. That's what makes it private." /></div>
      <div class="foot">
        <button class="btn primary block" onClick={() => { finishEnroll(); S.push.value = { type: "devices", open: "add" }; S.tab.value = "you"; }}><Icon name="plus" />Add my second device now</button>
        {!later
          ? <button class="link muted" onClick={() => setLater(true)}>Not now</button>
          : <button class="btn ghost block" onClick={onNext}>I'll add it soon. I know a lost phone means a lost vault</button>}
      </div>
    </>
  );
}

/** The recovery card: shown once. Write it down, type one group back, then on. */
function RecoveryCardStep({ onNext }) {
  const code = S.cardCode.value;
  const [saved, setSaved] = useState(false);
  return (
    <>
      <div class="eyebrow">{code ? "Shown once · write it down now" : "Your recovery card"}</div>
      <h1 style={{ marginTop: 8 }}>{code ? "Your recovery card" : "No recovery set up yet"}</h1>
      {code ? (
        <>
          <p class="lede" style={{ marginTop: 10 }}>{CARD_IS_ONE}</p>
          <div class="card" style={{ marginTop: 16 }}>
            <CardBox code={code} />
            <CardConfirm code={code} onChange={setSaved} />
            <div class="row-x" style={{ marginTop: 12 }}>
              {CAN_PRINT && <button class="btn quiet sm" onClick={() => window.print()}><Icon name="file" />Print</button>}
              <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save as a file</button>
            </div>
            <p class="fine" style={{ marginTop: 8 }}>A saved file can sync to a cloud you don't control. Paper, kept away from your ID, is the safer copy.</p>
            <PrintableCard code={code} />
          </div>
        </>
      ) : <div style={{ marginTop: 18 }}><Banner tone="amber" title="Set it up under You" text={`${RECOVERY_RULE} Set up two, or a second device, so losing this phone doesn't lose your vault.`} /></div>}
      <div class="foot">
        <button class="btn primary block" onClick={() => {
          if (!(code && !saved)) return onNext();
          const f = document.getElementById("card-check");
          f?.scrollIntoView({ block: "center", behavior: "smooth" });
          f?.focus({ preventScroll: true });
        }}>
          <Icon name={code ? "check" : "chevron"} />{code && !saved ? "Check your copy to continue" : code ? "I've written it down" : "Continue"}
        </button>
      </div>
    </>
  );
}

function YoureIn() {
  const holderOnly = S.recoveryMode.value?.mode === HOLDER_ONLY;
  return (
    <>
      <div class="hero" style={{ flex: "0 0 auto", marginTop: 4 }}><Mark state="verified" size={150} /></div>
      <h1 class="center" style={{ marginTop: 10 }}>You're in</h1>
      <p class="lede center" style={{ margin: "8px auto 0" }}>Your HumID is live and locked to this phone.</p>
      <p class="center" style={{ marginTop: 10 }}><AssurancePill assurance={S.identity.value?.assurance} /></p>
      <div class="foot">
        <button class="btn primary mint lg block" onClick={finishEnroll}><Icon name="vault" />Open my vault</button>
        <p class="fine center">{holderOnly
          ? "Next, under You → Devices: a second device. It's the only way back in if you lose this phone."
          : "Next, under You: a second proof and a second device, so a lost phone is never an emergency."}</p>
      </div>
    </>
  );
}
