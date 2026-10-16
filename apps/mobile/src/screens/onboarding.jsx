// Welcome → Enrol (connect · access pass, when the server needs one · bind · done + recovery card) → Lock.
// Welcome → Join (connect · choose · details · wait) for a new device of an existing HumID.
import { Mark, Wordmark, Stars } from "../brand.jsx";
import { Icon } from "../icons.jsx";
import { AssurancePill, CodeBox, CardBox, CardConfirm, PrintableCard, CAN_PRINT, useNow, fmtLeft, QrCode, ProofMeter, tierText, ChipAccess } from "../ui.jsx";
import * as S from "../core/state.js";
import {
  startEnroll, enroll, finishEnroll, unlock, connectServer, resetLocal, saveCard, copyCard,
  redeemAccessCode, resumePass, demoAccessCode, serverPinned,
  startJoin, beginJoin, pollJoin, cancelJoin, addCardToJoin, addChipToJoin, demoChipSource, nfcChipSource, DURESS_HOLD_MS,
} from "../core/controller.js";
import { useRef, useState } from "preact/hooks";
import { parseCard } from "@humid/recovery";
import { parseAccessCode } from "@humid/pass";
import { serverHost, SERVER_URL, DEMO_BUILD } from "../core/config.js";

export function Welcome() {
  return (
    <main class="screen">
      <Stars />
      <div class="hero" style={{ paddingTop: "4vh" }}>
        <Mark />
        <Wordmark />
        <div class="tagline">Safe.&nbsp; Secure.&nbsp; Simple.</div>
      </div>
      <div class="points">
        <div class="point"><span class="p-ico"><Icon name="fingerprint" /></span><div><strong>Opens only for you, live</strong><span>Every open, save or delete needs your face or fingerprint, right then.</span></div></div>
        <div class="point"><span class="p-ico"><Icon name="lock" /></span><div><strong>Sealed on your phone</strong><span>Documents are encrypted before they leave. The server can't read them, or even their names.</span></div></div>
        <div class="point"><span class="p-ico"><Icon name="chain" /></span><div><strong>Every access on the record</strong><span>A tamper-evident log your phone verifies for itself.</span></div></div>
        <div class="point"><span class="p-ico"><Icon name="user" /></span><div><strong>No name, no email, no number</strong><span>Your HumID is a set of keys. Even paying for it doesn't tell us who you are.</span></div></div>
      </div>
      <div class="foot">
        <button class="btn primary block" onClick={startEnroll}><Icon name="sparkle" />Create my HumID</button>
        <button class="btn ghost block" onClick={startJoin}><Icon name="key" />I already have HumID</button>
        <p class="fine">Post-quantum protection: ML-KEM-1024 + X25519 · ML-DSA-87</p>
      </div>
    </main>
  );
}

function TopBar({ step, steps, onBack }) {
  return (
    <>
      <div class="topbar">
        {onBack && <button class="icon-btn" aria-label="Back" onClick={onBack}><Icon name="back" /></button>}
        <div class="grow" />
        <Wordmark small />
      </div>
      <div class="stepper" role="progressbar" aria-label="Setup progress" aria-valuemin={1} aria-valuemax={steps} aria-valuenow={step + 1} aria-valuetext={`Step ${step + 1} of ${steps}`}>{Array.from({ length: steps }, (_, i) => <i class={i <= step ? "on" : ""} />)}</div>
    </>
  );
}

/** Step: which vault server, and its pinned post-quantum key. */
function ConnectStep({ eyebrow, onNext }) {
  const srv = S.server.value;
  return (
    <>
      <div class="eyebrow">{eyebrow}</div>
      <h1 style={{ marginTop: 8 }}>Connect to the vault you'll trust</h1>
      <p class="lede" style={{ marginTop: 10 }}>HumID remembers this server's post-quantum key. If it ever changes, the app refuses to connect.</p>
      <div class="card" style={{ marginTop: 22 }}>
        <div class="row"><span class="k">Server</span><span class="v">{serverHost(SERVER_URL)}</span></div>
        <div class="row"><span class="k">Channel</span><span class="v">HTP/1 · ML-KEM-1024 + X25519</span></div>
        <div class="row" style={{ display: "block" }}>
          <div class="k" style={{ marginBottom: 10 }}>Server key fingerprint</div>
          {srv ? <div class="kid">{srv.fingerprint.split("-").map((g) => <span>{g}</span>)}</div>
            : S.serverError.value ? <div class="banner bad"><span class="b-ico"><Icon name="wifi_off" /></span><div><strong>Server unreachable</strong><span>{S.serverError.value}</span></div></div>
            : <span class="muted small">Contacting server…</span>}
        </div>
      </div>
      <div style={{ flex: 1 }} />
      <div class="foot">
        {srv ? <button class="btn primary block" onClick={onNext}>Trust this server</button>
          : <button class="btn ghost block" onClick={connectServer}>Try again</button>}
      </div>
    </>
  );
}

/**
 * HumID can't see whose faces or fingers the phone has enrolled, only that a live match
 * happened. So it asks, once, and records the answer with this device in your ledger.
 * Adding anyone later destroys this device's keys (they're tied to the enrolled set).
 */
function SoleBiometric({ checked, onChange }) {
  return (
    <label class="check" style={{ marginBottom: 14 }}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.currentTarget.checked)} />
      <span>Only my own face or fingerprints are set up on this device. If anyone else's are added later, this device's HumID keys are destroyed.</span>
    </label>
  );
}

/** Bind buttons: hardware gate if present; demo only when the server accepts it. */
function BindButtons({ onBind, label, disabled = false }) {
  const hw = S.hwGate.value;
  const demo = S.demoAllowed.value;
  const policy = S.server.value?.policy?.devicePolicy || "attested";
  return (
    <>
      {!hw?.probe.available && hw?.probe.reason && (
        <div class="banner warn" style={{ marginBottom: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Open HumID in the app</strong><span>{hw.probe.reason} {demo ? "This development server also allows demo mode." : "PINs and passwords are never accepted."}</span></div></div>
      )}
      {hw?.probe.available && !hw.probe.proof && policy === "attested" && (
        <div class="banner warn" style={{ marginBottom: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Use your phone</strong><span>This vault accepts only phones whose secure chip can prove each face or fingerprint check. Set up HumID on your iPhone or Android phone first.</span></div></div>
      )}
      {hw?.probe.available && (hw.probe.proof || policy !== "attested") && <button class="btn primary block" disabled={disabled} onClick={() => onBind(false)}><Icon name="fingerprint" />{label} with {hw.probe.label}</button>}
      {demo && <button class={`btn ${hw?.probe.available ? "ghost" : "primary"} block`} disabled={disabled} onClick={() => onBind(true)}>Use demo mode (no sensor)</button>}
    </>
  );
}

export function Enroll() {
  const step = S.enrollStep.value;
  const hw = S.hwGate.value;
  const [sole, setSole] = useState(false);
  // The trust step only when the server isn't pinned by the build; the access step only when
  // this server needs a pass to create a HumID.
  const steps = [...(serverPinned() ? [] : ["connect"]), ...(S.passNeeded.value ? ["access"] : []), "bind", "done"];
  const idx = steps.indexOf(step);
  const at = Math.max(0, idx);
  const go = (i) => (S.enrollStep.value = steps[i]);
  const next = () => go(Math.min(idx + 1, steps.length - 1));
  const back = step !== "done" ? () => (idx <= 0 ? (S.view.value = "welcome") : go(idx - 1)) : null;
  return (
    <main class="screen">
      <TopBar step={at} steps={steps.length} onBack={back} />

      {step === "connect" && <ConnectStep eyebrow="Step 1 · Your vault server" onNext={next} />}

      {step === "access" && <AccessStep eyebrow={`Step ${at + 1} · Your access pass`} onNext={next} />}

      {step === "bind" && (
        <>
          <div class="eyebrow">Step {at + 1} · Bind to this device</div>
          <h1 style={{ marginTop: 8 }}>Your body becomes the key</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your keys are generated on this phone and locked behind {hw?.probe.available ? hw.probe.label : "your biometric"}. They never leave it, and HumID never sees your biometric.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "26px 0 10px" }}><Mark size={170} /></div>
          <div style={{ flex: 1 }} />
          <div class="foot">
            <SoleBiometric checked={sole} onChange={setSole} />
            <BindButtons onBind={(demo) => enroll(demo, { soleBiometric: sole })} label="Bind" disabled={!sole} />
          </div>
        </>
      )}

      {step === "done" && <EnrollDone />}
    </main>
  );
}

/**
 * Step: pay without being identified. The access code someone bought (cash at a counter,
 * or any online store) is swapped for an access pass the vault signs blind: when the
 * pass is spent at registration, the vault can't tell which code or purchase it came from.
 */
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
      <div class="eyebrow">{eyebrow}</div>
      <h1 style={{ marginTop: 8 }}>Pay without being known</h1>
      <p class="lede" style={{ marginTop: 10 }}>Your access code becomes a pass the vault signs without seeing it. When you create your HumID, the vault can check the pass is real, but it can't tell which code, purchase or person it came from.</p>

      {rec?.state === "ready" ? (
        <div class="banner" style={{ marginTop: 22 }}><span class="b-ico"><Icon name="check" /></span><div><strong>Access pass ready</strong><span>Kept on this phone until you create your HumID. Your access code is no longer stored.</span></div></div>
      ) : rec?.state === "draft" ? (
        <div class="banner warn" style={{ marginTop: 22 }}><span class="b-ico"><Icon name="clock" /></span><div><strong>Finishing your pass</strong><span>Your code was sent but the answer didn't arrive. It's saved here, so nothing is lost.</span></div></div>
      ) : (
        <div class="field" style={{ marginTop: 22 }}>
          <label for="access">Access code</label>
          <input id="access" class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
            value={text} onInput={(e) => setText(e.currentTarget.value)} disabled={busy} />
          {valid && <span class="hint ok"><Icon name="check" />Code looks right</span>}
          {!valid && typed >= 24 && <span class="hint warn">That code has a typo. Check each character.</span>}
          {!typed && <span class="hint">{buyUrl ? <>Don't have one? <a href={buyUrl} target="_blank" rel="noopener noreferrer">Buy an access code</a>. Paying with cash leaves no trace at all.</> : "Bought with cash at a counter, or online. Either way, the pass can't be traced to it."}</span>}
        </div>
      )}

      <div style={{ flex: 1 }} />
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

function EnrollDone() {
  const code = S.cardCode.value;
  const [saved, setSaved] = useState(false);
  return (
    <>
      <div class="hero" style={{ flex: "0 0 auto", marginTop: 4 }}><Mark state="verified" size={110} /></div>
      <h1 style={{ textAlign: "center", marginTop: 10 }}>You're all set</h1>
      <p class="lede" style={{ textAlign: "center", margin: "8px auto 0" }}>Your HumID is live and bound to this device. <AssurancePill assurance={S.identity.value?.assurance} /></p>

      {code ? (
        <div class="card" style={{ marginTop: 18 }}>
          <h3>Save your seal card</h3>
          <p class="small muted" style={{ marginTop: 6 }}>One of two proofs that bring your vault back if you lose every device. On its own it opens nothing: recovery also needs your witnesses or your ID, then waits while your devices can veto.</p>
          <CardBox code={code} />
          <div class="split" style={{ marginTop: 12 }}>
            {CAN_PRINT && <button class="btn quiet sm" onClick={() => window.print()}><Icon name="file" />Print</button>}
            <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save</button>
            <button class="btn quiet sm" onClick={() => copyCard(code)}><Icon name="file" />Copy</button>
          </div>
          <CardConfirm code={code} onChange={setSaved} />
          <PrintableCard code={code} />
        </div>
      ) : null}

      {code ? (
        <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="shield" /></span><div><strong>Next: finish protecting it</strong><span>Your vault shows what's left, with a button for each: a second proof (witnesses keep you anonymous) and a second device, so a lost phone is never an emergency.</span></div></div>
      ) : (
        <div class="banner warn" style={{ marginTop: 18 }}><span class="b-ico"><Icon name="info" /></span><div><strong>No recovery set up yet</strong><span>In Security, set up two proofs (witnesses, your ID, a seal card), or add a second device, so losing this phone doesn't lose your vault.</span></div></div>
      )}

      <div style={{ flex: 1 }} />
      <div class="foot">
        {/* Never a dead grey button: until the card is checked, it says why and takes you to the check. */}
        <button class={`btn secure block${code && !saved ? " waiting" : ""}`}
          onClick={() => {
            if (!(code && !saved)) return finishEnroll();
            const f = document.getElementById("card-check");
            f?.scrollIntoView({ block: "center", behavior: "smooth" });
            f?.focus({ preventScroll: true });
          }}>
          <Icon name="vault" />{code && !saved ? "Check your card to continue" : "Open my vault"}
        </button>
      </div>
    </>
  );
}

/* ---------------- joining an existing HumID ---------------- */

const ROUTES = [
  { id: "link", icon: "key", title: "From another device", desc: "A phone or laptop that already has your HumID approves this one. Takes a minute." },
  { id: "quorum", icon: "shield", title: "Prove it's me", desc: "Any two of: your witnesses, your ID chip, your seal card. Opens after a wait your devices can veto." },
];
const OLD_ROUTES = [
  { id: "card", icon: "idcard", title: "Older recovery card", desc: "A card made before two-proof recovery. Opens after 72 hours." },
  { id: "contacts", icon: "user", title: "Older recovery contacts", desc: "Contacts chosen before two-proof recovery. Then 72 hours." },
];

export function Join() {
  const step = S.joinStep.value;
  const method = S.joinMethod.value;
  const [old, setOld] = useState(false);
  const back = step === 0 || (step === 1 && serverPinned()) ? () => (S.view.value = "welcome") : step < 3 ? () => (S.joinStep.value = step - 1) : null;
  return (
    <main class="screen">
      <TopBar step={step} steps={4} onBack={back} />
      {step === 0 && <ConnectStep eyebrow="Step 1 · Your vault server" onNext={() => (S.joinStep.value = 1)} />}

      {step === 1 && (
        <>
          <div class="eyebrow">Step 2 · Bring your HumID here</div>
          <h1 style={{ marginTop: 8 }}>How do you want to get in?</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your vault key never passes through the server in a form it can read, whichever you choose.</p>
          <div class="options" style={{ marginTop: 20 }}>
            {(old ? [...ROUTES, ...OLD_ROUTES] : ROUTES).map((r) => (
              <button class="option" onClick={() => { S.joinMethod.value = r.id; S.joinStep.value = 2; }}>
                <span class="o-ico"><Icon name={r.icon} /></span>
                <span><strong>{r.title}</strong><span>{r.desc}</span></span>
                <Icon name="chevron" />
              </button>
            ))}
          </div>
          {!old && <button class="link" style={{ marginTop: 14 }} onClick={() => setOld(true)}>I have an older recovery card or contacts</button>}
        </>
      )}

      {step === 2 && method === "link" && (
        <JoinDetails title="Approve from your other device" lede="First, bind this device to your biometric. Then it shows a code and a QR code. On your other device: Security → Add a device."
          bindLabel="Bind" onBind={(demo, sole) => beginJoin("link", { useDemo: demo, soleBiometric: sole })} />
      )}
      {step === 2 && method === "quorum" && <QuorumEntry />}
      {step === 2 && method === "card" && <CardEntry />}
      {step === 2 && method === "contacts" && (
        <JoinDetails title="Ask your recovery contacts" lede="Bind this device, then send the code it shows to your recovery contacts. When enough of them approve, your vault opens here after 72 hours, unless you cancel from a device you still have."
          bindLabel="Bind" onBind={(demo, sole) => beginJoin("contacts", { useDemo: demo, soleBiometric: sole })} />
      )}

      {step === 3 && <JoinWait />}
    </main>
  );
}

function JoinDetails({ title, lede, bindLabel, onBind, disabled, children }) {
  const [sole, setSole] = useState(false);
  return (
    <>
      <div class="eyebrow">Step 3 · Bind this device</div>
      <h1 style={{ marginTop: 8 }}>{title}</h1>
      <p class="lede" style={{ marginTop: 10 }}>{lede}</p>
      {children}
      <div style={{ flex: 1 }} />
      <div class="foot">
        <SoleBiometric checked={sole} onChange={setSole} />
        <BindButtons onBind={(demo) => onBind(demo, sole)} label={bindLabel} disabled={disabled || !sole} />
      </div>
    </>
  );
}

function QuorumEntry() {
  const [text, setText] = useState("");
  let state = null;
  try { if (text.replace(/[^0-9a-z]/gi, "").length >= 30) { parseCard(text); state = "ok"; } } catch (e) { state = e.message; }
  return (
    <JoinDetails title="Prove it's you" lede="Recovery needs two different proofs that you're the person who set up this HumID: your witnesses, your ID chip, your seal card. Bind this device first. Your other devices are alerted and can veto during the wait."
      bindLabel="Bind" disabled={!!text.trim() && state !== "ok"} onBind={(demo, sole) => beginJoin("quorum", { useDemo: demo, cardInput: state === "ok" ? text : "", soleBiometric: sole })}>
      <div class="field">
        <label for="qcard">Seal card (if you have it)</label>
        <input id="qcard" class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          value={text} onInput={(e) => setText(e.currentTarget.value)} />
        {state === "ok" && <span class="hint ok"><Icon name="check" />Card code looks right</span>}
        {state && state !== "ok" && <span class="hint warn">{state}</span>}
        {!text && <span class="hint">You can also add it later, or use witnesses and your ID instead.</span>}
      </div>
    </JoinDetails>
  );
}

function CardEntry() {
  const [text, setText] = useState("");
  let state = null;
  try { if (text.replace(/[^0-9a-z]/gi, "").length >= 30) { parseCard(text); state = "ok"; } } catch (e) { state = e.message; }
  return (
    <JoinDetails title="Use your recovery card" lede="Type the code from your card. Then bind this device. Your vault opens here after 72 hours, and every device you still have is alerted and can cancel."
      bindLabel="Bind" disabled={state !== "ok"} onBind={(demo, sole) => beginJoin("card", { useDemo: demo, cardInput: text, soleBiometric: sole })}>
      <div class="field">
        <label for="card">Recovery card</label>
        <input id="card" class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          value={text} onInput={(e) => setText(e.currentTarget.value)} />
        {state === "ok" && <span class="hint ok"><Icon name="check" />Card code looks right</span>}
        {state && state !== "ok" && <span class="hint warn">{state}</span>}
      </div>
    </JoinDetails>
  );
}

function JoinWait() {
  const id = S.identity.value;
  const p = id?.pending;
  const st = S.joinStatus.value;
  const now = useNow();
  if (!p) return null;
  const ended = st && ["expired", "cancelled"].includes(st.status);
  const releaseAt = st?.releaseAt || p.releaseAt;
  return (
    <>
      <div class="eyebrow">Step 4 · {p.method === "link" ? "Approve on your other device" : "Waiting for your vault"}</div>

      {p.method === "link" && (
        <>
          <h1 style={{ marginTop: 8 }}>Enter this code on your other device</h1>
          <p class="lede" style={{ marginTop: 10 }}>On the device that has your HumID: <b>Security → Add a device</b>. It checks that this code matches this device's keys, then asks for your biometric.</p>
          <CodeBox code={p.code} label="Device code" />
          <QrCode kind="link" code={p.code} />
          {!ended && <p class="fine" style={{ textAlign: "center" }}>Scan it from your other device, or type it. Expires in {fmtLeft(p.expiresAt - now)}</p>}
        </>
      )}

      {p.method === "card" && (
        <>
          <h1 style={{ marginTop: 8 }}>Your vault opens here in {fmtLeft((releaseAt || 0) - now)}</h1>
          <p class="lede" style={{ marginTop: 10 }}>Every device that still has your HumID was alerted and can cancel. This wait is what stops someone who found your card. You can close the app; it picks up where it left off.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0" }}><Mark state="scanning" size={140} /></div>
        </>
      )}

      {p.method === "quorum" && <QuorumWait p={p} st={st} now={now} />}

      {p.method === "contacts" && (
        <>
          <h1 style={{ marginTop: 8 }}>{releaseAt ? `Your vault opens here in ${fmtLeft(releaseAt - now)}` : "Send this code to your contacts"}</h1>
          <p class="lede" style={{ marginTop: 10 }}>{releaseAt
            ? "Enough contacts approved. Every device that still has your HumID was alerted and can cancel during the wait."
            : <>Ask each contact to open HumID → <b>Security → Help recover</b> and enter this code. Call them, so they know it's really you.</>}</p>
          {!releaseAt && <CodeBox code={p.code} label="Recovery code" />}
          <div class="card" style={{ marginTop: 14 }}>
            <div class="row"><span class="k">Contacts who helped</span><span class="v">{st?.approvals ?? 0}{st?.threshold ? ` of ${st.threshold} needed` : ""}</span></div>
          </div>
        </>
      )}

      {st?.status === "expired" && <div class="banner warn" style={{ marginTop: 16 }}><span class="b-ico"><Icon name="clock" /></span><div><strong>This expired</strong><span>Start again to get a fresh code.</span></div></div>}
      {st?.status === "cancelled" && <div class="banner bad" style={{ marginTop: 16 }}><span class="b-ico"><Icon name="alert" /></span><div><strong>Cancelled from one of your devices</strong><span>{st.reason === "card_replaced" ? "The recovery card was replaced." : "If that wasn't you, someone else has your HumID unlocked."}</span></div></div>}
      {st?.status === "error" && <div class="banner bad" style={{ marginTop: 16 }}><span class="b-ico"><Icon name="alert" /></span><div><strong>Couldn't finish</strong><span>{st.message}</span></div></div>}

      <div style={{ flex: 1 }} />
      <div class="foot">
        {st?.status === "error" && <button class="btn primary block" onClick={pollJoin}>Try again</button>}
        {ended && <button class="btn primary block" onClick={cancelJoin}>Start again</button>}
        {!ended && <button class="link" onClick={cancelJoin}>Cancel and start over</button>}
        <p class="fine">This device is bound to {id.method === "demo-no-hardware" ? "demo mode" : "your biometric"} · {serverHost(id.server?.url)}</p>
      </div>
    </>
  );
}

function QuorumWait({ p, st, now }) {
  const kinds = [...new Set([...(st?.kinds || []), ...(p.hasCard ? ["card"] : [])])];
  const releaseAt = st?.releaseAt;
  const [card, setCard] = useState("");
  const [name, setName] = useState("Demo Person");
  const [busy, setBusy] = useState(false);
  const ended = st && ["expired", "cancelled"].includes(st.status);
  const tier = tierText(kinds, st?.anchorMode);
  const cardOk = (() => { try { parseCard(card); return true; } catch { return false; } })();
  const [access, setAccess] = useState(null);
  const nfc = S.nfc.value;
  const chip = async () => { setBusy(true); await addChipToJoin(demoChipSource(name)); setBusy(false); };
  const readLive = async () => { setBusy(true); await addChipToJoin(nfcChipSource(access)); setBusy(false); };
  return (
    <>
      <h1 style={{ marginTop: 8 }}>{releaseAt ? `Your vault opens here in ${fmtLeft(releaseAt - now)}` : kinds.length ? "One proof in. Add a second" : "Show your proofs"}</h1>
      <p class="lede" style={{ marginTop: 10 }}>{releaseAt
        ? <>Two proofs matched ({st.evidence}). Every device that still has your HumID was alerted and can veto. {st.duress && <b>The wait is doubled because of a recent duress signal.</b>}</>
        : <>Any two different proofs. Witnesses open HumID → <b>Security → Help recover</b>; a HumID station operator scans this code with your ID in hand.</>}</p>
      <ProofMeter have={kinds} />
      {tier && <p class="tier" style={{ marginTop: 10 }}><Icon name="clock" />Wait with these proofs: {tier}</p>}

      {!releaseAt && !ended && (
        <>
          <CodeBox code={p.code} label="Recovery code" />
          <QrCode kind="recover" code={p.code} />
          <div class="card" style={{ marginTop: 14 }}>
            <div class="proof-row" data-done={kinds.includes("witness") ? "1" : "0"}>
              <span class="p-ico"><Icon name="users" /></span>
              <span><strong>Witnesses</strong><span>{st?.threshold ? `${st.approvals ?? 0} of ${st.threshold} have approved` : st?.approvals ? `${st.approvals} approved so far` : "Send them the code above and call them, so they know it's you."}</span></span>
              {kinds.includes("witness") ? <Icon name="check" /> : <span />}
            </div>
            <div class="proof-row" data-done={kinds.includes("card") ? "1" : "0"}>
              <span class="p-ico"><Icon name="idcard" /></span>
              <span><strong>Seal card</strong><span>{kinds.includes("card") ? "Added" : "Type it below if you have it."}</span></span>
              {kinds.includes("card") ? <Icon name="check" /> : <span />}
            </div>
            {!kinds.includes("card") && (
              <div class="field" style={{ marginTop: 0 }}>
                <input aria-label="Seal card" class="mono up" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-…" value={card} onInput={(e) => setCard(e.currentTarget.value)} />
                <button class="btn quiet sm" style={{ marginTop: 8 }} disabled={!cardOk} onClick={async () => { if (await addCardToJoin(card)) setCard(""); }}><Icon name="fingerprint" />Add seal card</button>
              </div>
            )}
            <div class="proof-row" data-done={kinds.includes("anchor") ? "1" : "0"}>
              <span class="p-ico"><Icon name="passport" /></span>
              <span><strong>ID chip</strong><span>{kinds.includes("anchor") ? (st?.anchorMode === "station" ? "Verified in person at a station" : "Verified live") : nfc?.available ? "Read your passport or ID card's chip now, or show this code at a HumID station." : "At a HumID station: show the operator this code and your passport or ID."}</span></span>
              {kinds.includes("anchor") ? <Icon name="check" /> : <span />}
            </div>
            {nfc?.available && !kinds.includes("anchor") && (
              <>
                <ChipAccess onChange={setAccess} />
                <button class="btn quiet sm" style={{ marginTop: 8 }} disabled={busy || !access} onClick={readLive}><Icon name="passport" />{nfc.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
              </>
            )}
            {DEMO_BUILD && !kinds.includes("anchor") && (
              <div class="field" style={{ marginTop: 0 }}>
                <input aria-label="Demo passport holder" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                <button class="btn quiet sm" style={{ marginTop: 8 }} disabled={busy} onClick={chip}><Icon name="passport" />Tap demo passport</button>
              </div>
            )}
          </div>
        </>
      )}
      {releaseAt && <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0" }}><Mark state="scanning" size={140} /></div>}
    </>
  );
}

/* ---------------- lock ---------------- */

const ISSUES = {
  server_identity_changed: (host) => ({
    title: "Your vault server's identity changed",
    text: `The server at ${host} presented a different post-quantum key than the one this phone trusts, so HumID refused to connect. This happens if the server was rebuilt, or if someone is impersonating it.`,
    warn: true,
  }),
  unknown_identity: (host) => ({ title: "Your vault doesn't know this HumID", text: `The server at ${host} has no record of this identity. It may have been reset or replaced, or this HumID came from an earlier test version.` }),
  device_not_proven: () => ({ title: "Your vault needs a provable live check", text: "This vault server now accepts only devices whose secure chip proves every face or fingerprint check. Open HumID on your phone, or add this device again once it qualifies." }),
  device_removed: () => ({ title: "This device was removed from your HumID", text: "Someone removed it from another of your devices. It can no longer open your vault. If that was you, set this device up again with I already have HumID." }),
};

/**
 * The unlock controls, with the duress gesture if it's on. Both gestures look like
 * ordinary unlocking: hold the Unlock button a little longer, or tap the mark a few
 * times. Nothing on screen changes to show which one happened.
 */
function useUnlockGestures(duress) {
  const taps = useRef({ n: 0, t: null });
  const press = useRef(0);
  const gesture = duress?.enabled ? duress.gesture : null;
  const onMark = () => {
    if (gesture !== "taps") return unlock(false);
    const st = taps.current;
    st.n += 1;
    clearTimeout(st.t);
    st.t = setTimeout(() => { const n = st.n; st.n = 0; unlock(n >= 3); }, 650);
  };
  const button = gesture === "hold"
    ? {
      onPointerDown: () => { press.current = Date.now(); },
      onPointerUp: () => { const held = press.current && Date.now() - press.current; press.current = 0; unlock(held >= DURESS_HOLD_MS); },
      onPointerLeave: () => { press.current = 0; },
      onKeyDown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); unlock(false); } },
      onContextMenu: (e) => e.preventDefault(),
    }
    : { onClick: () => unlock(false) };
  return { onMark, button };
}

export function Lock() {
  const id = S.identity.value;
  const [confirm, setConfirm] = useState(false);
  const issue = S.lockIssue.value;
  const g = useUnlockGestures(id?.duress);
  if (issue) {
    const x = (ISSUES[issue] || ISSUES.unknown_identity)(serverHost(id?.server?.url));
    return (
      <main class="screen">
        <div class="hero" style={{ flex: "0 0 auto", marginTop: "8vh" }}><Mark state="failed" progress={1} size={150} /></div>
        <h1 style={{ textAlign: "center", marginTop: 18 }}>{x.title}</h1>
        <p class="lede" style={{ textAlign: "center", margin: "10px auto 0" }}>{x.text}</p>
        {x.warn && <div class="banner warn" style={{ marginTop: 18 }}><span class="b-ico"><Icon name="alert" /></span><div><strong>Don't continue unless you expected this</strong><span>Check with whoever runs your vault server before setting up again.</span></div></div>}
        <div style={{ flex: 1 }} />
        <div class="foot">
          {!confirm && <button class="btn ghost block" onClick={() => setConfirm(true)}>Set up HumID again</button>}
          {confirm && <button class="btn danger block" onClick={resetLocal}>Remove this identity from this phone</button>}
          {confirm && <p class="fine">Your documents stay in your vault. Get back in with another device, your recovery card or your contacts.</p>}
          <button class="btn primary block" onClick={() => { S.lockIssue.value = null; setConfirm(false); }}>Back</button>
        </div>
      </main>
    );
  }
  return (
    <main class="screen">
      <Stars count={60} />
      <div class="hero">
        <button class="lockmark" aria-label="Unlock HumID" onClick={g.onMark}><Mark size={230} /></button>
        <Wordmark />
        <div class="tagline">Safe.&nbsp; Secure.&nbsp; Simple.</div>
      </div>
      <div class="foot">
        <button class="btn primary block" {...g.button}><Icon name="fingerprint" />Unlock</button>
        {(!S.online.value || S.serverError.value) && S.offlineReady.value && (
          <p class="fine offline-note" role="status">No connection. You can still unlock to see your vault, read only.</p>
        )}
        <p class="fine">{id?.mode === "demo" ? "Demo identity · no hardware sensor" : "Keys stay sealed until a live biometric check"}{id?.server ? ` · ${serverHost(id.server.url)}` : ""}</p>
      </div>
    </main>
  );
}

