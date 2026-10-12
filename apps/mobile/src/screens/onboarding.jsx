// Welcome → Enrol (connect · bind · done + recovery card) → Lock.
// Welcome → Join (connect · choose · details · wait) for a new device of an existing HumID.
import { Mark, Wordmark, Stars } from "../brand.jsx";
import { Icon } from "../icons.jsx";
import { AssurancePill, CodeBox, CardBox, useNow, fmtLeft } from "../ui.jsx";
import * as S from "../core/state.js";
import {
  startEnroll, enroll, finishEnroll, unlock, connectServer, resetLocal, saveCard, copyCard,
  startJoin, beginJoin, pollJoin, cancelJoin,
} from "../core/controller.js";
import { useState } from "preact/hooks";
import { parseCard } from "@humid/recovery";
import { serverHost, SERVER_URL } from "../core/config.js";

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
      <div class="stepper" aria-label={`Step ${step + 1} of ${steps}`}>{Array.from({ length: steps }, (_, i) => <i class={i <= step ? "on" : ""} />)}</div>
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

/** Bind buttons: hardware gate if present; demo only when the server accepts it. */
function BindButtons({ onBind, label, disabled = false }) {
  const hw = S.hwGate.value;
  const demo = S.demoAllowed.value;
  return (
    <>
      {!hw?.probe.available && hw?.probe.reason && (
        <div class="banner warn" style={{ marginBottom: 12 }}><span class="b-ico"><Icon name="info" /></span><div><strong>No biometric gate here</strong><span>{hw.probe.reason} {demo ? "You can try HumID in demo mode." : "This vault server requires a real biometric sensor."}</span></div></div>
      )}
      {hw?.probe.available && <button class="btn primary block" disabled={disabled} onClick={() => onBind(false)}><Icon name="fingerprint" />{label} with {hw.probe.label}</button>}
      {demo && <button class={`btn ${hw?.probe.available ? "ghost" : "primary"} block`} disabled={disabled} onClick={() => onBind(true)}>Use demo mode (no sensor)</button>}
    </>
  );
}

export function Enroll() {
  const step = S.enrollStep.value;
  const hw = S.hwGate.value;
  const back = step < 2 ? () => (step === 0 ? (S.view.value = "welcome") : (S.enrollStep.value = step - 1)) : null;
  return (
    <main class="screen">
      <TopBar step={step} steps={3} onBack={back} />

      {step === 0 && <ConnectStep eyebrow="Step 1 · Your vault server" onNext={() => (S.enrollStep.value = 1)} />}

      {step === 1 && (
        <>
          <div class="eyebrow">Step 2 · Bind to this device</div>
          <h1 style={{ marginTop: 8 }}>Your body becomes the key</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your keys are generated on this phone and locked behind {hw?.probe.available ? hw.probe.label : "your biometric"}. They never leave it, and HumID never sees your biometric.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "26px 0 10px" }}><Mark size={170} /></div>
          <div style={{ flex: 1 }} />
          <div class="foot"><BindButtons onBind={enroll} label="Bind" /></div>
        </>
      )}

      {step === 2 && <EnrollDone />}
    </main>
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
          <h3>Save your recovery card</h3>
          <p class="small muted" style={{ marginTop: 6 }}>If you lose every device, this card brings your vault back on a new one. Recovery waits 72 hours and alerts your devices, so a stolen card alone isn't enough.</p>
          <CardBox code={code} />
          <div class="split" style={{ marginTop: 12 }}>
            <button class="btn quiet sm" onClick={() => saveCard(code)}><Icon name="download" />Save</button>
            <button class="btn quiet sm" onClick={() => copyCard(code)}><Icon name="file" />Copy</button>
          </div>
          <label class="check" style={{ marginTop: 14 }}>
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
            <span>I've stored my card somewhere safe and offline</span>
          </label>
        </div>
      ) : (
        <div class="banner warn" style={{ marginTop: 18 }}><span class="b-ico"><Icon name="info" /></span><div><strong>No recovery card yet</strong><span>Make one in Security, or add a second device, so losing this phone doesn't lose your vault.</span></div></div>
      )}

      <div style={{ flex: 1 }} />
      <div class="foot"><button class="btn secure block" disabled={code && !saved} onClick={finishEnroll}><Icon name="vault" />Open my vault</button></div>
    </>
  );
}

/* ---------------- joining an existing HumID ---------------- */

const ROUTES = [
  { id: "link", icon: "key", title: "From another device", desc: "A phone or tablet that already has your HumID approves this one. Takes a minute." },
  { id: "card", icon: "idcard", title: "With my recovery card", desc: "Type the HUMID-… code. Opens after 72 hours, and your devices are alerted." },
  { id: "contacts", icon: "user", title: "With my recovery contacts", desc: "People you chose approve with their own biometric. Then 72 hours." },
];

export function Join() {
  const step = S.joinStep.value;
  const method = S.joinMethod.value;
  const back = step === 0 ? () => (S.view.value = "welcome") : step < 3 ? () => (S.joinStep.value = step - 1) : null;
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
            {ROUTES.map((r) => (
              <button class="option" onClick={() => { S.joinMethod.value = r.id; S.joinStep.value = 2; }}>
                <span class="o-ico"><Icon name={r.icon} /></span>
                <span><strong>{r.title}</strong><span>{r.desc}</span></span>
                <Icon name="chevron" />
              </button>
            ))}
          </div>
        </>
      )}

      {step === 2 && method === "link" && (
        <JoinDetails title="Approve from your other device" lede="First, bind this device to your biometric. Then it shows a code. Enter that code on your other device in Security → Add a device."
          bindLabel="Bind" onBind={(demo) => beginJoin("link", { useDemo: demo })} />
      )}
      {step === 2 && method === "card" && <CardEntry />}
      {step === 2 && method === "contacts" && (
        <JoinDetails title="Ask your recovery contacts" lede="Bind this device, then send the code it shows to your recovery contacts. When enough of them approve, your vault opens here after 72 hours, unless you cancel from a device you still have."
          bindLabel="Bind" onBind={(demo) => beginJoin("contacts", { useDemo: demo })} />
      )}

      {step === 3 && <JoinWait />}
    </main>
  );
}

function JoinDetails({ title, lede, bindLabel, onBind, disabled, children }) {
  return (
    <>
      <div class="eyebrow">Step 3 · Bind this device</div>
      <h1 style={{ marginTop: 8 }}>{title}</h1>
      <p class="lede" style={{ marginTop: 10 }}>{lede}</p>
      {children}
      <div style={{ flex: 1 }} />
      <div class="foot"><BindButtons onBind={onBind} label={bindLabel} disabled={disabled} /></div>
    </>
  );
}

function CardEntry() {
  const [text, setText] = useState("");
  let state = null;
  try { if (text.replace(/[^0-9a-z]/gi, "").length >= 30) { parseCard(text); state = "ok"; } } catch (e) { state = e.message; }
  return (
    <JoinDetails title="Use your recovery card" lede="Type the code from your card. Then bind this device. Your vault opens here after 72 hours, and every device you still have is alerted and can cancel."
      bindLabel="Bind" disabled={state !== "ok"} onBind={(demo) => beginJoin("card", { useDemo: demo, cardInput: text })}>
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
          {!ended && <p class="fine" style={{ textAlign: "center" }}>Code expires in {fmtLeft(p.expiresAt - now)}</p>}
        </>
      )}

      {p.method === "card" && (
        <>
          <h1 style={{ marginTop: 8 }}>Your vault opens here in {fmtLeft((releaseAt || 0) - now)}</h1>
          <p class="lede" style={{ marginTop: 10 }}>Every device that still has your HumID was alerted and can cancel. This wait is what stops someone who found your card. You can close the app; it picks up where it left off.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0" }}><Mark state="scanning" size={140} /></div>
        </>
      )}

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

/* ---------------- lock ---------------- */

const ISSUES = {
  server_identity_changed: (host) => ({
    title: "Your vault server's identity changed",
    text: `The server at ${host} presented a different post-quantum key than the one this phone trusts, so HumID refused to connect. This happens if the server was rebuilt, or if someone is impersonating it.`,
    warn: true,
  }),
  unknown_identity: (host) => ({ title: "Your vault doesn't know this HumID", text: `The server at ${host} has no record of this identity. It may have been reset or replaced, or this HumID came from an earlier test version.` }),
  device_removed: () => ({ title: "This device was removed from your HumID", text: "Someone removed it from another of your devices. It can no longer open your vault. If that was you, set this device up again with I already have HumID." }),
};

export function Lock() {
  const id = S.identity.value;
  const [confirm, setConfirm] = useState(false);
  const issue = S.lockIssue.value;
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
        <button class="lockmark" aria-label="Unlock HumID" onClick={unlock}><Mark size={230} /></button>
        <Wordmark />
        <div class="tagline">Safe.&nbsp; Secure.&nbsp; Simple.</div>
      </div>
      <div class="foot">
        <button class="btn primary block" onClick={unlock}><Icon name="fingerprint" />Unlock</button>
        <p class="fine">{id?.mode === "demo" ? "Demo identity · no hardware sensor" : "Keys stay sealed until a live biometric check"}{id?.server ? ` · ${serverHost(id.server.url)}` : ""}</p>
      </div>
    </main>
  );
}

