// Welcome → Enrol (connect · bind · done) → Lock.
import { Mark, Wordmark, Stars } from "../brand.jsx";
import { Icon } from "../icons.jsx";
import { AssurancePill, groupKey } from "../ui.jsx";
import * as S from "../core/state.js";
import { startEnroll, enroll, finishEnroll, unlock, connectServer, resetLocal } from "../core/controller.js";
import { useState } from "preact/hooks";
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
        <p class="fine">Post-quantum protection: ML-KEM-1024 + X25519 · ML-DSA-87</p>
      </div>
    </main>
  );
}

export function Enroll() {
  const step = S.enrollStep.value;
  const hw = S.hwGate.value;
  const srv = S.server.value;
  return (
    <main class="screen">
      <div class="topbar">
        {step < 2 && <button class="icon-btn" aria-label="Back" onClick={() => (step === 0 ? (S.view.value = "welcome") : (S.enrollStep.value = step - 1))}><Icon name="back" /></button>}
        <div class="grow" />
        <Wordmark small />
      </div>
      <div class="stepper" aria-label={`Step ${step + 1} of 3`}>{[0, 1, 2].map((i) => <i class={i <= step ? "on" : ""} />)}</div>

      {step === 0 && (
        <>
          <div class="eyebrow">Step 1 · Your vault server</div>
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
            {srv ? <button class="btn primary block" onClick={() => (S.enrollStep.value = 1)}>Trust this server</button>
              : <button class="btn ghost block" onClick={connectServer}>Try again</button>}
          </div>
        </>
      )}

      {step === 1 && (
        <>
          <div class="eyebrow">Step 2 · Bind to this device</div>
          <h1 style={{ marginTop: 8 }}>Your body becomes the key</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your keys are generated on this phone and locked behind {hw?.probe.available ? hw.probe.label : "your biometric"}. They never leave it, and HumID never sees your biometric.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "26px 0 10px" }}><Mark size={170} /></div>
          {!hw?.probe.available && hw?.probe.reason && (
            <div class="banner warn"><span class="b-ico"><Icon name="info" /></span><div><strong>No biometric gate here</strong><span>{hw.probe.reason} You can try HumID in demo mode.</span></div></div>
          )}
          <div style={{ flex: 1 }} />
          <div class="foot">
            {hw?.probe.available && <button class="btn primary block" onClick={() => enroll(false)}><Icon name="fingerprint" />Bind with {hw.probe.label}</button>}
            <button class={`btn ${hw?.probe.available ? "ghost" : "primary"} block`} onClick={() => enroll(true)}>Use demo mode (no sensor)</button>
          </div>
        </>
      )}

      {step === 2 && (
        <>
          <div class="hero" style={{ flex: "0 0 auto", marginTop: 12 }}><Mark state="verified" size={150} /></div>
          <h1 style={{ textAlign: "center", marginTop: 14 }}>You're all set</h1>
          <p class="lede" style={{ textAlign: "center", margin: "10px auto 0" }}>Your HumID is live and bound to this device.</p>
          <div class="card" style={{ marginTop: 22 }}>
            <div class="row"><span class="k">Protection</span><span class="v"><AssurancePill assurance={S.identity.value?.assurance} /></span></div>
            <div class="row" style={{ display: "block" }}>
              <div class="k" style={{ marginBottom: 10 }}>Identity commitment</div>
              <div class="kid">{groupKey(S.identity.value?.commit).slice(0, 8).map((g) => <span>{g}</span>)}</div>
            </div>
          </div>
          <div style={{ flex: 1 }} />
          <div class="foot"><button class="btn secure block" onClick={finishEnroll}><Icon name="vault" />Open my vault</button></div>
        </>
      )}
    </main>
  );
}

export function Lock() {
  const id = S.identity.value;
  const [confirm, setConfirm] = useState(false);
  const issue = S.lockIssue.value;
  if (issue) {
    const changed = issue === "server_identity_changed";
    return (
      <main class="screen">
        <div class="hero" style={{ flex: "0 0 auto", marginTop: "8vh" }}><Mark state="failed" progress={1} size={150} /></div>
        <h1 style={{ textAlign: "center", marginTop: 18 }}>{changed ? "Your vault server's identity changed" : "Your vault doesn't know this HumID"}</h1>
        <p class="lede" style={{ textAlign: "center", margin: "10px auto 0" }}>
          {changed
            ? `The server at ${serverHost(id?.server?.url)} presented a different post-quantum key than the one this phone trusts, so HumID refused to connect. This happens if the server was rebuilt, or if someone is impersonating it.`
            : `The server at ${serverHost(id?.server?.url)} has no record of this identity. It may have been reset or replaced.`}
        </p>
        {changed && <div class="banner warn" style={{ marginTop: 18 }}><span class="b-ico"><Icon name="alert" /></span><div><strong>Don't continue unless you expected this</strong><span>Check with whoever runs your vault server before setting up again.</span></div></div>}
        <div style={{ flex: 1 }} />
        <div class="foot">
          {!confirm && <button class="btn ghost block" onClick={() => setConfirm(true)}>Set up HumID again</button>}
          {confirm && <button class="btn danger block" onClick={resetLocal}>Remove this identity from this phone</button>}
          {confirm && <p class="fine">Documents stored with the old identity can't be opened from this phone afterwards.</p>}
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
