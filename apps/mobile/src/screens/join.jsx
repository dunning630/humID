// I already have HumID: add this device from another, or prove it's you with two proofs.
// 3.0: a "what you'll need" prelude before anything is bound, one proof at a time while
// collecting, a fresh code without unbinding when a link expires, and a clear stop when
// the match code doesn't match.
import { useState } from "preact/hooks";
import { Mark } from "../brand/mark.jsx";
import { Icon } from "../brand/icons.jsx";
import { Banner, Row, useNow } from "../ui/kit.jsx";
import { fmtLeft } from "../ui/format.js";
import { CodeBox, QrCode, ProofMeter, tierText, WAITS, ChipAccess, PROOFS } from "../ui/codes.jsx";
import { TopBar, ConnectStep, SoleBiometric, BindButtons } from "./create.jsx";
import * as S from "../core/state.js";
import { beginJoin, pollJoin, cancelJoin, confirmJoin, rejectJoin, renewLink, addCardToJoin, addChipToJoin, addKeyToJoin, demoChipSource, nfcChipSource, serverPinned, joinRoutes, setJoinMode, HOLDER_ONLY } from "../core/index.js";
import { parseCard } from "@humid/recovery";
import { serverHost, DEMO_BUILD } from "../core/config.js";

const ROUTES = [
  { id: "link", icon: "key", title: "From another device", desc: "A phone that already has your HumID approves this one. Takes a minute." },
  { id: "quorum", icon: "shield", title: "Prove it's me", desc: "Any two of: your witnesses, your ID chip, your recovery card, your security key. Opens after a wait your devices can veto." },
];
const OLD_ROUTES = [
  { id: "card", icon: "idcard", title: "Older recovery card", desc: "A card made before two-proof recovery. Opens after 72 hours." },
  { id: "contacts", icon: "user", title: "Older witnesses", desc: "Witnesses chosen before two-proof recovery. Then 72 hours." },
];

export function Join() {
  const step = S.joinStep.value;
  const method = S.joinMethod.value;
  const [old, setOld] = useState(false);
  const [prelude, setPrelude] = useState(true);
  const steps = (serverPinned() ? 0 : 1) + 3;
  const shown = step - (serverPinned() ? 1 : 0);
  const back = step === 0 || (step === 1 && serverPinned()) ? () => (S.view.value = "welcome") : step < 3 ? () => (S.joinStep.value = step - 1) : null;
  const n = (k) => `Step ${k - (serverPinned() ? 1 : 0) + 1} of ${steps}`;
  // Only the routes this HumID's recovery mode allows: just "from another device" for holder-only.
  const allowed = joinRoutes();
  const holderOnly = S.joinMode.value === HOLDER_ONLY;
  if (step === 4) return <Mismatch />;
  return (
    <main class="screen">
      <TopBar step={Math.max(0, Math.min(steps - 1, shown))} steps={steps} onBack={back} />
      {step === 0 && <ConnectStep eyebrow={n(0)} onNext={() => (S.joinStep.value = 1)} />}
      {step === 1 && (
        <>
          <div class="eyebrow">{n(1)} · Bring your HumID here</div>
          <h1 style={{ marginTop: 8 }}>How do you want to get in?</h1>
          <p class="lede" style={{ marginTop: 10 }}>{holderOnly
            ? "Your HumID opens only on your own devices, so this one joins from a device you already use. There's no other way in, by your choice."
            : "Your vault key never passes through the server in a form it can read, whichever you choose."}</p>
          <div class="options" style={{ marginTop: 20 }}>
            {(old ? [...ROUTES, ...OLD_ROUTES] : ROUTES).filter((r) => allowed.includes(r.id)).map((r) => (
              <button class="option" onClick={() => { S.joinMethod.value = r.id; S.joinStep.value = 2; setPrelude(true); }}>
                <span class="lead"><Icon name={r.icon} /></span>
                <span><span class="title">{r.title}</span><span class="sub" style={{ display: "block" }}>{r.desc}</span></span>
                <Icon name="chevron" />
              </button>
            ))}
          </div>
          {!old && !holderOnly && <button class="link" style={{ marginTop: 14 }} onClick={() => setOld(true)}>I have an older recovery card or witnesses</button>}
          {!holderOnly
            ? <button class="link muted" style={{ marginTop: 6 }} onClick={() => setJoinMode(HOLDER_ONLY)}>I chose Only my own devices</button>
            : <p class="fine" style={{ marginTop: 14 }}>Lost every device? Then no one can bring this HumID back: that's what Only my own devices means. You can create a new HumID instead.</p>}
          {holderOnly && <button class="link muted" style={{ marginTop: 6 }} onClick={() => setJoinMode(null)}>I'm not sure: show every way in</button>}
        </>
      )}
      {step === 2 && method === "link" && (
        <JoinDetails eyebrow={n(2)} title="Approve from your other device" lede="First, lock this device to you with one live check. Then it shows a code and a QR code. On your other device: You → Devices → Add a device."
          bindLabel="Continue" onBind={(demo, sole) => beginJoin("link", { useDemo: demo, soleBiometric: sole })} />
      )}
      {step === 2 && method === "quorum" && (prelude ? <Prelude eyebrow={n(2)} onNext={() => setPrelude(false)} /> : <QuorumEntry eyebrow={n(2)} />)}
      {step === 2 && method === "card" && <CardEntry eyebrow={n(2)} />}
      {step === 2 && method === "contacts" && (
        <JoinDetails eyebrow={n(2)} title="Ask your witnesses" lede="Lock this device to you with one live check, then send the code it shows to your witnesses. When enough of them approve, your vault opens here after 72 hours, unless you cancel from a device you still have."
          bindLabel="Continue" onBind={(demo, sole) => beginJoin("contacts", { useDemo: demo, soleBiometric: sole })} />
      )}
      {step === 3 && <JoinWait eyebrow={n(3)} />}
    </main>
  );
}

const PRELUDE_SUB = {
  witness: "A majority of the people you chose approve from their own HumID.",
  anchor: "Your passport or ID card's chip, read by this phone or at a HumID station.",
  card: "The code you wrote down when you created your HumID.",
  key: "A security key you added, with its PIN, held to this phone.",
};

/** Before anything is bound: what two-proof recovery needs, and how long each pair waits. */
function Prelude({ eyebrow, onNext }) {
  return (
    <>
      <div class="eyebrow">{eyebrow} · What you'll need</div>
      <h1 style={{ marginTop: 8 }}>Any two of these four</h1>
      <p class="lede" style={{ marginTop: 10 }}>Recovery proves it's you with two different things. Then it waits, while every device that still has your HumID can veto.</p>
      <div class="rows" style={{ marginTop: 18 }}>
        {PROOFS.map((p) => <Row icon={p.icon} tone="mint" chevron={false} title={p.title} sub={PRELUDE_SUB[p.id]} />)}
      </div>
      <div class="section">
        <div class="eyebrow">How long the wait is</div>
        <div class="rows">{WAITS.map((w) => <Row chevron={false} title={w.wait} sub={w.pair} />)}</div>
      </div>
      <div class="foot">
        <button class="btn primary block" onClick={onNext}>I have two of these</button>
        <p class="fine center">Lost everything? A witness and a HumID station can still bring it back.</p>
      </div>
    </>
  );
}

function JoinDetails({ eyebrow, title, lede, bindLabel, onBind, disabled, children }) {
  const [sole, setSole] = useState(false);
  return (
    <>
      <div class="eyebrow">{eyebrow} · Lock this device to you</div>
      <h1 style={{ marginTop: 8 }}>{title}</h1>
      <p class="lede" style={{ marginTop: 10 }}>{lede}</p>
      {children}
      <div class="foot">
        <SoleBiometric checked={sole} onChange={setSole} id="sole-join" />
        {disabled ? <button class="btn primary lg block" disabled>{bindLabel}</button> : <BindButtons onBind={(demo) => onBind(demo, sole)} label={bindLabel} sole={sole} soleId="sole-join" />}
      </div>
    </>
  );
}

function cardState(text) {
  try { if (text.replace(/[^0-9a-z]/gi, "").length >= 30) { parseCard(text); return "ok"; } } catch (e) { return e.message; }
  return null;
}

function QuorumEntry({ eyebrow }) {
  const [text, setText] = useState("");
  const state = cardState(text);
  return (
    <JoinDetails eyebrow={eyebrow} title="Prove it's you" lede="One live check locks this device to you first. Then you show your proofs, one at a time."
      bindLabel="Continue" disabled={!!text.trim() && state !== "ok"} onBind={(demo, sole) => beginJoin("quorum", { useDemo: demo, cardInput: state === "ok" ? text : "", soleBiometric: sole })}>
      <div class="field" style={{ marginTop: 16 }}>
        <label for="qcard">Recovery card (if you have it handy)</label>
        <input autocorrect="off" id="qcard" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          value={text} onInput={(e) => setText(e.currentTarget.value)} />
        {state === "ok" && <span class="hint mint">Card code looks right</span>}
        {state && state !== "ok" && <span class="hint amber">{state}</span>}
        {!text && <span class="hint">You can also add it later.</span>}
      </div>
    </JoinDetails>
  );
}

function CardEntry({ eyebrow }) {
  const [text, setText] = useState("");
  const state = cardState(text);
  return (
    <JoinDetails eyebrow={eyebrow} title="Use your recovery card" lede="Type the code from your card, then one live check locks this device to you. Your vault opens here after 72 hours, and every device you still have is alerted and can cancel."
      bindLabel="Continue" disabled={state !== "ok"} onBind={(demo, sole) => beginJoin("card", { useDemo: demo, cardInput: text, soleBiometric: sole })}>
      <div class="field" style={{ marginTop: 16 }}>
        <label for="card">Recovery card</label>
        <input autocorrect="off" id="card" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          value={text} onInput={(e) => setText(e.currentTarget.value)} />
        {state === "ok" && <span class="hint mint">Card code looks right</span>}
        {state && state !== "ok" && <span class="hint amber">{state}</span>}
      </div>
    </JoinDetails>
  );
}

function JoinWait({ eyebrow }) {
  const id = S.identity.value;
  const p = id?.pending;
  const st = S.joinStatus.value;
  const now = useNow();
  if (!p) return null;
  const ended = st && ["expired", "cancelled"].includes(st.status);
  const releaseAt = st?.releaseAt || p.releaseAt;
  const expired = p.method === "link" && (st?.status === "expired" || p.expiresAt - now <= 0);
  return (
    <>
      <div class="eyebrow">{eyebrow} · {p.method === "link" ? "Approve on your other device" : "Waiting for your vault"}</div>
      {p.method === "link" && (st?.check ? (
        <>
          <h1 style={{ marginTop: 8 }}>Does your other device show this?</h1>
          <p class="lede" style={{ marginTop: 10 }}>Your other device approved. Before this one joins, make sure it's your account: your other device shows a match code after approving.</p>
          <CodeBox code={st.check} label="Match code" />
          <div class="actions">
            <button class="btn primary block" onClick={confirmJoin}><Icon name="fingerprint" />It matches: finish</button>
            <button class="btn ghost block" onClick={rejectJoin}>It doesn't match</button>
          </div>
        </>
      ) : (
        <>
          <h1 style={{ marginTop: 8 }}>Enter this code on your other device</h1>
          <p class="lede" style={{ marginTop: 10 }}>On the device that has your HumID: <b>You → Devices → Add a device</b>. It checks that this code matches this device's keys, then runs one live check.</p>
          <CodeBox code={p.code} label="Device code" />
          <QrCode kind="link" code={p.code} expiresAt={p.expiresAt} />
          {!expired && <p class="fine center">Scan it from your other device, or type it. Expires in {fmtLeft(p.expiresAt - now)}</p>}
        </>
      ))}
      {p.method === "card" && (
        <>
          <h1 style={{ marginTop: 8 }}>Your vault opens here in {fmtLeft((releaseAt || 0) - now)}</h1>
          <p class="lede" style={{ marginTop: 10 }}>Every device that still has your HumID was alerted and can cancel. This wait is what stops someone who found your card. You can close the app; it picks up where it left off.</p>
          <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0" }}><Mark state="scanning" size={120} /></div>
        </>
      )}
      {p.method === "quorum" && <QuorumWait p={p} st={st} now={now} />}
      {p.method === "contacts" && (
        <>
          <h1 style={{ marginTop: 8 }}>{releaseAt ? `Your vault opens here in ${fmtLeft(releaseAt - now)}` : "Send this code to your witnesses"}</h1>
          <p class="lede" style={{ marginTop: 10 }}>{releaseAt
            ? "Enough witnesses approved. Every device that still has your HumID was alerted and can cancel during the wait."
            : <>Ask each witness to open HumID → <b>You → Help others → Help recover</b> and enter this code. Call them, so they know it's really you.</>}</p>
          {!releaseAt && <CodeBox code={p.code} label="Recovery code" />}
          <div class="rows" style={{ marginTop: 14 }}><Row chevron={false} title="Witnesses who helped" trail={`${st?.approvals ?? 0}${st?.threshold ? ` of ${st.threshold} needed` : ""}`} /></div>
        </>
      )}
      <div style={{ marginTop: 16 }}>
        {expired && p.method === "link" && <Banner tone="amber" icon="clock" title="That code expired" text="Get a fresh one: this phone stays locked to you, no need to start over." action="New code" onAction={renewLink} />}
        {st?.status === "expired" && p.method !== "link" && <Banner tone="amber" icon="clock" title="This expired" text="Start again to get a fresh code." />}
        {st?.status === "cancelled" && (st.reason === "holder_only"
          ? <Banner tone="amber" icon="key" title="This HumID opens only on its own devices" text="Its holder chose that, so no recovery can finish. Add this device from one of theirs instead." />
          : <Banner tone="danger" icon="alert" title="Cancelled from one of your devices" text={st.reason === "card_replaced" ? "The recovery card was replaced." : "If that wasn't you, someone else has your HumID unlocked."} />)}
        {st?.status === "error" && <Banner tone="danger" icon="alert" title="Couldn't finish" text={st.message} />}
      </div>
      <div class="foot">
        {st?.status === "error" && <button class="btn primary block" onClick={pollJoin}>Try again</button>}
        {ended && !expired && <button class="btn primary block" onClick={cancelJoin}>Start again</button>}
        {!(ended && !expired) && <button class="link muted" onClick={cancelJoin}>Cancel and start over</button>}
        <p class="fine">This device is locked to {id.method === "demo-no-hardware" ? "demo mode" : "you"} · {serverHost(id.server?.url)}</p>
      </div>
    </>
  );
}

/** Two-proof recovery while collecting: one proof open at a time; the code to show in a panel. */
function QuorumWait({ p, st, now }) {
  const kinds = [...new Set([...(st?.kinds || []), ...(p.hasCard ? ["card"] : [])])];
  const releaseAt = st?.releaseAt;
  const [open, setOpen] = useState(null); // which proof is expanded
  const [showCode, setShowCode] = useState(false);
  const [card, setCard] = useState("");
  const [name, setName] = useState("Demo Person");
  const [busy, setBusy] = useState(false);
  const [access, setAccess] = useState(null);
  const [pin, setPin] = useState("");
  const [pinProblem, setPinProblem] = useState(null);
  const ended = st && ["expired", "cancelled"].includes(st.status);
  const tier = tierText(kinds, st?.anchorMode);
  const cardOk = (() => { try { parseCard(card); return true; } catch { return false; } })();
  const nfc = S.nfc.value;
  const run = async (fn) => { setBusy(true); try { await fn(); } finally { setBusy(false); } };
  const has = (k) => kinds.includes(k);
  // The key counts only when this device also kept its secret (the server may have counted it
  // before the app was closed).
  const keyHere = has("key") && !!p.hasKey;
  return (
    <>
      <h1 style={{ marginTop: 8 }}>{releaseAt ? `Your vault opens here in ${fmtLeft(releaseAt - now)}` : kinds.length ? "One proof in. Add a second" : "Show your proofs"}</h1>
      <p class="lede" style={{ marginTop: 10 }}>{releaseAt
        ? <>Two proofs matched ({st.evidence}). Every device that still has your HumID was alerted and can veto. {st.duress && <b>The wait is doubled because of a recent duress signal.</b>}</>
        : "Any two different proofs. Open one below to add it."}</p>
      <div style={{ marginTop: 12 }}><ProofMeter have={kinds} /></div>
      {tier && <p class="small t2" style={{ marginTop: 8 }}><Icon name="clock" /> Wait with these proofs: {tier}</p>}
      {releaseAt && has("key") && !p.hasKey && !ended && <div style={{ marginTop: 12 }}><Banner tone="amber" icon="seckey" title="One more tap with your security key" text="Your vault counted your key, but this phone didn't keep its secret (the app closed in between). Hold the key here again, or this phone can't open your vault when the wait ends." /></div>}
      {(!releaseAt || (has("key") && !p.hasKey)) && !ended && (
        <div class="stack" style={{ marginTop: 14 }}>
          <div class="rows">
            <Row icon="users" tone={has("witness") ? "mint" : ""} title="Witnesses" sub={has("witness") ? "Approved" : st?.threshold ? `${st.approvals ?? 0} of ${st.threshold} have approved` : "A majority of your witnesses approve"} trail={has("witness") && <Icon name="check" />} onClick={() => setOpen(open === "witness" ? null : "witness")} />
            {open === "witness" && !has("witness") && (
              <div style={{ padding: "0 16px 16px" }} class="stack">
                <p class="small t2">Each witness opens HumID → <b>You → Help others → Help recover</b> and enters your recovery code. Call them, so they know it's you.</p>
                <CodeBox code={p.code} label="Recovery code" />
              </div>
            )}
            <Row icon="idcard" tone={has("card") ? "mint" : ""} title="Recovery card" sub={has("card") ? "Added" : "Type the code you wrote down"} trail={has("card") && <Icon name="check" />} onClick={() => setOpen(open === "card" ? null : "card")} />
            {open === "card" && !has("card") && (
              <div style={{ padding: "0 16px 16px" }} class="stack">
                <input autocorrect="off" aria-label="Recovery card" class="input code" autocomplete="off" autocapitalize="characters" spellcheck={false} placeholder="HUMID-XXXXX-…" value={card} onInput={(e) => setCard(e.currentTarget.value)} />
                <button class="btn primary" disabled={!cardOk || busy} onClick={() => run(async () => { if (await addCardToJoin(card)) setCard(""); })}><Icon name="fingerprint" />Add recovery card</button>
              </div>
            )}
            <Row icon="passport" tone={has("anchor") ? "mint" : ""} title="ID chip" sub={has("anchor") ? (st?.anchorMode === "station" ? "Verified in person at a station" : "Verified live") : nfc?.available ? "Read your passport or ID card's chip" : "Show your code at a HumID station"} trail={has("anchor") && <Icon name="check" />} onClick={() => setOpen(open === "anchor" ? null : "anchor")} />
            {open === "anchor" && !has("anchor") && (
              <div style={{ padding: "0 16px 16px" }} class="stack">
                {nfc?.available ? (
                  <>
                    <ChipAccess onChange={setAccess} />
                    <button class="btn primary" disabled={busy || !access} onClick={() => run(() => addChipToJoin(nfcChipSource(access)))}><Icon name="passport" />{nfc.kind === "reader" ? "Read with the card reader" : "Hold to my phone and read"}</button>
                  </>
                ) : <p class="small t2">At a HumID station: show the operator your recovery code and your passport or ID.</p>}
                {DEMO_BUILD && (
                  <div class="row-x">
                    <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Demo passport holder" class="input grow" value={name} onInput={(e) => setName(e.currentTarget.value)} />
                    <button class="btn quiet" disabled={busy} onClick={() => run(() => addChipToJoin(demoChipSource(name)))}>Demo passport</button>
                  </div>
                )}
              </div>
            )}
            <Row icon="seckey" tone={keyHere ? "mint" : ""} title="Security key" sub={keyHere ? "Verified: your key answered with its PIN" : has("key") ? "Hold your key to this phone once more to finish" : "Type its PIN, then hold it to this phone"} trail={keyHere && <Icon name="check" />} onClick={() => setOpen(open === "key" ? null : "key")} />
            {open === "key" && !keyHere && (
              <div style={{ padding: "0 16px 16px" }} class="stack">
                {nfc?.available ? (
                  <>
                    <div class="field" style={{ marginTop: 0 }}>
                      <label for="join-key-pin">Your security key's PIN</label>
                      <input id="join-key-pin" class="input code" type="password" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={63} value={pin} onInput={(e) => { setPin(e.currentTarget.value); setPinProblem(null); }} aria-describedby="join-key-hint" />
                      {pinProblem ? <span id="join-key-hint" class="hint danger" role="alert">{pinProblem.message}</span> : <span id="join-key-hint" class="hint">Only the key checks it. Eight wrong tries lock the key for good.</span>}
                    </div>
                    <button class="btn primary" disabled={busy} onClick={() => run(async () => {
                      if ([...pin].length < 4) { setPinProblem({ code: "missing", message: "Type your key's PIN first." }); document.getElementById("join-key-pin")?.focus(); return; }
                      const r = await addKeyToJoin(pin);
                      if (r === true || r === false) setPin("");
                      else if (r?.pinError) { setPinProblem(r.pinError); if (r.pinError.code === "pin_invalid") setPin(""); }
                    })}><Icon name="fingerprint" />Hold the key to {nfc.kind === "reader" ? "the reader" : "the phone"}, then confirm</button>
                  </>
                ) : <p class="small t2">{nfc?.reason || "This device can't reach a security key. Use the HumID app on a phone with NFC."}</p>}
              </div>
            )}
          </div>
          <button class="link" onClick={() => setShowCode(!showCode)}>{showCode ? "Hide the code" : "Show my recovery code to a witness or station"}</button>
          {showCode && <div class="stack"><CodeBox code={p.code} label="Recovery code" /><QrCode kind="recover" code={p.code} expiresAt={p.expiresAt} /></div>}
        </div>
      )}
      {releaseAt && <div class="hero" style={{ flex: "0 0 auto", margin: "18px 0" }}><Mark state="scanning" size={120} /></div>}
    </>
  );
}

/** The match code didn't match: a dedicated stop, not a bounce back to the same server. */
function Mismatch() {
  return (
    <main class="screen">
      <div class="hero" style={{ flex: "0 0 auto", marginTop: "8vh" }}><Mark state="failed" size={140} /></div>
      <h1 class="center" style={{ marginTop: 18 }}>Something is wrong</h1>
      <p class="lede center" style={{ margin: "10px auto 0" }}>The account offered to this device wasn't yours. Nothing was added, and nothing is unlocked.</p>
      <div style={{ marginTop: 18 }}>
        <Banner tone="danger" icon="alert" title="Don't try again on this server yet" text="Either a device was added to the wrong HumID, or the server handed you someone else's account. Tell whoever runs it what you saw." />
      </div>
      <div class="foot">
        <button class="btn quiet block" onClick={() => { S.joinStep.value = 1; S.joinStatus.value = null; }}>Back to the start</button>
      </div>
    </main>
  );
}
