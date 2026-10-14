// Payment cards: add one (camera, tap, or type), and the card view inside the
// viewer. The rules live in @humid/cards (never a PIN or the back of the card,
// the security code only on opt-in); this file is the screens around them.
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { Sheet, Steps } from "../ui.jsx";
import * as S from "../core/state.js";
import { addCardRecord, readCardTap, readCardPhoto, copySecret, chipReader } from "../core/controller.js";
import { jpeg, imageUrl, releaseReaders } from "../core/scan.js";
import { PLATFORM } from "../core/config.js";
import { DocCamera } from "./ids.jsx";
import {
  newCard, applyRead, applyTyped, setStoreCvv, setImage, view, title as cardTitle, copyValue, checkPan, brandOf, formatPan, showExpiry, HANDLING,
} from "@humid/cards";

const IOS = PLATFORM.startsWith("iOS");

export function CardSheet() {
  const st = S.sheet.value;
  const rec = useRef(newCard());
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [step, setStep] = useState("how"); // how | review
  const [cam, setCam] = useState(false);
  const [note, setNote] = useState(null);
  const [nfc, setNfc] = useState(null);
  const [tapping, setTapping] = useState(false);
  const busy = st.stage != null;

  useEffect(() => { if (!IOS) chipReader().then(setNfc).catch(() => setNfc({ available: false })); return () => { releaseReaders(); }; }, []);
  const close = () => { if (!busy) S.sheet.value = null; };

  async function photographed({ canvas }) {
    setCam(false);
    setImage(rec.current, "front", await jpeg(canvas, { maxW: 1200 }));
    setNote({ tone: "ok", text: "Reading the card…" });
    setStep("review");
    redraw();
    const r = await readCardPhoto(canvas);
    if (r?.pan) {
      try { applyRead(rec.current, r, "camera"); setNote({ tone: "ok", text: `Read ${brandOf(r.pan).name} ending ${r.pan.slice(-4)}. Check the details.` }); }
      catch { setNote({ tone: "warn", text: "Couldn't read the number clearly. Type it below." }); }
    } else setNote({ tone: "warn", text: "Couldn't read the number from the photo. Type it below." });
    redraw();
  }

  async function tap() {
    setTapping(true);
    const r = await readCardTap();
    setTapping(false);
    if (!r) return;
    try {
      applyRead(rec.current, r, "nfc");
      setNote({ tone: "ok", text: `Read ${r.network || brandOf(r.pan).name} ending ${r.pan.slice(-4)} from the chip. No payment was made.` });
      setStep("review");
      redraw();
    } catch (e) { setNote({ tone: "warn", text: e.message }); }
  }

  const head = (
    <div class="s-head"><div class="grow"><div class="eyebrow">New card</div>
      <h2 style={{ marginTop: 4 }}>{step === "how" ? "Add a payment card" : "Check the details"}</h2></div>
      {!busy && <button class="icon-btn" aria-label="Close" onClick={close}><Icon name="x" /></button>}</div>
  );

  return (
    <>
      <Sheet onClose={close} label="Add a card">
        {head}
        {step === "how" && (
          <>
            <p class="lede">Credit and debit cards, sealed on this phone. Only your face or fingerprint shows the full number.</p>
            <div class="kinds">
              <button class="kind" onClick={() => setCam(true)}><span class="ico"><Icon name="camera" /></span><span><strong>Scan the front</strong><span>Reads the number, expiry and name</span></span><Icon name="chevron" /></button>
              {!IOS && nfc?.available && (
                <button class="kind" disabled={tapping} onClick={tap}><span class="ico"><Icon name="nfc" /></span>
                  <span><strong>{tapping ? "Hold the card still…" : "Tap the card"}</strong><span>{nfc.kind === "reader" ? "Place it on the card reader. A read, not a payment." : "Hold it to the back of your phone. A read, not a payment."}</span></span><Icon name="chevron" /></button>
              )}
              <button class="kind" onClick={() => setStep("review")}><span class="ico"><Icon name="pencil" /></span><span><strong>Type it</strong><span>Number, expiry and name</span></span><Icon name="chevron" /></button>
            </div>
            {note && <CardNote {...note} />}
            <p class="fine" style={{ marginTop: 14 }}>HumID never stores a card's PIN or a photo of its back, and keeps the security code only if you turn that on.</p>
          </>
        )}
        {step === "review" && (busy
          ? <Steps current={{ seal: 0, upload: 1, done: 2 }[st.stage]} steps={["Sealing on this device", "Sending over HTP/1", "Stored · signature verified by the vault"]} />
          : <CardForm rec={rec.current} note={note} onRetake={() => setCam(true)} onChange={redraw} />)}
      </Sheet>
      {cam && <DocCamera shape="id1" eyebrow="Card" title="The front of the card" hint="Fit the card in the frame, number side up." onCancel={() => setCam(false)} onDone={photographed} />}
    </>
  );
}

function CardNote({ tone, text }) {
  return <div class={`banner ${tone === "warn" ? "warn" : ""}`} style={{ marginTop: 10 }}><span class="b-ico"><Icon name={tone === "warn" ? "info" : "check"} /></span><div><span>{text}</span></div></div>;
}

function CardForm({ rec, note, onRetake, onChange }) {
  const f = rec.fields;
  const [v, setV] = useState({ pan: f.pan ? formatPan(f.pan) : "", expiry: showExpiry(f.expiry), name: f.name || "", nickname: "", bank: "", phone: "", notes: "", cvv: "" });
  const [keepCvv, setKeepCvv] = useState(false);
  const [err, setErr] = useState(null);
  const [name, setName] = useState("");
  useEffect(() => { setV((x) => ({ ...x, pan: rec.fields.pan ? formatPan(rec.fields.pan) : x.pan, expiry: showExpiry(rec.fields.expiry) || x.expiry, name: rec.fields.name || x.name })); }, [rec.fields.pan, rec.fields.expiry, rec.fields.name]);
  const set = (k) => (e) => { setErr(null); setV({ ...v, [k]: e.currentTarget.value }); };
  const c = v.pan ? checkPan(v.pan) : null;
  const brand = c ? brandOf(c.pan) : null;
  const panHint = !c ? null : c.ok ? brand.name : c.problems.includes("luhn") && c.pan.length >= brand.lengths[0] ? "That number has a typo" : null;

  const save = async () => {
    try {
      setStoreCvv(rec, keepCvv);
      const typed = Object.fromEntries(Object.entries(v).filter(([k]) => k !== "cvv" || keepCvv).map(([k, x]) => [k, String(x).trim()]));
      applyTyped(rec, typed);
      onChange();
      await addCardRecord(rec, name.trim() || cardTitle(rec));
    } catch (e) { setErr(e.message); }
  };

  return (
    <>
      {note && <CardNote {...note} />}
      {rec.images.front && (
        <div class="id-thumbs"><figure data-shape="id1"><img src={imageUrl(rec.images.front)} alt="Front of the card" /><figcaption>Front<button class="linklike" onClick={onRetake}>Retake</button></figcaption></figure></div>
      )}
      <div class="id-form">
        <div class="field id-field">
          <label for="cf-pan">Card number{panHint && <span class={`src ${c?.ok ? "src-typed" : ""}`}>{panHint}</span>}</label>
          <input id="cf-pan" class="mono" inputMode="numeric" autocomplete="off" spellcheck={false} maxLength={23} value={v.pan} onInput={set("pan")} placeholder="1234 5678 9012 3456" />
        </div>
        <div class="split">
          <div class="field id-field"><label for="cf-exp">Expires</label><input id="cf-exp" class="mono" inputMode="numeric" placeholder="MM/YY" maxLength={7} autocomplete="off" value={v.expiry} onInput={set("expiry")} /></div>
          <div class="field id-field"><label for="cf-nick">Nickname</label><input id="cf-nick" placeholder="Travel card" maxLength={40} autocomplete="off" value={v.nickname} onInput={set("nickname")} /></div>
        </div>
        <div class="field id-field"><label for="cf-name">Name on card</label><input id="cf-name" class="up" autocomplete="off" maxLength={40} value={v.name} onInput={set("name")} /></div>
        <div class="split">
          <div class="field id-field"><label for="cf-bank">Bank</label><input id="cf-bank" autocomplete="off" maxLength={60} value={v.bank} onInput={set("bank")} /></div>
          <div class="field id-field"><label for="cf-phone">Bank phone</label><input id="cf-phone" type="tel" autocomplete="off" maxLength={30} value={v.phone} onInput={set("phone")} /></div>
        </div>
        <label class="toggle" style={{ marginTop: 12 }}>
          <span><strong>Keep the security code</strong><span>Off by default. It's what makes a stolen number usable online.</span></span>
          <input type="checkbox" role="switch" checked={keepCvv} onChange={(e) => setKeepCvv(e.currentTarget.checked)} />
          <i aria-hidden="true" />
        </label>
        {keepCvv && <div class="field id-field"><label for="cf-cvv">Security code</label><input id="cf-cvv" class="mono" type="password" inputMode="numeric" autocomplete="off" maxLength={4} value={v.cvv} onInput={set("cvv")} /></div>}
        <div class="field id-field"><label for="cf-notes">Notes</label><input id="cf-notes" autocomplete="off" maxLength={200} value={v.notes} onInput={set("notes")} /></div>
      </div>
      <div class="field">
        <label for="cf-vname">Name in your vault</label>
        <input id="cf-vname" value={name} placeholder={v.nickname || (c?.ok ? `${brand.name} •••• ${c.pan.slice(-4)}` : "Card")} maxLength={120} onInput={(e) => setName(e.currentTarget.value)} autocomplete="off" />
      </div>
      {err && <p class="small" style={{ color: "var(--amber-hi)", marginTop: 10 }}>{err}</p>}
      <div class="actions">
        <button class="btn primary block" disabled={!c?.ok} onClick={save}><Icon name="fingerprint" />Seal &amp; store</button>
      </div>
      <p class="fine" style={{ marginTop: 12 }}>Sealed on this phone (ML-KEM-1024 + X25519, signed with ML-DSA-87). Your vault list shows only the network, last four digits and expiry.</p>
    </>
  );
}

/* ---------------- the card, opened ---------------- */

export function CardView({ record }) {
  const [revealed, setRevealed] = useState(false);
  const [left, setLeft] = useState(0);
  useEffect(() => {
    if (!revealed) return undefined;
    const end = Date.now() + HANDLING.revealMs;
    setLeft(Math.ceil(HANDLING.revealMs / 1000));
    const t = setInterval(() => { const s = Math.ceil((end - Date.now()) / 1000); if (s <= 0) { setRevealed(false); clearInterval(t); } else setLeft(s); }, 250);
    const hide = () => { if (document.hidden) setRevealed(false); };
    document.addEventListener("visibilitychange", hide);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", hide); };
  }, [revealed]);
  const c = view(record, { revealed });
  return (
    <div class="card-view">
      <div class={`pay-card brand-${c.brand}`} aria-label={`${c.brandName} card`}>
        <div class="pc-top"><span class="pc-brand">{c.brandName}</span>{c.status.state !== "valid" && c.status.state !== "unknown" && <span class="pc-flag">{c.status.state === "expired" ? "Expired" : "Expires soon"}</span>}</div>
        <div class="pc-number mono">{c.number}</div>
        <div class="pc-bottom"><span>{c.name || " "}</span><span class="mono">{c.expiry}</span></div>
      </div>
      <div class="actions">
        <button class="btn secure block" onClick={() => setRevealed(!revealed)}><Icon name={revealed ? "lock" : "eye"} />{revealed ? `Hide now (hides in ${left}s)` : "Show the number"}</button>
        <div class="split">
          <button class="btn quiet" onClick={() => copySecret(copyValue(record, "pan"), "Number copied")}><Icon name="copy" />Copy number</button>
          <button class="btn quiet" onClick={() => copySecret(copyValue(record, "expiry"), "Expiry copied")}><Icon name="copy" />Copy expiry</button>
        </div>
        {c.cvv && <button class="btn quiet block" onClick={() => copySecret(copyValue(record, "cvv"), "Security code copied")}><Icon name="copy" />Copy security code {revealed ? `(${c.cvv})` : ""}</button>}
      </div>
      {(c.bank || c.phone || c.notes) && (
        <div class="card" style={{ marginTop: 14 }}>
          {c.bank && <div class="row"><span class="k">Bank</span><span class="v">{c.bank}</span></div>}
          {c.phone && <div class="row"><span class="k">Bank phone</span><span class="v"><a href={`tel:${c.phone.replace(/[^\d+]/g, "")}`}>{c.phone}</a></span></div>}
          {c.notes && <div class="row"><span class="k">Notes</span><span class="v">{c.notes}</span></div>}
        </div>
      )}
      <p class="fine" style={{ marginTop: 12 }}>The number hides again after {Math.round(HANDLING.revealMs / 1000)} seconds or when you leave the app; copies clear from the clipboard after {Math.round(HANDLING.clipboardClearMs / 1000)} seconds.</p>
    </div>
  );
}
