// Payment cards: add one (camera, tap, or type) as a step inside the Add flow, and the
// card view inside the viewer. The rules live in @humid/cards (never a PIN, chip or
// stripe data, or a photo of the back; the security code only when the holder keeps it).
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Toggle, Row } from "../../ui/kit.jsx";
import { openExternal } from "../../core/external.js";
import * as S from "../../core/state.js";
import { addCardRecord, readCardTap, readCardPhoto, chipReader, setPref, toast } from "../../core/index.js";
import { jpeg, imageUrl, releaseReaders, rotateCanvas, warmScan } from "../../core/scan.js";
import { PLATFORM } from "../../core/config.js";
import { DocCamera, turnedImage } from "./camera.jsx";
import { Review, Step, Note } from "./review.jsx";
import {
  newCard, applyRead, applyTyped, setStoreCvv, setImage, view, title as cardTitle, checkPan, brandOf, formatPan, showExpiry, HANDLING,
} from "@humid/cards";

const IOS = PLATFORM.startsWith("iOS");

/** Can this device tap a card? Resolves { available, kind } (iPhones can't read payment cards). */
export const cardTapReader = () => (IOS ? Promise.resolve({ available: false, kind: "none" }) : chipReader().catch(() => ({ available: false })));

/** The front, read either way up: as straightened, and if that finds nothing, turned round. */
export async function readFrontEitherWay(shot, pan = null) {
  let r = await readCardPhoto(shot, { side: "front", pan });
  if (r?.pan) return { r, canvas: shot };
  const turned = rotateCanvas(shot, 180);
  const r2 = await readCardPhoto(turned, { side: "front", pan });
  return r2?.pan ? { r: r2, canvas: turned } : { r, canvas: shot };
}

const readNote = (r) => {
  const amex = brandOf(r.pan).id === "amex";
  return { tone: "ok", text: `Read ${brandOf(r.pan).name} ending ${r.pan.slice(-4)}${r.expiry ? ", its expiry" : ""}${r.name ? " and the name" : ""}. Review them.${amex ? r.cvv ? " The 4-digit security code is on the front: switch on Keep the security code below to keep it." : "" : " Then scan the back for the security code."}` };
};

/**
 * The payment-card step.
 *   start    { front: { canvas, read } } — the front the camera photographed and read;
 *            { tap: true } — go straight to a tap; {} — the typed form;
 *            { rec, form, name, tags } — a draft kept across a lock
 *   onExit   Back from the form
 *   onDraft  ({ rec, form, name, tags }) whenever something worth keeping changes
 */
export function CardFlow({ start, onExit, onDraft }) {
  const rec = useRef(start.rec || newCard());
  const pendingCvv = useRef(null);
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [cam, setCam] = useState(null);
  const [note, setNote] = useState(null);
  const [tapping, setTapping] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    warmScan("card");
    if (start.front) applyFront(start.front.read, start.front.canvas);
    else if (start.tap) tap();
    return () => { releaseReaders(); };
  }, []);

  async function applyFront(r, canvas) {
    const img = await jpeg(canvas, { maxW: 1200 });
    setImage(rec.current, "front", img);
    if (r?.pan) {
      try {
        applyRead(rec.current, { ...r, cvv: null }, "camera");
        pendingCvv.current = r.cvv || null;
        setNote(readNote(r));
      } catch { setNote({ tone: "warn", text: "Couldn't read the number clearly. Type it below." }); }
    } else setNote({ tone: "warn", text: "Couldn't read the number from the photo. Type it below, or try again in better light." });
    redraw();
  }

  async function front({ canvas: shot }) {
    const { r, canvas } = await readFrontEitherWay(shot, rec.current.fields.pan);
    const img = await jpeg(canvas, { maxW: 1200 });
    return () => {
      setCam(null);
      setImage(rec.current, "front", img);
      if (r?.pan) {
        try {
          applyRead(rec.current, { ...r, cvv: null }, "camera");
          pendingCvv.current = r.cvv || null;
          setNote(readNote(r));
        } catch { setNote({ tone: "warn", text: "Couldn't read the number clearly. Type it below." }); }
      } else setNote({ tone: "warn", text: "Couldn't read the number from the photo. Type it below, or try again in better light." });
      redraw();
    };
  }

  // The back: read the security code and the bank's phone number. The photo isn't kept.
  async function back({ canvas }) {
    const found = (x) => !!(x?.cvv || x?.phone);
    let r = await readCardPhoto(canvas, { side: "back", pan: rec.current.fields.pan });
    if (!found(r)) { const r2 = await readCardPhoto(rotateCanvas(canvas, 180), { side: "back", pan: rec.current.fields.pan }); if (found(r2)) r = r2; }
    return () => {
      setCam(null);
      if (r?.cvv) setStoreCvv(rec.current, true);
      applyRead(rec.current, { cvv: r?.cvv, phone: r?.phone }, "camera");
      const got = [r?.cvv && "the security code", r?.phone && "the bank's phone number"].filter(Boolean);
      setNote(got.length
        ? { tone: "ok", text: `Read ${got.join(" and ")} from the back. The photo of the back wasn't kept.${r?.cvv ? " The code will be kept; switch off Keep the security code to drop it." : ""}` }
        : { tone: "warn", text: "Couldn't read the back clearly. Type the security code below if you want to keep it." });
      redraw();
    };
  }

  async function tap() {
    setTapping(true);
    const r = await readCardTap();
    setTapping(false);
    if (!r) { setNote({ tone: "warn", text: "No card read. Type it below, or scan it." }); redraw(); return; }
    try {
      applyRead(rec.current, r, "nfc");
      setNote({ tone: "ok", text: `Read ${r.network || brandOf(r.pan).name} ending ${r.pan.slice(-4)} from the chip. No payment was made. The chip doesn't hold the security code: scan the back or type it.` });
      redraw();
    } catch (e) { setNote({ tone: "warn", text: e.message }); redraw(); }
  }

  return (
    <>
      <Step eyebrow="Payment card" title={tapping ? "Hold the card still…" : "Review, then seal"} onBack={onExit}>
        <CardForm rec={rec.current} note={note} pending={pendingCvv} resume={start.rec ? start : null} onRetake={() => setCam("front")} onBack={() => setCam("back")} onChange={redraw} onDraft={onDraft} />
      </Step>
      {cam === "front" && <DocCamera kind="card" side="front" shape="id1" eyebrow="Card · front" title="The front of the card" hint="Line the card up inside the outline, number side up." onCancel={() => setCam(null)} onDone={front} />}
      {cam === "back" && <DocCamera kind="card" side="back" shape="id1" eyebrow="Card · back" title="The back of the card" hint="The side with the signature strip, lined up inside the outline. The photo isn't kept." onCancel={() => setCam(null)} onDone={back} />}
    </>
  );
}

function CardForm({ rec, note, pending, resume, onRetake, onBack, onChange, onDraft }) {
  const f = rec.fields;
  const [v, setV] = useState(() => resume?.form || { pan: f.pan ? formatPan(f.pan) : "", expiry: showExpiry(f.expiry), name: f.name || "", nickname: "", bank: "", phone: f.phone || "", notes: "", cvv: f.cvv || "" });
  const [keepCvv, setKeepCvv] = useState(!!rec.policy.storeCvv);
  const [err, setErr] = useState(null);
  const [name, setName] = useState(resume?.name || "");
  const [tags, setTags] = useState(resume?.tags || ["money"]);
  useEffect(() => {
    setV((x) => ({
      ...x, pan: f.pan ? formatPan(f.pan) : x.pan, expiry: showExpiry(f.expiry) || x.expiry, name: f.name || x.name,
      phone: f.phone || x.phone, cvv: f.cvv || x.cvv,
    }));
    if (rec.policy.storeCvv) setKeepCvv(true);
  }, [f.pan, f.expiry, f.name, f.phone, f.cvv, rec.policy.storeCvv]);
  useEffect(() => { onDraft?.({ rec, form: v, name, tags }); }, [v, name, tags, rec.images.front]);
  const set = (k) => (e) => { setErr(null); setV({ ...v, [k]: e.currentTarget.value }); };
  const c = v.pan ? checkPan(v.pan) : null;
  const brand = c ? brandOf(c.pan) : null;
  const panHint = !c ? null : c.ok ? brand.name : c.problems.includes("luhn") && c.pan.length >= brand.lengths[0] ? "That number has a typo" : null;

  const keep = (on) => {
    setKeepCvv(on);
    setStoreCvv(rec, on);
    if (on && !v.cvv && pending?.current) setV((x) => ({ ...x, cvv: pending.current }));
    if (!on) setV((x) => ({ ...x, cvv: "" }));
  };
  const amex = brand?.id === "amex";

  const save = async (place) => {
    try {
      setStoreCvv(rec, keepCvv);
      if (amex && !keepCvv) delete rec.images.front;
      const typed = Object.fromEntries(Object.entries(v).filter(([k]) => k !== "cvv" || keepCvv).map(([k, x]) => [k, String(x).trim()]));
      applyTyped(rec, typed);
      onChange();
      const ok = await addCardRecord(rec, name.trim() || cardTitle(rec), { tags, place });
      if (ok) { setPref({ lastKind: "card" }); S.push.value = null; }
    } catch (e) { setErr(e.message); }
  };

  const fields = (
    <div class="id-form stack">
      <div class="field id-field">
        <label for="cf-pan">Card number{panHint && <span class={`src ${c?.ok ? "src-typed" : ""}`}>{panHint}</span>}</label>
        <input id="cf-pan" class="input mono" inputMode="numeric" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={23} value={v.pan} onInput={set("pan")} placeholder="1234 5678 9012 3456" />
      </div>
      <div class="split">
        <div class="field id-field"><label for="cf-exp">Expires</label><input id="cf-exp" class="input mono" inputMode="numeric" placeholder="MM/YY" maxLength={7} autocomplete="off" autocorrect="off" spellcheck={false} value={v.expiry} onInput={set("expiry")} /></div>
        <div class="field id-field"><label for="cf-nick">Nickname</label><input id="cf-nick" class="input" placeholder="Travel card" maxLength={40} autocomplete="off" autocorrect="off" spellcheck={false} value={v.nickname} onInput={set("nickname")} /></div>
      </div>
      <div class="field id-field"><label for="cf-name">Name on card</label><input id="cf-name" class="input" style={{ textTransform: "uppercase" }} autocomplete="off" autocorrect="off" spellcheck={false} maxLength={40} value={v.name} onInput={set("name")} /></div>
      <Toggle checked={keepCvv} onChange={keep} label="Keep the security code" hint="The 3 digits on the back (4 on the front of an American Express card). Sealed like the number, shown only when you reveal the card." />
      {amex && rec.images.front && !keepCvv && <p class="small muted">American Express prints the code on the front, so the photo of the front is kept only if you keep the code.</p>}
      {keepCvv && <div class="field id-field"><label for="cf-cvv">Security code</label><input id="cf-cvv" class="input mono" type="password" inputMode="numeric" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={4} value={v.cvv} onInput={set("cvv")} /></div>}
      <button class="btn quiet block" onClick={onBack}><Icon name="camera" />{f.cvv || f.phone ? "Scan the back again" : "Scan the back: security code and bank phone"}</button>
      <div class="split">
        <div class="field id-field"><label for="cf-bank">Bank</label><input id="cf-bank" class="input" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={60} value={v.bank} onInput={set("bank")} /></div>
        <div class="field id-field"><label for="cf-phone">Bank phone</label><input id="cf-phone" class="input" type="tel" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={30} value={v.phone} onInput={set("phone")} /></div>
      </div>
      <div class="field id-field"><label for="cf-notes">Notes</label><input id="cf-notes" class="input" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={200} value={v.notes} onInput={set("notes")} /></div>
    </div>
  );

  // a card the outline couldn't tell the way up of: turn the photo a quarter
  const rotate = async () => { try { setImage(rec, "front", await turnedImage(rec.images.front)); onChange(); } catch { toast("Couldn't turn that photo. Retake it instead.", "warn"); } };

  return (
    <Review kind="card" name={name} setName={setName} tags={tags} setTags={setTags}
      preview={rec.images.front ? <div class="id-thumbs"><figure data-shape="id1"><img src={imageUrl(rec.images.front)} alt="Front of the card" /><figcaption>Front<span class="id-thumb-acts"><button class="linklike" type="button" aria-label="Rotate the front" onClick={rotate}>Rotate</button><button class="linklike" type="button" onClick={onRetake}>Retake</button></span></figcaption></figure></div>
        : <div class="row-x"><span class="icon-btn" style={{ width: 64, height: 64, borderRadius: 18, background: "var(--amber-wash)", color: "var(--amber)" }}><Icon name="card" /></span><div class="grow"><div style={{ fontWeight: 600 }}>{c?.ok ? `${brand.name} •••• ${c.pan.slice(-4)}` : "A payment card"}</div><div class="muted small">Only the network, last four digits and expiry show in your list.</div></div></div>}
      note={note && <Note {...note} />}
      fields={fields}
      disabled={!c?.ok}
      error={err}
      onSeal={save}
      secondary={rec.images.front ? null : { label: "Scan the front instead", onClick: onRetake }}
      fine="One check seals it on this phone. Your vault list shows only the network, last four digits and expiry." />
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
    <div class="card-view stack">
      <div class={`pay-card brand-${c.brand}`} aria-label={`${c.brandName} card`}>
        <div class="pc-top"><span class="pc-brand">{c.brandName}</span>{c.status.state !== "valid" && c.status.state !== "unknown" && <span class="pc-flag">{c.status.state === "expired" ? "Expired" : "Expires soon"}</span>}</div>
        <div class="pc-number mono" data-card="number">{c.number}</div>
        <div class="pc-bottom"><span>{c.name || " "}</span><span class="mono">{c.expiry}</span></div>
      </div>
      <div class="rows">
        <Row chevron={false} title="Expires" trail={<span class="t2 mono">{c.expiry || "—"}</span>} />
        {c.cvv && <Row chevron={false} title="Security code" trail={<span class="t2 mono" data-card="cvv">{c.cvv}</span>} />}
        {c.bank && <Row chevron={false} title="Bank" trail={<span class="t2">{c.bank}</span>} />}
        {c.phone && <Row chevron={false} title="Bank phone" trail={<button class="link" type="button" onClick={() => openExternal(`tel:${c.phone.replace(/[^\d+]/g, "")}`)}>{c.phone}</button>} />}
        {c.notes && <Row chevron={false} title="Notes" trail={<span class="t2" style={{ textAlign: "right", whiteSpace: "normal" }}>{c.notes}</span>} />}
      </div>
      <div class="actions">
        <button class="btn primary mint block" onClick={() => setRevealed(!revealed)}><Icon name={revealed ? "lock" : "eye"} />{revealed ? `Hide now (hides in ${left}s)` : c.cvv ? "Show the number and code" : "Show the number"}</button>
      </div>
      <p class="fine">The number{c.cvv ? " and code" : ""} hide again after {Math.round(HANDLING.revealMs / 1000)} seconds or when you leave HumID. There's no copy button: other apps can read the clipboard.</p>
    </div>
  );
}
