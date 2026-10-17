// Payment cards: add one (camera, tap, or type) as a step inside the Add screen, and
// the card view inside the viewer. The rules live in @humid/cards (never a PIN, chip
// or stripe data, or a photo of the back; the security code only when the holder
// keeps it); this file is the screens around them.
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { openExternal } from "../core/external.js";
import * as S from "../core/state.js";
import { addCardRecord, readCardTap, readCardPhoto, chipReader } from "../core/controller.js";
import { jpeg, imageUrl, releaseReaders, rotateCanvas } from "../core/scan.js";
import { PLATFORM } from "../core/config.js";
import { DocCamera } from "./ids.jsx";
import { Review, Push } from "./review.jsx";
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

/**
 * The payment-card step of the Add screen.
 *   start   { front: { canvas, read } } — the front the Add camera photographed and read
 *           (read may be null); { tap: true } — go straight to a tap; {} — the typed form
 *   onExit  Back from the form: the caller shows what was before
 */
export function CardFlow({ start, onExit }) {
  const rec = useRef(newCard());
  const pendingCvv = useRef(null); // a code read from an American Express front: kept only if the holder chooses
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [cam, setCam] = useState(null);     // null | "front" | "back"
  const [note, setNote] = useState(null);
  const [tapping, setTapping] = useState(false);
  const started = useRef(false);
  const busy = S.sheet.value?.stage != null;

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (start.front) applyFront(start.front.read, start.front.canvas);
    else if (start.tap) tap();
    return () => { releaseReaders(); };
  }, []);

  /** Keep the front's photo and what was read from it. */
  async function applyFront(r, canvas) {
    const img = await jpeg(canvas, { maxW: 1200 });
    setImage(rec.current, "front", img);
    if (r?.pan) {
      try {
        applyRead(rec.current, { ...r, cvv: null }, "camera"); // a code read here isn't kept unless the holder says so
        pendingCvv.current = r.cvv || null;
        const amex = brandOf(r.pan).id === "amex";
        setNote({ tone: "ok", text: `Read ${brandOf(r.pan).name} ending ${r.pan.slice(-4)}${r.expiry ? ", its expiry" : ""}${r.name ? " and the name" : ""}. Check them.${amex ? r.cvv ? " The 4-digit security code is on the front: switch on Keep the security code below to keep it." : "" : " Then scan the back for the security code."}` });
      } catch { setNote({ tone: "warn", text: "Couldn't read the number clearly. Type it below." }); }
    } else setNote({ tone: "warn", text: "Couldn't read the number from the photo. Type it below, or try again in better light." });
    redraw();
  }

  // The front, retaken: keep its photo, read number, expiry and name. The camera stays open
  // ("Reading…") while the text is read, then closes onto the details to check.
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
          const amex = brandOf(r.pan).id === "amex";
          setNote({ tone: "ok", text: `Read ${brandOf(r.pan).name} ending ${r.pan.slice(-4)}${r.expiry ? ", its expiry" : ""}${r.name ? " and the name" : ""}. Check them.${amex ? r.cvv ? " The 4-digit security code is on the front: switch on Keep the security code below to keep it." : "" : " Then scan the back for the security code."}` });
        } catch { setNote({ tone: "warn", text: "Couldn't read the number clearly. Type it below." }); }
      } else setNote({ tone: "warn", text: "Couldn't read the number from the photo. Type it below, or try again in better light." });
      redraw();
    };
  }

  // The back: read the security code and the bank's phone number. The photo isn't kept.
  // A card can be held any way up: read it as straightened, and if that finds nothing, turned round.
  async function back({ canvas }) {
    const found = (x) => !!(x?.cvv || x?.phone);
    let r = await readCardPhoto(canvas, { side: "back", pan: rec.current.fields.pan });
    if (!found(r)) { const r2 = await readCardPhoto(rotateCanvas(canvas, 180), { side: "back", pan: rec.current.fields.pan }); if (found(r2)) r = r2; }
    return () => {
      setCam(null);
      // Scanning the back is asking HumID for the code; the switch below stays the holder's to turn off.
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
      <Push eyebrow="Payment card" title={tapping ? "Hold the card still…" : "Check the details"} onBack={onExit} busy={busy} label="Add a card">
        <CardForm rec={rec.current} note={note} pending={pendingCvv} onRetake={() => setCam("front")} onBack={() => setCam("back")} onChange={redraw} />
      </Push>
      {cam === "front" && <DocCamera shape="id1" eyebrow="Card · front" title="The front of the card" hint="Fit the card in the frame, number side up." onCancel={() => setCam(null)} onDone={front} />}
      {cam === "back" && <DocCamera shape="id1" eyebrow="Card · back" title="The back of the card" hint="The side with the signature strip. The photo isn't kept." onCancel={() => setCam(null)} onDone={back} />}
    </>
  );
}

function CardNote({ tone, text }) {
  return <div class={`banner ${tone === "warn" ? "warn" : ""}`} role="status" style={{ marginTop: 10 }}><span class="b-ico"><Icon name={tone === "warn" ? "info" : "check"} /></span><div><span>{text}</span></div></div>;
}

function CardForm({ rec, note, pending, onRetake, onBack, onChange }) {
  const f = rec.fields;
  const [v, setV] = useState({ pan: f.pan ? formatPan(f.pan) : "", expiry: showExpiry(f.expiry), name: f.name || "", nickname: "", bank: "", phone: f.phone || "", notes: "", cvv: f.cvv || "" });
  const [keepCvv, setKeepCvv] = useState(!!rec.policy.storeCvv);
  const [err, setErr] = useState(null);
  const [name, setName] = useState("");
  const [tags, setTags] = useState(["money"]);
  // what a scan or tap read arrives after the form is on screen
  useEffect(() => {
    setV((x) => ({
      ...x, pan: f.pan ? formatPan(f.pan) : x.pan, expiry: showExpiry(f.expiry) || x.expiry, name: f.name || x.name,
      phone: f.phone || x.phone, cvv: f.cvv || x.cvv,
    }));
    if (rec.policy.storeCvv) setKeepCvv(true);
  }, [f.pan, f.expiry, f.name, f.phone, f.cvv, rec.policy.storeCvv]);
  const set = (k) => (e) => { setErr(null); setV({ ...v, [k]: e.currentTarget.value }); };
  const c = v.pan ? checkPan(v.pan) : null;
  const brand = c ? brandOf(c.pan) : null;
  const panHint = !c ? null : c.ok ? brand.name : c.problems.includes("luhn") && c.pan.length >= brand.lengths[0] ? "That number has a typo" : null;

  // The switch is the holder's: it sets the record's policy at once (off deletes a code already read).
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
      // American Express prints the code on the front: the front photo goes with the code, or not at all
      if (amex && !keepCvv) delete rec.images.front;
      const typed = Object.fromEntries(Object.entries(v).filter(([k]) => k !== "cvv" || keepCvv).map(([k, x]) => [k, String(x).trim()]));
      applyTyped(rec, typed);
      onChange();
      await addCardRecord(rec, name.trim() || cardTitle(rec), { tags, place });
    } catch (e) { setErr(e.message); }
  };

  const fields = (
    <div class="id-form">
      <div class="field id-field">
        <label for="cf-pan">Card number{panHint && <span class={`src ${c?.ok ? "src-typed" : ""}`}>{panHint}</span>}</label>
        <input id="cf-pan" class="mono" inputMode="numeric" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={23} value={v.pan} onInput={set("pan")} placeholder="1234 5678 9012 3456" />
      </div>
      <div class="split">
        <div class="field id-field"><label for="cf-exp">Expires</label><input id="cf-exp" class="mono" inputMode="numeric" placeholder="MM/YY" maxLength={7} autocomplete="off" autocorrect="off" spellcheck={false} value={v.expiry} onInput={set("expiry")} /></div>
        <div class="field id-field"><label for="cf-nick">Nickname</label><input id="cf-nick" placeholder="Travel card" maxLength={40} autocomplete="off" autocorrect="off" spellcheck={false} value={v.nickname} onInput={set("nickname")} /></div>
      </div>
      <div class="field id-field"><label for="cf-name">Name on card</label><input id="cf-name" class="up" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={40} value={v.name} onInput={set("name")} /></div>
      <label class="toggle" style={{ marginTop: 12 }}>
        <span><strong>Keep the security code</strong><span>The 3 digits on the back (4 on the front of an American Express card). Sealed like the number, shown only when you reveal the card.</span></span>
        <input type="checkbox" role="switch" checked={keepCvv} onChange={(e) => keep(e.currentTarget.checked)} />
        <i aria-hidden="true" />
      </label>
      {amex && rec.images.front && !keepCvv && <p class="small muted" style={{ marginTop: 6 }}>American Express prints the code on the front, so the photo of the front is kept only if you keep the code.</p>}
      {keepCvv && <div class="field id-field"><label for="cf-cvv">Security code</label><input id="cf-cvv" class="mono" type="password" inputMode="numeric" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={4} value={v.cvv} onInput={set("cvv")} /></div>}
      <button class="btn quiet block" style={{ marginTop: 10 }} onClick={onBack}><Icon name="camera" />{f.cvv || f.phone ? "Scan the back again" : "Scan the back: security code and bank phone"}</button>
      <div class="split">
        <div class="field id-field"><label for="cf-bank">Bank</label><input id="cf-bank" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={60} value={v.bank} onInput={set("bank")} /></div>
        <div class="field id-field"><label for="cf-phone">Bank phone</label><input id="cf-phone" type="tel" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={30} value={v.phone} onInput={set("phone")} /></div>
      </div>
      <div class="field id-field"><label for="cf-notes">Notes</label><input id="cf-notes" autocomplete="off" autocorrect="off" spellcheck={false} maxLength={200} value={v.notes} onInput={set("notes")} /></div>
    </div>
  );

  return (
    <Review kind="card" name={name} setName={setName} tags={tags} setTags={setTags}
      preview={rec.images.front ? <div class="id-thumbs"><figure data-shape="id1"><img src={imageUrl(rec.images.front)} alt="Front of the card" /><figcaption>Front<button class="linklike" onClick={onRetake}>Retake</button></figcaption></figure></div>
        : <div class="doc-hero"><span class="ico" data-kind="card" style={{ display: "grid", placeItems: "center", borderRadius: 18, width: 64, height: 64 }}><Icon name="card" /></span><div><div class="name" style={{ fontWeight: 600 }}>{c?.ok ? `${brand.name} •••• ${c.pan.slice(-4)}` : "A payment card"}</div><div class="muted small">Only the network, last four digits and expiry show in your list.</div></div></div>}
      note={note && <CardNote {...note} />}
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
    <div class="card-view">
      <div class={`pay-card brand-${c.brand}`} aria-label={`${c.brandName} card`}>
        <div class="pc-top"><span class="pc-brand">{c.brandName}</span>{c.status.state !== "valid" && c.status.state !== "unknown" && <span class="pc-flag">{c.status.state === "expired" ? "Expired" : "Expires soon"}</span>}</div>
        <div class="pc-number mono" data-card="number">{c.number}</div>
        <div class="pc-bottom"><span>{c.name || " "}</span><span class="mono">{c.expiry}</span></div>
      </div>
      <div class="card" style={{ marginTop: 14 }}>
        <div class="row"><span class="k">Expires</span><span class="v mono">{c.expiry || "—"}</span></div>
        {c.cvv && <div class="row"><span class="k">Security code</span><span class="v mono" data-card="cvv">{c.cvv}</span></div>}
        {c.bank && <div class="row"><span class="k">Bank</span><span class="v">{c.bank}</span></div>}
        {c.phone && <div class="row"><span class="k">Bank phone</span><span class="v"><button class="linklike" type="button" onClick={() => openExternal(`tel:${c.phone.replace(/[^\d+]/g, "")}`)}>{c.phone}</button></span></div>}
        {c.notes && <div class="row"><span class="k">Notes</span><span class="v">{c.notes}</span></div>}
      </div>
      <div class="actions">
        <button class="btn secure block" onClick={() => setRevealed(!revealed)}><Icon name={revealed ? "lock" : "eye"} />{revealed ? `Hide now (hides in ${left}s)` : c.cvv ? "Show the number and code" : "Show the number"}</button>
      </div>
      <p class="fine" style={{ marginTop: 12 }}>The number{c.cvv ? " and code" : ""} hide again after {Math.round(HANDLING.revealMs / 1000)} seconds or when you leave HumID. There's no copy button: other apps can read the clipboard.</p>
    </div>
  );
}
