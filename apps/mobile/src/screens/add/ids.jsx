// Identity documents: scan a driver's license, passport or ID card with the camera (and
// its chip, where there is one), review the details, and seal one record. IdFlow is a
// step inside the Add flow; IdView is the opened record in the viewer.
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Banner, Toggle, Row } from "../../ui/kit.jsx";
import { ChipAccess } from "../../ui/codes.jsx";
import { Review, Step, Note } from "./review.jsx";
import { DocCamera, turnedImage } from "./camera.jsx";
import * as S from "../../core/state.js";
import { addIdRecord, chipReader, readChipInto, saveCopy, setPref, toast } from "../../core/index.js";
import {
  KINDS, kindLabel, fieldsFor, newRecord, applyMrz, applyAamva, applyTyped, setImage, title as recordTitle, status as idStatus,
  provenance, fullName, niceName, countryName, regionName, parseAamva,
} from "@humid/idscan";
import { releaseReaders, jpeg, imageUrl, portraitImage, warmScan, modesForKind } from "../../core/scan.js";
import { LIGHT_TIP } from "../../core/addroute.js";

/* ---------------- the ID flow ---------------- */

// What each kind of document asks the camera for, side by side.
export const PLAN = {
  passport: [{ side: "front", shape: "td3", read: { mrz: true }, title: "The photo page", hint: "The page with your photo, the two lines of <<< at the bottom of the frame." }],
  driver_license: [
    { side: "front", shape: "id1", read: {}, title: "Front of the license", hint: "The side with your photo, filling the frame edge to edge." },
    { side: "back", shape: "id1", read: { barcode: true }, title: "Back of the license", hint: "The side with the long barcode. It's read the moment it's in the frame." },
  ],
  id_card: [
    { side: "front", shape: "id1", read: {}, title: "Front of the card", hint: "The side with your photo, filling the frame edge to edge." },
    { side: "back", shape: "id1", read: { barcode: true, mrz: true }, title: "Back of the card", hint: "A barcode or lines of <<< are read the moment they're in the frame.", optional: true },
  ],
  residence_permit: [
    { side: "front", shape: "id1", read: {}, title: "Front of the permit", hint: "The side with your photo, filling the frame edge to edge." },
    { side: "back", shape: "id1", read: { mrz: true }, title: "Back of the permit", hint: "The side with three lines of <<<. They're read the moment they're in the frame.", optional: true },
  ],
  other: [
    { side: "front", shape: "id1", read: {}, title: "Front", hint: "Fill the frame edge to edge. It takes the photo by itself." },
    { side: "back", shape: "id1", read: {}, title: "Back", hint: "Fill the frame edge to edge. It takes the photo by itself.", optional: true },
  ],
};

/** The ID kinds on "What are you adding?" (3.0.1: listed there directly; each opens its own outline at once). */
export const ID_CHOICES = [
  { kind: "passport", icon: "passport", title: "Passport", sub: "The photo page. Reads the lines of <<<, and the chip on phones with NFC." },
  { kind: "driver_license", icon: "idcard", title: "Driver's license", sub: "The front, then the barcode on the back." },
  { kind: "id_card", icon: "idcard", title: "State ID or ID card", sub: "A state ID, or a national ID card. Front, then back." },
  { kind: "residence_permit", icon: "idcard", title: "Green card or residence permit", sub: "The front, then the lines of <<< on the back." },
  { kind: "other", icon: "file", title: "Another card", sub: "Insurance, membership, student ID: front and back." },
];

const SOURCE = { chip: "Chip", barcode: "Barcode", mrz: "Scanned", typed: "You" };

/** The three plain tiers of where an ID's details came from (UX-26). */
export function proofTier(level) {
  // Mint only when the issuing country's signature was checked; a phone-only read is amber (CREDS-04).
  if (level === "chip") return { icon: "nfc", text: "Read from the chip", tone: "mint" };
  if (level === "chip-issuer-unverified") return { icon: "nfc", text: "Read from the chip, issuer not verified on this phone", tone: "amber" };
  if (level === "chip-edited") return { icon: "nfc", text: "Read from the chip, then edited", tone: "" };
  if (level === "barcode") return { icon: "barcode", text: "Read from the barcode", tone: "mint" };
  if (level === "mrz") return { icon: "scan", text: "Read from the document's lines", tone: "mint" };
  if (level === "mrz-partial" || level === "mrz-unverified") return { icon: "scan", text: "Read from the lines, partly", tone: "amber" };
  if (level?.startsWith("chip")) return { icon: "nfc", text: "Chip read, not verified", tone: "amber" };
  if (level === "mdoc") return { icon: "phone", text: "Mobile ID, issuer checked", tone: "mint" };
  if (level === "mdoc-edited") return { icon: "phone", text: "Mobile ID, then edited", tone: "" };
  if (level?.startsWith("mdoc")) return { icon: "phone", text: "Mobile ID, not verified", tone: "amber" };
  return { icon: "pencil", text: "Typed by you", tone: "" };
}

/**
 * A record started from what the Add camera found: the side it photographed (with what it
 * read). `found`: { kind, side, canvas, barcode, mrz, consensus }.
 */
export async function recordFrom(found) {
  const rc = newRecord(found.kind);
  if (found.canvas) {
    const img = await jpeg(found.canvas);
    setImage(rc, found.side, img);
  }
  let note = null;
  if (found.barcode) {
    const a = parseAamva(found.barcode);
    if (a) { applyAamva(rc, a); rc.raw.barcode = found.barcode; note = { tone: "ok", text: `Barcode read: ${[niceName(a.fields.given), niceName(a.fields.surname)].filter(Boolean).join(" ") || "details found"}.` }; }
  }
  if (found.mrz) {
    applyMrz(rc, found.mrz, { consensus: found.consensus });
    note = found.mrz.valid
      ? { tone: "ok", text: `Details read${found.consensus ? "" : " (review them)"}: ${fullName(rc) || found.mrz.number}.` }
      : { tone: "warn", text: "Read only part of the details. Review them, or retake the photo." };
  }
  return { rec: rc, note };
}

/**
 * The ID flow: capture each side (the camera reads a barcode or MRZ as it goes), read the
 * chip where there is one, review the details, seal.
 *   start    { rec, note, step, name, tags } — a record to carry on with; step: "camera" (open the
 *            first side's outline at once: the kind was just picked), "capture" (default), "auto" (a
 *            side was already read), "chip", or "review"
 *   onExit   the flow is left from its first step (Back)
 *   onDraft  ({ rec, step, name, tags }) whenever something worth keeping across a lock changes
 */
export function IdFlow({ start, onExit, onDraft }) {
  const rec = useRef(start.rec);
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [step, setStep] = useState(start.step === "auto" || start.step === "camera" ? "capture" : start.step || "capture"); // capture | chip | review
  // picked a moment ago: the first side's camera opens with the flow, no "Start camera" between
  const [cam, setCam] = useState(() => (start.step === "camera" ? (PLAN[start.rec.kind] || PLAN.other).find((p) => !start.rec.images[p.side]) || null : null));
  const camRun = useRef({ cam: null, n: 0 });
  if (cam !== camRun.current.cam) camRun.current = { cam, n: camRun.current.n + 1 };
  const [saved, setSaved] = useState(null);
  const [note, setNote] = useState(start.note || null);
  const [nfc, setNfc] = useState(null);
  const [access, setAccess] = useState(null);
  const [name, setName] = useState(start.name || "");
  const [tags, setTags] = useState(start.tags || ["identity"]);
  const fields = useRef(null);

  const r = rec.current;
  const plan = PLAN[r.kind] || PLAN.other;
  const done = plan.filter((p) => r.images[p.side]);
  const next = plan.find((p) => !r.images[p.side] && !r.skipped?.includes(p.side));

  useEffect(() => {
    for (const m of modesForKind(r.kind)) warmScan(m);
    if (KINDS[r.kind]?.chip || step === "chip") chipReader().then(setNfc).catch(() => setNfc({ available: false }));
    if (start.step === "auto") {
      if (next) { setStep("capture"); setSaved({ text: done.length ? `${done[0].side === "back" ? "Back" : "Front"} saved. Now the ${next.side}.` : null, img: done[0] ? r.images[done[0].side] : null }); setCam(next); }
      else afterCapture();
    }
    return () => { releaseReaders(); };
  }, []);
  useEffect(() => { if (step === "review") setName((n) => n || recordTitle(rec.current)); }, [step]);
  useEffect(() => { onDraft?.({ rec: rec.current, step, name, tags }); }, [step, name, tags, r.images.front, r.images.back, r.verified.chip]);

  async function captured(asked, { canvas, barcode, mrz, consensus, side }) {
    const rc = rec.current;
    // the camera can tell a license front from its back by the barcode: a back held up for the front is kept as the back
    const p = side && side !== asked.side ? (PLAN[rc.kind] || PLAN.other).find((x) => x.side === side) || asked : asked;
    let img;
    try { img = await jpeg(canvas); }
    catch { throw new Error("Couldn't save that photo. Try again, or choose one with Photo."); }
    setImage(rc, p.side, img);
    let n = null;
    if (barcode) {
      const a = parseAamva(barcode);
      if (a) { applyAamva(rc, a); rc.raw.barcode = barcode; n = { tone: "ok", text: `Barcode read: ${[niceName(a.fields.given), niceName(a.fields.surname)].filter(Boolean).join(" ") || "details found"}.` }; }
      else n = { tone: "warn", text: "That barcode isn't a license barcode. Fill in the details yourself." };
    }
    if (mrz) {
      applyMrz(rc, mrz, { consensus });
      n = mrz.valid
        ? { tone: "ok", text: `Details read${consensus ? "" : " (review them)"}: ${fullName(rc) || mrz.number}.` }
        : { tone: "warn", text: "Read only part of the details. Review them, or retake the photo." };
    }
    if (!n && (p.read.barcode || p.read.mrz)) n = { tone: "warn", text: p.read.barcode && !p.read.mrz ? "Couldn't read the barcode. Retake the back, or fill in the details yourself." : "Couldn't read the details from the photo. Retake it, or fill them in yourself." };
    if (!n) n = { tone: "ok", text: `${p.title} saved.` };
    setNote(n);
    redraw();
    const left = (PLAN[rc.kind] || PLAN.other).find((x) => !rc.images[x.side] && !rc.skipped?.includes(x.side));
    if (left && n.tone === "ok") {
      return () => { setSaved({ text: p.side === "front" ? "Front saved. Now turn it over." : left.side === "front" ? "Back saved. Now the front." : `${p.title} saved.`, img }); setCam({ ...left }); }; // a fresh camera, even for the side that was just open
    }
    return () => { setSaved(null); setCam(null); afterCapture(); };
  }

  function afterCapture() {
    const rc = rec.current;
    const left = (PLAN[rc.kind] || PLAN.other).find((p) => !rc.images[p.side] && !rc.skipped?.includes(p.side));
    if (left) { setStep("capture"); return; }
    setStep(KINDS[rc.kind]?.chip && nfc?.kind !== "none" && !rc.verified.chip ? "chip" : "review");
    setName((n) => n || recordTitle(rc));
  }

  const chipOffered = () => KINDS[r?.kind]?.chip && nfc && nfc.kind !== "none" && !r?.verified.chip;

  const stepBack = () => {
    if (step === "review") { fields.current?.commit(); setStep(chipOffered() ? "chip" : "capture"); return; }
    if (step === "chip") { if (start.step === "chip" && !done.length) onExit(); else setStep("capture"); return; }
    onExit();
  };

  function skipSide(p) {
    setCam(null);
    const rc = rec.current;
    rc.skipped = [...(rc.skipped || []), p.side];
    redraw();
    afterCapture();
  }

  async function readChipNow() {
    const ok = await readChipInto(rec.current, access, { portrait: portraitImage });
    if (ok === "unverified") {
      setNote({ tone: "warn", text: "The chip couldn't be verified, so its data wasn't used. Try again, or continue with the printed details (marked as not verified)." });
      return;
    }
    if (ok) {
      setNote({ tone: "ok", text: "Read from the chip. Its files match the chip's own list of hashes; the issuing country's signature isn't checked on this phone." });
      setName(recordTitle(rec.current));
      setStep("review");
      redraw();
    }
  }

  const retake = (p) => { fields.current?.commit(); setCam(p); };
  // the outline settles which way up a card is held; this turns what is left: half round for a card or a
  // passport page (they're always landscape), a quarter for anything else
  const rotate = async (p) => {
    const img = rec.current.images[p.side];
    if (!img) return;
    try { setImage(rec.current, p.side, await turnedImage(img, p.shape === "id1" || p.shape === "td3" ? 180 : 90)); redraw(); }
    catch { toast("Couldn't turn that photo. Retake it instead.", "warn"); }
  };
  const toChip = () => { fields.current?.commit(); setStep("chip"); };
  const seal = async (place) => {
    fields.current?.commit();
    const ok = await addIdRecord(rec.current, name || recordTitle(rec.current), place, { tags });
    if (ok) { setPref({ lastKind: rec.current.kind }); S.push.value = null; }
  };
  const missing = step === "review" ? (fields.current?.missing?.() || []) : [];

  return (
    <>
      <Step eyebrow={kindLabel(r.kind)} title={step === "chip" ? "Read the ID chip" : step === "review" ? "Review, then seal" : "Scan it"} onBack={stepBack}>
        {step === "capture" && (
          <div class="stack">
            {note && <Note {...note} />}
            <Thumbs rec={r} plan={plan} onRetake={(p) => setCam(p)} onRotate={rotate} />
            {next && <Banner icon="camera" title={next.title} text={next.hint} />}
            {next && <p class="small muted">{LIGHT_TIP}</p>}
            {next && (
              <div class="actions">
                <button class="btn primary block" data-start-camera onClick={() => setCam(next)}><Icon name="camera" />{done.length ? `Start camera: the ${next.side}` : "Start camera"}</button>
                {next.optional && <button class="btn ghost block" onClick={() => skipSide(next)}>No {next.side} to scan</button>}
              </div>
            )}
          </div>
        )}

        {step === "chip" && (
          <div class="stack">
            {note && <Note {...note} />}
            <Banner icon="nfc" title="The chip holds the details and photo, checked on this phone" text={`${nfc?.kind === "reader" ? "Place the document on the card reader when asked." : "Hold the top of your phone flat against the document when asked."} It takes about 10 seconds.`} />
            {nfc && !nfc.available && <Banner tone="amber" icon="info" title="Can't read chips right now" text={nfc.reason} />}
            <ChipAccess onChange={setAccess} initial={chipAccessFrom(r)} title="Details that open the chip" note="They only open the chip. What it holds is sealed with this record." />
            <div class="actions">
              <button class="btn primary block" disabled={!access || !nfc?.available} onClick={readChipNow}><Icon name="nfc" />Read the ID chip</button>
              {nfc && !nfc.available && <button class="btn quiet block" onClick={async () => setNfc(await chipReader({ fresh: true }))}>Try again</button>}
              <button class="btn ghost block" onClick={() => setStep("review")}>Continue with the printed details (not verified)</button>
            </div>
          </div>
        )}

        {step === "review" && (
          <Review kind="id" name={name} setName={setName} tags={tags} setTags={setTags}
            preview={<><IdProof rec={r} /><Thumbs rec={r} plan={plan} onRetake={retake} onRotate={rotate} />{chipOffered() && <button class="btn quiet block" onClick={toChip}><Icon name="nfc" />Also read the ID chip</button>}</>}
            note={note && <Note {...note} />}
            fields={<IdFields rec={r} api={fields} onChange={redraw} />}
            disabled={missing.length > 0}
            error={missing.length > 0 ? `Add the ${missing.map((k) => (k === "number" ? "document number" : "surname")).join(" and ")} before sealing.` : null}
            onSeal={seal}
            secondary={next ? { label: `Scan the ${next.side}`, onClick: () => retake(next) } : done.length ? { label: "Retake", onClick: () => retake(plan[0]) } : null}
            fine={`One live check seals the details, photos${r.raw.chip ? " and the chip's signed data" : ""} together on this phone.`} />
        )}
      </Step>
      {cam && (
        <DocCamera key={`${cam.side}-${camRun.current.n}`} kind={r.kind} side={cam.side} shape={cam.shape} read={cam.read} eyebrow={kindLabel(r.kind)} title={cam.title} hint={cam.hint}
          saved={saved} onCancel={() => { setSaved(null); setCam(null); if (start.step === "camera" && !done.length) onExit(); }} onSkip={cam.optional ? () => { setSaved(null); skipSide(cam); } : null} onDone={(res) => captured(cam, res)} />
      )}
    </>
  );
}

const chipAccessFrom = (r) => ({ number: r.fields.number || "", birth: r.fields.birth || "", expiry: r.fields.expiry || "" });

function Thumbs({ rec, plan, onRetake, onRotate }) {
  const sides = [...plan.map((p) => p.side), ...(rec.images.portrait ? ["portrait"] : [])];
  return (
    <div class="id-thumbs">
      {sides.map((side) => {
        const img = rec.images[side];
        const p = plan.find((x) => x.side === side);
        return (
          <figure data-shape={side === "portrait" ? "portrait" : p?.shape}>
            {img ? <img src={imageUrl(img)} alt={`${side} of the document`} /> : <span class="empty-thumb">{rec.skipped?.includes(side) ? "Skipped" : "Not yet"}</span>}
            <figcaption>{side === "portrait" ? "Chip photo" : side === "front" ? "Front" : "Back"}{img && p && <span class="id-thumb-acts">{onRotate && <button class="linklike" type="button" aria-label={`Rotate the ${side}`} onClick={() => onRotate(p)}>Rotate</button>}<button class="linklike" type="button" onClick={() => onRetake(p)}>Retake</button></span>}</figcaption>
          </figure>
        );
      })}
    </div>
  );
}

function IdProof({ rec }) {
  const p = provenance(rec);
  const t = proofTier(p.level);
  return <div class={`id-proof lvl-${p.level}`}><Icon name={t.icon} /><span>{t.text}</span></div>;
}

/* ---------------- review the details ---------------- */

function IdFields({ rec, api, onChange }) {
  const [vals, setVals] = useState(() => Object.fromEntries(fieldsFor(rec.kind).map((f) => [f.key, rec.fields[f.key] ?? ""])));
  const [addr, setAddr] = useState(() => rec.address || { street: "", street2: "", city: "", region: "", postalCode: "", country: rec.fields.issuer || "" });
  const [more, setMore] = useState(false);
  const checks = rec.verified.mrz?.checks || {};
  const unsure = (k) => rec.source[k] === "mrz" && ((k === "number" && checks.number === false) || (k === "birth" && checks.birth === false) || (k === "expiry" && checks.expiry === false) || (k === "optional" && checks.optional === false));
  const set = (k) => (v) => setVals({ ...vals, [k]: v });
  const fields = fieldsFor(rec.kind);
  const main = fields.filter((f) => !f.optional || vals[f.key] !== "" && vals[f.key] != null);
  const extra = fields.filter((f) => f.optional && (vals[f.key] === "" || vals[f.key] == null));
  const missing = () => (rec.kind === "other" ? [] : ["surname", "number"].filter((k) => !String(vals[k] || "").trim()));
  const commit = () => {
    const typed = Object.fromEntries(Object.entries(vals).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v]).filter(([k, v]) => (rec.fields[k] ?? "") !== (v ?? "")));
    applyTyped(rec, typed);
    const a = Object.fromEntries(Object.entries(addr).map(([k, v]) => [k, String(v || "").trim()]));
    if (Object.values(a).some(Boolean) && JSON.stringify(a) !== JSON.stringify(rec.address || {})) { rec.address = a; rec.addressSource = "typed"; }
    onChange();
  };
  api.current = { commit, missing };
  useEffect(() => { onChange(); }, [vals.surname, vals.number]);

  return (
    <div class="id-form stack">
      {main.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={rec.source[f.key]} unsure={unsure(f.key)} />)}
      {rec.kind !== "passport" && (rec.address || rec.kind === "driver_license" || rec.kind === "id_card") && (
        <fieldset class="id-addr">
          <legend>Address</legend>
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Street" placeholder="Street" value={addr.street} onInput={(e) => setAddr({ ...addr, street: e.currentTarget.value })} />
          <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="Apartment, suite" placeholder="Apartment, suite (optional)" value={addr.street2} onInput={(e) => setAddr({ ...addr, street2: e.currentTarget.value })} />
          <div class="split3">
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="City" placeholder="City" value={addr.city} onInput={(e) => setAddr({ ...addr, city: e.currentTarget.value })} />
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="State" placeholder="State" maxLength={3} class="up" value={addr.region} onInput={(e) => setAddr({ ...addr, region: e.currentTarget.value.toUpperCase() })} />
            <input autocorrect="off" spellcheck={false} autocomplete="off" aria-label="ZIP or postal code" placeholder="ZIP" value={addr.postalCode} onInput={(e) => setAddr({ ...addr, postalCode: e.currentTarget.value })} />
          </div>
        </fieldset>
      )}
      {extra.length > 0 && !more && <button class="link muted" type="button" onClick={() => setMore(true)}>Add more details ({extra.map((f) => f.label.toLowerCase()).slice(0, 3).join(", ")}…)</button>}
      {more && extra.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={null} />)}
    </div>
  );
}

function FieldInput({ f, value, onInput, source, unsure }) {
  const id = `idf-${f.key}`;
  const tag = source && <span class={`src src-${source}`} title={`From the ${SOURCE[source] || source}`}>{SOURCE[source] || source}</span>;
  const text = (e) => onInput(e.currentTarget.value);
  let input;
  if (f.type === "date") input = <input id={id} class="input" type="date" value={value || ""} onInput={text} />;
  else if (f.type === "sex") input = (
    <select id={id} value={value || ""} onChange={text}><option value="">—</option><option value="F">Female</option><option value="M">Male</option><option value="X">Unspecified (X)</option></select>
  );
  else if (f.type === "bool") return <Toggle checked={value === true} onChange={(v) => onInput(v)} label={f.label} hint={tag ? `From the ${SOURCE[source] || source}` : null} />;
  else input = <input autocorrect="off" id={id} class={`input${f.mono ? " mono" : ""}`} style={f.mono || f.type === "country" || f.type === "region" ? { textTransform: "uppercase" } : undefined} value={value ?? ""} onInput={text} autocomplete="off" spellcheck={false}
    maxLength={f.type === "country" ? 3 : f.type === "region" ? 3 : 80} />;
  const hint = f.type === "country" && value ? countryName(value) : f.type === "region" && value ? regionName(value) : null;
  return (
    <div class={`field id-field${unsure ? " unsure" : ""}`}>
      <label for={id}>{f.label}{tag}</label>
      {input}
      {unsure ? <span class="hint amber">Check this against the document: its check digit didn't agree.</span> : hint && hint !== value ? <span class="hint">{hint}</span> : null}
    </div>
  );
}

/* ---------------- a sealed ID, opened ---------------- */

const fmtDay = (iso) => {
  if (!iso) return "";
  const d = new Date(`${iso}T12:00:00Z`);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
};

export function IdView({ record: rec, item }) {
  const [side, setSide] = useState(rec.images.front ? "front" : rec.images.portrait ? "portrait" : "back");
  const st = idStatus(rec, new Date(), S.prefs.value.expiryWarnDays);
  const p = provenance(rec);
  const tier = proofTier(p.level);
  const rows = fieldsFor(rec.kind).filter((f) => rec.fields[f.key] !== undefined && rec.fields[f.key] !== "" && rec.fields[f.key] !== null);
  const show = (f) => {
    const v = rec.fields[f.key];
    if (f.type === "date") return fmtDay(v);
    if (f.type === "country") return `${countryName(v)}${countryName(v) !== v ? ` (${v})` : ""}`;
    if (f.type === "region") return regionName(v);
    if (f.type === "bool") return v ? "Yes" : "No";
    if (f.type === "sex") return { M: "Male", F: "Female", X: "Unspecified" }[v] || v;
    if (f.key === "surname" || f.key === "given") return niceName(v);
    return String(v);
  };
  const sides = ["front", "back", "portrait"].filter((s) => rec.images[s]);
  const sideName = (s) => (s === "portrait" ? "Chip photo" : s === "front" ? "Front" : "Back");
  return (
    <div class="id-view stack">
      <div class="id-card-hero">
        {rec.images[side] && <img src={imageUrl(rec.images[side])} alt={side === "portrait" ? "Photo from the chip" : `${side} of the document`} data-side={side} />}
        {sides.length > 1 && (
          <div class="seg mt-3" role="tablist" aria-label="Which side">
            {sides.map((s) => <button role="tab" aria-selected={side === s} aria-pressed={side === s} onClick={() => setSide(s)}>{sideName(s)}</button>)}
          </div>
        )}
      </div>
      <h2>{fullName(rec) || recordTitle(rec)}</h2>
      <div class="id-badges">
        <span class={`pill ${st.state === "expired" ? "danger" : st.state === "expiring" ? "amber" : st.state === "valid" ? "mint" : ""}`}>
          <Icon name="clock" />{st.state === "expired" ? `Expired ${fmtDay(rec.fields.expiry)}` : st.state === "expiring" ? `Expires in ${st.days} days` : st.state === "valid" ? `Valid to ${fmtDay(rec.fields.expiry)}` : "No expiry date"}
        </span>
        <span class={`pill ${tier.tone}`}><Icon name={tier.icon} />{tier.text}</span>
      </div>
      <div class="rows">
        {rows.map((f) => <Row chevron={false} title={f.label} trail={<span class={`t2${f.mono ? " mono" : ""}`} style={{ textAlign: "right", whiteSpace: "normal" }}>{show(f)}</span>} />)}
        {rec.address && (
          <Row chevron={false} title="Address" trail={<span class="t2" style={{ textAlign: "right", whiteSpace: "normal" }}>{[rec.address.street, rec.address.street2].filter(Boolean).join(", ")}<br />{[rec.address.city, [rec.address.region, rec.address.postalCode].filter(Boolean).join(" ")].filter(Boolean).join(", ")}</span>} />
        )}
      </div>
      <details class="pass-back">
        <summary>Details</summary>
        <p class="fine">{p.text}.{rec.edited?.length ? ` You edited: ${rec.edited.map((k) => fieldsFor(rec.kind).find((f) => f.key === k)?.label.toLowerCase() || k).join(", ")}.` : ""}{p.level === "chip-edited" ? " The chip's files match its own list of hashes; the issuing country's signature isn't checked on this phone." : ""}</p>
        {rec.raw?.mrz && <pre class="mrz-lines" aria-label="The lines read from the document">{rec.raw.mrz.join("\n")}</pre>}
      </details>
      <div class="actions"><button class="btn quiet block" onClick={() => saveCopy(item)}><Icon name="download" />Save a copy (JSON with photos)</button></div>
    </div>
  );
}
