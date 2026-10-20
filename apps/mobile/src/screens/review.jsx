// The one review screen every kind goes through before it's sealed: what was captured
// or chosen, its name, its kind (with a way to change it), the fields that kind has,
// tags, the location stamp, and Seal. The Add flow (add.jsx), the ID flow (ids.jsx)
// and the payment-card flow (cards.jsx) all render this with their own fields block.
// Also the photo choice (clean scan / straightened / original) a camera photo offers.
import { useEffect, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { Steps, usePlaceStamp, HowProtectedLink, SEAL_STEPS } from "../ui.jsx";
import { TAGS, kindOf } from "../core/categories.js";
import { rotateCanvas } from "../core/scan.js";
import * as S from "../core/state.js";
import { warmSeal } from "../core/controller.js";

/** Tags: optional labels for what an item is about. Any number can be on. */
export function TagPicker({ tags, onChange, label = "Tags (optional)" }) {
  const toggle = (id) => onChange(tags.includes(id) ? tags.filter((t) => t !== id) : [...tags, id]);
  return (
    <div class="field tagpick">
      <label>{label}</label>
      <div class="chips" role="group" aria-label="Tags">
        {TAGS.map((t) => <button class="chip" type="button" aria-pressed={tags.includes(t.id)} onClick={() => toggle(t.id)}><Icon name={t.icon} />{t.label}</button>)}
      </div>
    </div>
  );
}

/**
 * The review. Props:
 *   kind        id | card | pass | photo | file
 *   preview     the thumbnail, photo choice, card thumbs or pass face
 *   name, setName
 *   fields      the kind's own fields block (ID details, card details, the pass check), or null
 *   tags, setTags
 *   note        a line under the name ("Read from the barcode", a warning), or null
 *   onChangeKind  opens the picker; omitted when the kind can't change here
 *   onSeal(place) seals; disabled while `disabled`
 *   secondary   { label, onClick } — the ghost button (Retake / Choose another)
 *   fine        the sentence before "How HumID protects you"
 *   error       a message shown above Seal
 *   busy        the seal stage from S.sheet (the stepper replaces the form)
 */
export function Review({ kind, preview, name, setName, fields, tags, setTags, note, onChangeKind, onSeal, disabled, secondary, fine, error }) {
  const stage = S.sheet.value?.stage;
  const place = usePlaceStamp();
  useEffect(() => { warmSeal(); }, []); // the sealing arithmetic warms up while this is read
  const k = kindOf(kind);
  if (stage != null) return <Steps current={{ seal: 0, upload: 1, done: 2 }[stage]} steps={SEAL_STEPS} />;
  return (
    <div class="review" data-kind={kind}>
      {preview}
      {note}
      <div class="field">
        <label for="doc-name">Name</label>
        <input autocorrect="off" spellcheck={false} id="doc-name" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" />
      </div>
      <div class="field kindrow">
        <label>Kind</label>
        <div class="kindrow-v"><span class="ico" data-kind={k.id}><Icon name={k.icon} /></span><span class="grow">{k.one}</span>
          {onChangeKind && <button class="linklike" type="button" onClick={onChangeKind}>Change</button>}</div>
      </div>
      {fields}
      <TagPicker tags={tags} onChange={setTags} />
      {place.element}
      {error && <p class="small" role="alert" style={{ color: "var(--amber-hi)", marginTop: 10 }}>{error}</p>}
      <div class="actions">
        <button class="btn primary block" disabled={!!disabled} onClick={() => onSeal(place.take())}><Icon name="fingerprint" />Seal</button>
        {secondary && <button class="btn ghost block" onClick={secondary.onClick}>{secondary.label}</button>}
      </div>
      <p class="fine" style={{ marginTop: 12 }}>{fine || "One check seals it on this phone."} The location stamp is sealed with it, so your vault server can't read it. <HowProtectedLink /></p>
    </div>
  );
}

/* ---------------- a camera photo, in up to three versions ---------------- */

export const canvasBlob = (c, q = 0.9) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error("Couldn't save that photo. Try again."))), "image/jpeg", q));

/** How much of a page must look like paper for the clean scan to be the suggested version. */
export const PAPER_SHARE = 0.45;

/** The canvas for a choice: "clean" (the clean scan), "proposed" (straightened) or "original", turned `turn` (not the original). */
export const versionOf = (shot, which, turn) =>
  which === "original" ? shot.original : rotateCanvas(which === "clean" && shot.clean ? shot.clean : shot.canvas, turn);

/**
 * A photo from the camera, in up to three versions: a clean scan (the page straightened,
 * turned the way it reads, and evened out to look like it came off a flatbed scanner:
 * shadows gone, paper white, ink crisp), the straightened photo with its true colours
 * and light, or the photo exactly as taken. The clean scan is suggested when the page
 * looks like paper; otherwise the straightened photo is. Either can be turned by hand if
 * the guess was wrong. Shows the chosen one; onChange({ which, turn }).
 */
export function PhotoChoice({ shot, which, turn, onChange, onRetake }) {
  const [url, setUrl] = useState(null);
  const [more, setMore] = useState(false); // "Looks wrong?" opened: the other versions, turning, retake
  useEffect(() => {
    let gone = false, made = null;
    const c = versionOf(shot, which, turn);
    // a small preview: the full photo is only encoded once, when it's sealed
    const s = Math.min(1, 900 / Math.max(c.width, c.height));
    const small = document.createElement("canvas");
    small.width = Math.round(c.width * s); small.height = Math.round(c.height * s);
    small.getContext("2d").drawImage(c, 0, 0, small.width, small.height);
    canvasBlob(small, 0.8).then((b) => { if (gone) return; made = URL.createObjectURL(b); setUrl(made); }).catch(() => {});
    return () => { gone = true; if (made) URL.revokeObjectURL(made); };
  }, [shot, which, turn]);
  const suggested = (shot.clean || shot.cleanP) && shot.cleanSuggested ? "clean" : "proposed";
  const tag = (w) => suggested === w && <span class="tag">Suggested</span>;
  const note = !shot.changed ? "As taken: no document edges were found to straighten."
    : which === "original" ? "The photo exactly as the camera took it."
    : which === "clean" && shot.cleanP ? "Making the clean scan: shadows gone, paper white. A moment…"
    : which === "clean" ? "Straightened and evened out like a scanner: shadows gone, paper white."
    : "Straightened, keeping its true colours and light.";
  return (
    <div class="photo-choice" data-more={more ? "1" : "0"}>
      {more && shot.changed && (
        <div class="seg" data-n={shot.clean ? "3" : "2"} role="radiogroup" aria-label="Which version to seal">
          {shot.clean && (
            <button role="radio" aria-checked={which === "clean"} onClick={() => onChange({ which: "clean", turn })}>
              <Icon name="sparkle" /><span>Clean scan</span>{tag("clean")}
            </button>
          )}
          <button role="radio" aria-checked={which === "proposed"} onClick={() => onChange({ which: "proposed", turn })}>
            <Icon name="scan" /><span>Straightened</span>{tag("proposed")}
          </button>
          <button role="radio" aria-checked={which === "original"} onClick={() => onChange({ which: "original", turn })}><Icon name="image" /><span>Original</span></button>
        </div>
      )}
      <figure class="photo-preview" data-which={which}>
        {url ? <img src={url} alt={which === "original" ? "The photo as taken" : which === "clean" ? "The document as a clean scan" : "The document, straightened"} /> : <span class="photo-wait" />}
        {more && which !== "original" && (
          <div class="photo-turn">
            <button class="icon-btn" aria-label="Turn left" onClick={() => onChange({ which, turn: (turn + 270) % 360 })}><Icon name="turn" /></button>
            <button class="icon-btn" aria-label="Turn right" onClick={() => onChange({ which, turn: (turn + 90) % 360 })}><Icon name="turn" /></button>
          </div>
        )}
      </figure>
      <p class="fine photo-note">
        {note}
        {" "}{more ? <button class="linklike" onClick={onRetake}>Retake</button> : <button class="linklike" onClick={() => setMore(true)}>Looks wrong?</button>}
      </p>
    </div>
  );
}

/** A full-screen pushed screen: Back in the top left (what Android Back presses), a title, then the content. */
export function Push({ label, eyebrow, title, onBack, backLabel = "Back", busy, children, right }) {
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape" && !busy) onBack?.(); };
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, [onBack, busy]);
  return (
    <section class="pushed" role="dialog" aria-modal="true" aria-label={label || title}>
      <div class="topbar">
        {!busy && <button class="icon-btn" aria-label={backLabel} data-back onClick={onBack}><Icon name="back" /></button>}
        <div class="grow">{eyebrow && <div class="eyebrow">{eyebrow}</div>}<h2 style={{ marginTop: eyebrow ? 4 : 0 }}>{title}</h2></div>
        {right}
      </div>
      <div class="pushed-body">{children}</div>
    </section>
  );
}
