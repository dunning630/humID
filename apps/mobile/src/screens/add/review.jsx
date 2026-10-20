// The one review every kind goes through before it's sealed: what was captured or chosen,
// its name, its kind (with a way to change it), the kind's own fields, tags, the location
// stamp, and Seal. The Add flow (index.jsx), the ID flow (ids.jsx) and the card flow
// (cards.jsx) render this with their own fields block. Also the photo choice (clean scan /
// straightened / original) a camera photo offers, and the Step shell every add screen
// uses (a pushed screen with an eyebrow, that holds still while a seal is under way).
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon } from "../../brand/icons.jsx";
import { Steps, SEAL_STEPS, Toggle, Row, HowProtectedLink, Pushed } from "../../ui/kit.jsx";
import { TAGS, kindOf } from "../../core/categories.js";
import { rotateCanvas } from "../../core/scan.js";
import { watchPlace, formatCoords, formatAccuracy, REASONS } from "../../core/place.js";
import { setPref, warmSeal } from "../../core/index.js";
import * as S from "../../core/state.js";

/** A full-screen add step. While a seal runs the back control is withheld: the check decides. */
export function Step({ eyebrow, title, onBack, children, trailing }) {
  const busy = S.sealing.value != null;
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape" && !busy) onBack?.(); };
    document.addEventListener("keydown", k);
    return () => document.removeEventListener("keydown", k);
  }, [onBack, busy]);
  return (
    <Pushed title={title} onBack={busy ? () => {} : onBack} trailing={trailing}>
      {eyebrow && <div class="eyebrow" style={{ marginTop: -8, marginBottom: 12 }}>{eyebrow}</div>}
      {children}
    </Pushed>
  );
}

/** Tags: optional labels for what an item is about. Any number can be on. */
import { TagPicker } from "../../ui/tags.jsx";
export { TagPicker };

/* ---------------- the location stamp ---------------- */

/** Coordinates kept to 3 decimals (about 110 m), no altitude: enough to say where, not which room. */
const coarse = (s) => ({ lat: Math.round(s.lat * 1000) / 1000, lon: Math.round(s.lon * 1000) / 1000, accuracy: Math.max(s.accuracy || 0, 110), at: s.at });

/**
 * Off by default, remembered per device (prefs.placeStamp). When on, the phone's location
 * is watched while the review is open and the stamp goes into the sealed index entry:
 * your vault never sees it. Returns { take(): watch-like or null, element }.
 */
export function usePlaceStamp() {
  const on = !!S.prefs.value.placeStamp;
  const [st, setSt] = useState({ reason: "waiting" });
  const watch = useRef(null);
  useEffect(() => {
    if (!on) { watch.current = null; return; }
    const w = watchPlace({ onChange: setSt });
    watch.current = w;
    setSt(w.status);
    return () => { w.stop(); if (watch.current === w) watch.current = null; };
  }, [on]);
  const hint = !on ? "Off. Turn it on to keep where this was sealed, to about 100 m. It's sealed with the item: your vault can't read it."
    : st.stamp ? `Here: ${formatCoords(coarse(st.stamp))} · ${formatAccuracy(coarse(st.stamp).accuracy)}`
    : REASONS[st.reason] || REASONS.waiting;
  const element = (
    <div class="place-stamp" data-on={on ? "1" : "0"} data-fix={on && st.stamp ? "1" : "0"}>
      <Toggle checked={on} onChange={(v) => setPref({ placeStamp: v })} label="Location stamp" hint={hint} />
    </div>
  );
  const take = () => {
    const w = watch.current;
    if (!on || !w) return null;
    return { take: async (ms) => { const g = await w.take(ms); return g.stamp ? { stamp: coarse(g.stamp) } : g; } };
  };
  return { take, element };
}

/* ---------------- the review ---------------- */

/**
 * Props:
 *   kind          id | card | pass | photo | file
 *   preview       the thumbnail, photo choice, card thumbs or pass face
 *   name, setName · focusName: the name is empty or a guess, so the field takes focus
 *   fields        the kind's own fields block, or null
 *   tags, setTags
 *   note          a line under the preview, or null
 *   onChangeKind  opens the picker; omitted when the kind can't change here
 *   onSeal(place) seals; disabled while `disabled`
 *   secondary     { label, onClick } — the ghost button (Retake / Choose another)
 *   fine          the sentence before "How HumID protects you"
 *   error         a message shown above Seal
 */
export function Review({ kind, preview, name, setName, focusName, fields, tags, setTags, note, onChangeKind, onSeal, disabled, secondary, fine, error }) {
  const stage = S.sealing.value;
  const place = usePlaceStamp();
  const k = kindOf(kind);
  const nameRef = useRef(null);
  useEffect(() => { warmSeal(); }, []); // the sealing arithmetic warms up while this is read
  useEffect(() => { if (focusName && nameRef.current && !nameRef.current.value) nameRef.current.focus(); }, []);
  if (stage != null) return <Steps current={{ seal: 0, upload: 1, done: 2 }[stage]} steps={SEAL_STEPS} />;
  return (
    <div class="stack" data-kind={kind}>
      {preview}
      {note}
      <div class="field">
        <label for="doc-name">Name</label>
        <input ref={nameRef} autocorrect="off" spellcheck={false} id="doc-name" class="input" value={name} placeholder="Name it so you can find it" onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" />
      </div>
      <div class="rows">
        <Row icon={k.icon} title="Kind" sub={k.one} trail={onChangeKind ? "Change" : null} onClick={onChangeKind} />
      </div>
      {fields}
      <TagPicker tags={tags} onChange={setTags} />
      {place.element}
      {error && <p class="small amber" role="alert">{error}</p>}
      <div class="actions">
        <button class="btn primary block" disabled={!!disabled} onClick={() => onSeal(place.take())}><Icon name="fingerprint" />Seal</button>
        {secondary && <button class="btn ghost block" onClick={secondary.onClick}>{secondary.label}</button>}
      </div>
      <p class="fine">{fine || "One check seals it on this phone."} <HowProtectedLink /></p>
    </div>
  );
}

/* ---------------- a camera photo, in up to three versions ---------------- */

export const canvasBlob = (c, q = 0.9) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error("Couldn't save that photo. Try again."))), "image/jpeg", q));

/** How much of a page must look like paper for the clean scan to be the suggested version. */
export const PAPER_SHARE = 0.45;

/** The canvas for a choice: "clean", "proposed" (straightened) or "original", turned `turn` (not the original). */
export const versionOf = (shot, which, turn) =>
  which === "original" ? shot.original : rotateCanvas(which === "clean" && shot.clean ? shot.clean : shot.canvas, turn);

/**
 * A photo from the camera, in up to three versions: a clean scan, the straightened photo
 * with its true colours, or the photo exactly as taken. Shows the chosen one; onChange({ which, turn }).
 */
export function PhotoChoice({ shot, which, turn, onChange, onRetake }) {
  const [url, setUrl] = useState(null);
  const [more, setMore] = useState(false);
  useEffect(() => {
    let gone = false, made = null;
    const c = versionOf(shot, which, turn);
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
        <div class="seg" data-n={shot.clean || shot.cleanP ? "3" : "2"} role="radiogroup" aria-label="Which version to seal">
          {(shot.clean || shot.cleanP) && (
            <button role="radio" aria-checked={which === "clean"} aria-pressed={which === "clean"} onClick={() => onChange({ which: "clean", turn })}>
              <Icon name="sparkle" /><span>Clean scan</span>{tag("clean")}
            </button>
          )}
          <button role="radio" aria-checked={which === "proposed"} aria-pressed={which === "proposed"} onClick={() => onChange({ which: "proposed", turn })}>
            <Icon name="scan" /><span>Straightened</span>{tag("proposed")}
          </button>
          <button role="radio" aria-checked={which === "original"} aria-pressed={which === "original"} onClick={() => onChange({ which: "original", turn })}><Icon name="image" /><span>Original</span></button>
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
        {" "}{more ? <button class="linklike" type="button" onClick={onRetake}>Retake</button> : <button class="linklike" type="button" onClick={() => setMore(true)}>Looks wrong?</button>}
      </p>
    </div>
  );
}

/** A note under a preview: what was read, or what to check. */
export function Note({ tone, text }) {
  return (
    <div class={`banner ${tone === "warn" ? "amber" : "mint"}`} role="status">
      <Icon name={tone === "warn" ? "info" : "check"} />
      <div><span>{text}</span></div>
    </div>
  );
}
