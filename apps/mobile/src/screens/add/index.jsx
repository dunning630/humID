// Add to your vault (3.0): camera first. "Add" opens the camera; the photo routes itself:
// an ID-1 card with a license barcode or a page with an MRZ to the ID flow (ids.jsx), a card
// with a payment number to the card flow (cards.jsx), anything else to the photo review.
// The step card says what the camera thinks it sees ("Looks like a card") and offers
// "It's something else", which opens the picker: one ID entry (the kind is detected from
// the photo), then Card, Wallet pass, Photo, File, the last-used kind first. A short
// "what to show" screen appears only until the first successful capture of that kind on
// this device. Every kind ends in the one Review (review.jsx), then Seal.
//
// What the person was in the middle of survives a lock (core/drafts.js): the flow writes
// its draft as it goes, and main.jsx hands it back as S.push.value.draft after unlock.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon, kindIcon } from "../../brand/icons.jsx";
import { Banner } from "../../ui/kit.jsx";
import { fmtSize } from "../../ui/format.js";
import { suggestTags, kindFromType } from "../../core/categories.js";
import { shapeOf, liveLabel, mrzBandLikely, idKindFrom, guideFor, LIGHT_TIP } from "../../core/addroute.js";
import { cleanCanvasAsync, paperOf, grayOf, grab, rotateCanvas } from "../../core/scan.js";
import { warmPlace, stopWarmPlace } from "../../core/place.js";
import * as S from "../../core/state.js";
import { addDocument, checkPass, addPass, toast, markPicking, setPref, setDraft, clearDraft } from "../../core/index.js";
import { DocCamera, readStill, findBarcode } from "./camera.jsx";
import { IdFlow, ID_CHOICES, recordFrom } from "./ids.jsx";
import { CardFlow, cardTapReader, readFrontEitherWay } from "./cards.jsx";
import { Review, Step, PhotoChoice, canvasBlob, versionOf, PAPER_SHARE } from "./review.jsx";
import { PassCheck } from "./passes.jsx";
import { looksLikePass } from "@humid/wallet";
import { newRecord } from "@humid/idscan";
import { DEMO_BUILD } from "../../core/config.js";

/* ---------------- opening and closing ---------------- */

const seen = (kind) => !!S.prefs.value.readySeen?.[kind];
const markSeen = (kind) => { if (!seen(kind)) setPref({ readySeen: { ...(S.prefs.value.readySeen || {}), [kind]: true } }); };

/** The first step for a kind: its camera, or the "what to show" screen the first time. */
function firstStep(kind) {
  if (kind === "card") return seen("card") ? { at: "cardcam" } : { at: "ready", kind: "card" };
  if (kind === "id") return { at: "idcam" };
  if (kind === "pass" || kind === "file") return { at: "pick" };
  return seen("photo") ? { at: "camera" } : { at: "ready", kind: "photo" };
}

/** Open the Add flow (the FAB, the empty vault's button). `kind` skips straight to that kind. */
let opened = 0;
export function openAdd(kind) { S.push.value = { type: "add", kind: kind || null, n: ++opened }; }
const closeAdd = () => { clearDraft(); if (S.push.value?.type === "add") S.push.value = null; };

/** The picker's choices, in order: the last-used kind first. */
function picks() {
  const all = [
    { kind: "id", icon: "idcard", title: "ID", sub: "Driver's license, passport, ID card or permit. HumID tells which from the photo.", go: "id" },
    { kind: "card", icon: "card", title: "Payment card", sub: "Credit or debit. Scan the front, tap it, or type it. Never the PIN.", go: "card" },
    { kind: "pass", icon: "ticket", title: "Wallet pass", sub: "A boarding pass, ticket or membership from Apple Wallet (.pkpass). Checked against its issuer.", go: "pass" },
    { kind: "photo", icon: "camera", title: "Photo", sub: "Any page or card. HumID finds it and straightens it.", go: "photo" },
    { kind: "file", icon: "file", title: "File", sub: "PDF, image, any type up to 50 MB.", go: "file" },
  ];
  const last = S.prefs.value.lastKind;
  return last ? [...all.filter((c) => c.kind === last).map((c) => ({ ...c, featured: true })), ...all.filter((c) => c.kind !== last)] : all;
}

/* ---------------- drafts ---------------- */

/** The draft to keep for a step, and which keys hold pictures. */
function draftOf(step, inner) {
  if (step.at === "photo") return { state: { at: "photo", shape: step.shape, pick: step.pick, shot: step.shot, ...inner }, images: ["shot"] };
  if (step.at === "file") return { state: { at: "file", file: step.file, ...inner }, images: [] };
  if (step.at === "pass") return { state: { at: "pass", file: step.file, check: step.check, ...inner }, images: [] };
  if (step.at === "id" && inner?.rec) { const { images, ...rec } = inner.rec; return { state: { at: "id", inner: { ...inner, rec }, recImages: images }, images: ["recImages"] }; }
  if (step.at === "card" && inner?.rec) { const { images, ...rec } = inner.rec; return { state: { at: "card", inner: { ...inner, rec }, recImages: images }, images: ["recImages"] }; }
  return null;
}

/** A kept draft → the step to resume at (the pictures may have been wiped meanwhile). */
function fromDraft(d) {
  const s = d?.state;
  if (!s) return null;
  if (s.at === "photo") return s.shot ? { at: "photo", shot: s.shot, shape: s.shape, pick: s.pick, resume: { name: s.name, tags: s.tags } } : null;
  if (s.at === "file") return s.file ? { at: "file", file: s.file, resume: { name: s.name, tags: s.tags } } : null;
  if (s.at === "pass") return s.file ? { at: "pass", file: s.file, check: s.check || { state: "checking" }, recheck: !s.check?.ok, resume: { name: s.name, tags: s.tags } } : null;
  if (s.at === "id" && s.inner?.rec) { const rec = { ...s.inner.rec, images: s.recImages || {} }; return { at: "id", start: { rec, step: s.recImages ? s.inner.step : "capture", name: s.inner.name, tags: s.inner.tags } }; }
  if (s.at === "card" && s.inner?.rec) { const rec = { ...s.inner.rec, images: s.recImages || {} }; return { at: "card", start: { rec, form: s.inner.form, name: s.inner.name, tags: s.inner.tags } }; }
  return null;
}

/* ---------------- the flow ---------------- */

export function Add() {
  const p = S.push.value;
  if (p?.type !== "add") return null;
  return <AddFlow key={p.n || "draft"} open={p} />;
}

function AddFlow({ open }) {
  const [step, setStep] = useState(() => (open.draft && fromDraft(open.draft)) || firstStep(open.kind));
  const [nfc, setNfc] = useState(null);
  const [label, setLabel] = useState(null);
  const [inner, setInner] = useState(null);           // what the step inside is holding (for the draft)
  const chooser = useRef(null);
  const current = useRef(null);
  const when = useRef(null);
  const from = useRef("close");                       // where Back from a sub-step returns to: close | pick | camera | a review step
  const barSeen = useRef(0);
  const looks = useRef(0);
  useEffect(() => { cardTapReader().then(setNfc); }, []);
  // a location fix is usually ready by the time the review is (only where the permission is already granted: this never asks early)
  useEffect(() => { if (step.at === "camera" || step.at === "idcam" || step.at === "cardcam") warmPlace(); }, [step.at]);
  useEffect(() => () => stopWarmPlace(), []);
  useEffect(() => {
    if (open.draft && step.at === "pass" && step.recheck) checkPass(step.file).then((r) => setStep((s) => (s.at === "pass" && s.file === step.file ? { ...s, check: r, recheck: false } : s)));
    if (open.draft) toast("Picked up where you left off.");
  }, []);
  // The draft follows the flow. Steps with nothing worth keeping clear it.
  useEffect(() => {
    const d = draftOf(step, inner);
    if (d) setDraft("add", d.state, { images: d.images }); else clearDraft();
  }, [step, inner]);

  const go = (next, origin) => { from.current = origin ?? step; setInner(null); setStep(next); };
  const back = () => {
    const f = from.current;
    if (f === "close") return closeAdd();
    if (f === "pick") return go({ at: "pick" }, "close");
    if (f === "camera") return go(firstStep("photo"), "close");
    if (f === "cardcam") return go(firstStep("card"), "close");
    if (typeof f === "object") return go(f, f.from ?? "close"); // a review the picker was opened from (UX-23)
    closeAdd();
  };
  const choose = (accept) => { markPicking(); chooser.current.accept = accept || ""; chooser.current.click(); };

  /* ---------------- the camera ---------------- */

  const looked = ({ look, quad, video }) => {
    let bar = Date.now() - barSeen.current < 1500;
    if (look?.found && quad && !bar && ++looks.current % 3 === 0) {
      try {
        const W = video.videoWidth, H = video.videoHeight;
        if (findBarcode(video, W, H)) { barSeen.current = Date.now(); bar = true; }
      } catch { /* a guess */ }
    }
    const l = liveLabel(look, { barcode: bar });
    setLabel((p) => (p?.text === l?.text ? p : l));
  };

  /**
   * The photo's taken. Look at it, cheapest first, and say where it goes. Throws keep the
   * camera open with the reason; the returned function runs once the tick has shown.
   *   intent  "any" (the Add camera) or "id" (the picker's ID entry: a kind is always chosen)
   */
  async function photographed(res, intent = "any") {
    when.current = new Date();
    const shape = res.straightened ? shapeOf(res.canvas.width, res.canvas.height) : "page";
    let found = null;
    if (res.barcode && idKindFrom({ barcode: res.barcode })) {
      const card = res.canvas.height > res.canvas.width ? rotateCanvas(res.canvas, 90) : res.canvas;
      found = { kind: "driver_license", side: "back", canvas: card, barcode: res.barcode };
    } else if (res.mrz?.valid) {
      found = { kind: idKindFrom({ mrz: res.mrz }) || "passport", side: "front", canvas: res.canvas, mrz: res.mrz, consensus: res.consensus };
    } else if (res.straightened && shape === "card") {
      const card = res.canvas.height > res.canvas.width ? rotateCanvas(res.canvas, 90) : res.canvas;
      res = { ...res, canvas: card };
      const r = await readStill(card, { barcode: true }, "id1", res.original);
      if (r.barcode && idKindFrom({ barcode: r.barcode })) found = { kind: "driver_license", side: "back", canvas: card, barcode: r.barcode };
      else if (intent === "any") {
        const c = await readFrontEitherWay(card);
        if (c.r?.pan) found = { card: { canvas: c.canvas, read: c.r } };
      }
    } else if (res.straightened && shape === "page-td3") {
      const band = grayOf(grab(res.canvas, { x: 0, y: Math.round(res.canvas.height * 0.66), w: res.canvas.width, h: Math.round(res.canvas.height * 0.34) }), 400);
      if (mrzBandLikely(band)) {
        const r = await readStill(res.canvas, { mrz: true }, "td3", null, { tryFlip: true });
        if (r.mrz?.valid) found = { kind: idKindFrom({ mrz: r.mrz }) || "passport", side: "front", canvas: r.flipped ? rotateCanvas(res.canvas, 180) : res.canvas, mrz: r.mrz, consensus: r.consensus };
      }
    }
    if (DEMO_BUILD) globalThis.__humidRoute = { shape, found: found ? (found.card ? "card" : found.kind) : "photo" };
    if (found?.card) { markSeen("card"); return () => go({ at: "card", start: { front: found.card } }, "camera"); }
    if (found) {
      const { rec, note } = await recordFrom(found).catch(() => { throw new Error("Couldn't save that photo. Try again, or choose one with Photo."); });
      return () => go({ at: "id", start: { rec, note, step: "auto" } }, intent === "id" ? "pick" : "camera");
    }
    if (intent === "id") return () => go({ at: "idpick", shot: res }, "pick"); // which ID is it? the person says
    markSeen("photo");
    // a straightened page also gets a clean scan. It is made in the background (off the main thread): the
    // review opens now, says whether the scan is suggested (a quick look at a small copy), and offers the
    // scan itself the moment it exists. Seal waits for it only if it is chosen.
    if (res.straightened) {
      try {
        const page = res.canvas;
        // started a moment from now: reading the page out of its canvas is main-thread work, and the review should be on screen first
        const cleanP = new Promise((r) => setTimeout(r, 350)).then(() => cleanCanvasAsync(page)).then((c) => c.canvas);
        cleanP.catch(() => {}); // the review handles a failure (low memory: the straightened photo is still offered)
        res = { ...res, cleanSuggested: paperOf(res.canvas) >= PAPER_SHARE, cleanP };
      } catch { /* low memory: the straightened photo is still offered */ }
    }
    return () => go({ at: "photo", shot: res, shape, pick: { which: !res.changed ? "original" : res.cleanSuggested ? "clean" : "proposed", turn: 0 } }, "camera");
  }

  /* ---------------- a file ---------------- */

  const onFile = (e) => {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    e.currentTarget.accept = "";
    if (!f) return;
    current.current = f;
    const origin = step.at === "pick" ? "pick" : step.at === "ready" ? "close" : "camera";
    if (looksLikePass(f)) {
      go({ at: "pass", file: f, check: { state: "checking" } }, origin);
      checkPass(f).then((r) => { if (current.current === f) setStep((s) => (s.at === "pass" && s.file === f ? { ...s, check: r } : s)); });
      return;
    }
    go({ at: "file", file: f }, origin);
  };

  /* ---------------- the picker ---------------- */

  async function picked(c, shot) {
    if (c.go === "id") {
      if (shot) return go({ at: "idpick", shot }, "pick");
      return go({ at: "idcam" }, "pick");
    }
    if (c.go === "card") {
      if (shot) { const r = await readFrontEitherWay(shot.canvas); return go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "pick"); }
      return go(firstStep("card"), "pick");
    }
    if (c.go === "pass") return choose(".pkpass,application/vnd.apple.pkpass");
    if (c.go === "file") return choose("");
    go(firstStep("photo"), "pick");
  }

  /** The ID kind, said by the person because the photo didn't say it. */
  async function pickedId(c, shot) {
    if (shot) {
      try {
        const { rec, note } = await recordFrom({ kind: c.kind, side: "front", canvas: shot.canvas });
        return go({ at: "id", start: { rec, note: note || { tone: "ok", text: "Front saved." }, step: "capture" } }, "pick");
      } catch { toast("Couldn't keep that photo. Scan it again.", "warn"); }
    }
    go({ at: "id", start: { rec: newRecord(c.kind), step: "capture" } }, "pick");
  }

  /* ---------------- render ---------------- */

  const toPick = (shot) => go({ at: "pick", shot }, step.at === "camera" || step.at === "idcam" ? "camera" : "close");
  const extra = { text: "It's something else", icon: "folder", onClick: () => toPick() };
  const tools = <MoreTools nfc={nfc} onFile={() => choose("")} onType={() => go({ at: "card", start: {} }, "camera")} onTap={() => go({ at: "card", start: { tap: true } }, "camera")} />;

  return (
    <>
      <input ref={chooser} id="add-file" type="file" hidden onChange={onFile} />
      {step.at === "ready" && <Ready kind={step.kind} nfc={nfc} onBack={() => (from.current === "pick" ? go({ at: "pick" }, "close") : closeAdd())}
        onStart={() => go({ at: step.kind === "card" ? "cardcam" : "camera" }, from.current)}
        onType={() => go({ at: "card", start: {} }, "close")} onTap={() => go({ at: "card", start: { tap: true } }, "close")}
        onFile={() => choose("")} onPick={() => go({ at: "pick" }, "close")} />}
      {step.at === "camera" && (
        <DocCamera shape="full" native title="Add to your vault" hint="Point the camera at an ID, a card or a document. It finds the edges by itself."
          onCancel={() => (from.current === "pick" ? go({ at: "pick" }, "close") : closeAdd())} onDone={(r) => photographed(r, "any")} onLook={looked}
          lead={label?.text || null} extra={extra} tools={tools} />
      )}
      {step.at === "idcam" && (
        <DocCamera shapes={["id1", "td3"]} side="back" read={{ barcode: true, mrz: true }} eyebrow="ID" title="Scan the ID" hint="Line the ID up inside the outline, either side. A license barcode or the lines of <<< read by themselves."
          onCancel={() => go({ at: "pick" }, "close")} onDone={(r) => photographed(r, "id")} onLook={looked} lead={label?.text || null} />
      )}
      {step.at === "cardcam" && (
        <DocCamera kind="card" side="front" shape="id1" eyebrow="Payment card" title="The front of the card" hint="Line the card up inside the outline, number side up. Never the PIN."
          onCancel={() => (from.current === "pick" ? go({ at: "pick" }, "close") : closeAdd())}
          onDone={async ({ canvas }) => { const r = await readFrontEitherWay(canvas); markSeen("card"); return () => go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "cardcam"); }} />
      )}
      {step.at === "pick" && (
        <Step title="What are you adding?" onBack={back}>
          <div class="kinds">
            {picks().map((c) => (
              <button class={`kind${c.featured ? " featured" : ""}`} onClick={() => picked(c, step.shot)}><span class="ico"><Icon name={c.icon} /></span><span><strong>{c.title}{c.featured ? " · last time" : ""}</strong><span>{c.sub}</span></span><Icon name="chevron" /></button>
            ))}
          </div>
          <p class="fine" style={{ marginTop: 14 }}>Reading happens on this phone. Photos and details are sealed here before anything is sent.</p>
        </Step>
      )}
      {step.at === "idpick" && (
        <Step eyebrow="ID" title="Which ID is it?" onBack={() => go({ at: "pick", shot: step.shot }, "close")}>
          {step.shot && <Banner icon="check" title="Photo kept" text="It'll be the front. Say which document it is so the right details are asked for." />}
          <div class="kinds">
            {ID_CHOICES.map((c) => (
              <button class="kind" onClick={() => pickedId(c, step.shot)}><span class="ico"><Icon name={c.icon} /></span><span><strong>{c.title}</strong><span>{c.sub}</span></span><Icon name="chevron" /></button>
            ))}
          </div>
        </Step>
      )}
      {step.at === "photo" && <PhotoReview step={step} setStep={setStep} when={when} onBack={back} onDraft={setInner}
        onRetake={() => go({ at: "camera" }, "close")} onPick={() => go({ at: "pick", shot: step.shot }, { ...step, from: from.current })} />}
      {step.at === "file" && <FileReview step={step} onBack={back} onDraft={setInner} onAnother={() => choose("")} onPick={() => go({ at: "pick" }, { ...step, from: from.current })} />}
      {step.at === "pass" && <PassReview step={step} setStep={setStep} onBack={back} onDraft={setInner} onAnother={() => choose(".pkpass,application/vnd.apple.pkpass")} />}
      {step.at === "id" && <IdFlow key={step.start.rec.createdAt} start={step.start} onExit={back} onDraft={setInner} />}
      {step.at === "card" && <CardFlow key={`card-${step.start.rec?.createdAt || ""}`} start={step.start} onExit={back} onDraft={setInner} />}
    </>
  );
}

/** The camera bar's extras, folded into one chip: File · Type a card · Tap a card. */
function MoreTools({ nfc, onFile, onType, onTap }) {
  const [open, setOpen] = useState(false);
  if (!open) return <button class="dc-tool" aria-expanded="false" onClick={() => setOpen(true)}><Icon name="more" /><span>More</span></button>;
  return (
    <>
      <button class="dc-tool" onClick={onFile}><Icon name="file" /><span>File</span></button>
      <button class="dc-tool" onClick={onType}><Icon name="pencil" /><span>Type a card</span></button>
      {nfc?.available && <button class="dc-tool" onClick={onTap}><Icon name="nfc" /><span>{nfc.kind === "reader" ? "Read a chip" : "Tap a card"}</span></button>}
      <button class="dc-tool" aria-expanded="true" aria-label="Fewer options" onClick={() => setOpen(false)}><Icon name="x" /></button>
    </>
  );
}

/* ---------------- before the camera, once ---------------- */

/** What to hold up and one clear "Start camera". Shown until the first capture of this kind on this device. */
function Ready({ kind, nfc, onBack, onStart, onType, onTap, onFile, onPick }) {
  const g = guideFor(kind);
  return (
    <Step eyebrow={g.eyebrow} title={g.title} onBack={onBack}>
      <Banner icon={kind === "card" ? "card" : "camera"} title="What to show" text={g.hold} />
      <p class="small muted">{LIGHT_TIP}</p>
      <div class="actions">
        <button class="btn primary block" data-start-camera onClick={onStart}><Icon name="camera" />Start camera</button>
        {kind === "card" && <button class="btn ghost block" onClick={onType}><Icon name="pencil" />Type it instead</button>}
        {kind === "card" && nfc?.available && <button class="btn ghost block" onClick={onTap}><Icon name="nfc" />{nfc.kind === "reader" ? "Read a chip" : "Tap the card"}</button>}
        {kind === "photo" && <button class="btn ghost block" onClick={onFile}><Icon name="file" />Choose a file or photo instead</button>}
        {onPick && <button class="btn quiet block" onClick={onPick}><Icon name="folder" />It's something else</button>}
      </div>
      <p class="fine" style={{ marginTop: 14 }}>The camera stays on this phone and stops when you leave this screen. This screen shows only until your first {kind === "card" ? "card" : "photo"}.</p>
    </Step>
  );
}

/* ---------------- the reviews ---------------- */

/** After a seal: remember the kind, close the flow. */
function sealed(kind) { setPref({ lastKind: kind }); clearDraft(); S.push.value = null; }

function PhotoReview({ step, setStep, when, onBack, onRetake, onPick, onDraft }) {
  const [name, setName] = useState(() => step.resume?.name ?? "");
  const [tags, setTags] = useState(() => step.resume?.tags || []);
  const [busy, setBusy] = useState(false);
  const { shot, pick } = step;
  const setPick = (p) => setStep((s) => ({ ...s, pick: p }));
  useEffect(() => { onDraft({ name, tags }); }, [name, tags]);
  // The clean scan is made in the background (photographed(), above): take it in when it arrives.
  useEffect(() => {
    const p = shot.cleanP;
    if (!p) return;
    let gone = false;
    p.then(
      (clean) => { if (!gone) setStep((s) => (s.at === "photo" && s.shot === shot ? { ...s, shot: { ...shot, clean, cleanP: null } } : s)); },
      () => { if (!gone) setStep((s) => (s.at === "photo" && s.shot === shot ? { ...s, shot: { ...shot, cleanP: null, cleanSuggested: false }, pick: s.pick.which === "clean" ? { ...s.pick, which: "proposed" } : s.pick } : s)); },
    );
    return () => { gone = true; };
  }, [shot]);
  const waiting = !!shot.cleanP && pick.which === "clean"; // the version chosen is still being made
  // Encoded ahead, while it is read: what Seal needs is then already a JPEG (a 2600 px page takes a moment to encode).
  const ahead = useRef({ key: "", p: null });
  useEffect(() => {
    if (waiting) return;
    const key = `${pick.which}:${pick.turn}:${shot.clean ? 1 : 0}`;
    if (ahead.current.key === key) return;
    const run = () => { ahead.current = { key, p: canvasBlob(versionOf(shot, pick.which, pick.turn), 0.9).catch(() => null) }; };
    ahead.current = { key: "", p: null };
    const t = setTimeout(run, 900); // after the preview has been drawn
    return () => clearTimeout(t);
  }, [shot, pick.which, pick.turn, waiting]);
  useEffect(() => () => { ahead.current = { key: "", p: null }; }, []);
  async function seal(place) {
    if (busy || waiting) return;
    setBusy(true);
    try {
      const key = `${pick.which}:${pick.turn}:${shot.clean ? 1 : 0}`;
      const blob = (ahead.current.key === key && await ahead.current.p) || await canvasBlob(versionOf(shot, pick.which, pick.turn), 0.9);
      ahead.current = { key: "", p: null };
      const t = when.current || new Date();
      const tag = { original: "", clean: " (scan)", proposed: " (straightened)" }[pick.which] ?? "";
      const f = new File([blob], `Photo ${t.toLocaleDateString()} ${t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${tag}.jpg`, { type: "image/jpeg" });
      const ok = await addDocument({ file: f, name: name.trim() || `Photo ${t.toLocaleDateString()}`, tags, place });
      if (ok) sealed("photo");
    } catch (e) { toast(e?.message || "Couldn't save that photo. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Step eyebrow="Photo" title="Review, then seal" onBack={onBack}>
      <Review kind="photo" name={name} setName={setName} focusName tags={tags} setTags={setTags}
        preview={<PhotoChoice shot={shot} which={pick.which} turn={pick.turn} onChange={setPick} onRetake={onRetake} />}
        note={step.shape === "card" ? <p class="small muted">Looks like a card, but nothing could be read from it. It's kept as a photo; <button class="linklike" type="button" onClick={onPick}>say what it is</button> to file it as an ID or a payment card.</p> : null}
        onChangeKind={onPick} onSeal={seal} disabled={busy || waiting}
        secondary={{ label: "Retake", onClick: onRetake }}
        fine="One check seals it on this phone. Only the version shown is kept." />
    </Step>
  );
}

function FileReview({ step, onBack, onAnother, onPick, onDraft }) {
  const { file } = step;
  const [name, setName] = useState(() => step.resume?.name ?? (file.name.replace(/\.[a-z0-9]{1,6}$/i, "").replace(/[_-]+/g, " ").slice(0, 80) || "Document"));
  const kind = kindFromType(file.type, file.name) === "photo" ? "photo" : "file";
  const [tags, setTags] = useState(() => step.resume?.tags || suggestTags(kind, file.name));
  const [busy, setBusy] = useState(false);
  useEffect(() => { onDraft({ name, tags }); }, [name, tags]);
  async function seal(place) {
    if (busy) return;
    setBusy(true);
    try {
      const f = looksLikePass(file) ? new File([file], file.name, { type: "application/octet-stream" }) : file;
      const ok = await addDocument({ file: f, name, tags, place });
      if (ok) sealed(kind);
    } catch (e) { toast(e?.message || "Couldn't seal that file. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Step eyebrow={kind === "photo" ? "Photo" : "File"} title="Review, then seal" onBack={onBack}>
      <Review kind={kind} name={name} setName={setName} tags={tags} setTags={setTags}
        preview={(
          <div class="row-x">
            <span class="icon-btn" style={{ width: 64, height: 64, borderRadius: 18, background: "var(--surface-3)", color: "var(--text-2)" }}><Icon name={kindIcon(file.type)} /></span>
            <div class="grow"><div style={{ fontWeight: 600, overflowWrap: "anywhere" }}>{file.name}</div><div class="muted small">{fmtSize(file.size)} · {file.type || "file"}</div></div>
          </div>
        )}
        onChangeKind={onPick} onSeal={seal} disabled={busy}
        secondary={{ label: "Choose another", onClick: onAnother }}
        fine="One check seals it on this phone. The original file isn't kept." />
    </Step>
  );
}

function PassReview({ step, setStep, onBack, onAnother, onDraft }) {
  const { file, check } = step;
  const [typed, setName] = useState(step.resume?.name ?? null);
  const name = typed ?? (check?.ok ? check.result.pass.description || check.result.pass.organization || "Pass" : "Pass");
  const [tags, setTags] = useState(() => step.resume?.tags || []);
  const [busy, setBusy] = useState(false);
  useEffect(() => { onDraft({ name: typed, tags }); }, [typed, tags]);
  const plain = () => setStep({ at: "file", file });
  async function seal(place) {
    if (busy || !check?.ok) return;
    setBusy(true);
    try { const ok = await addPass({ checked: check, name, tags, place }); if (ok) sealed("pass"); }
    catch (e) { toast(e?.message || "Couldn't seal that pass. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Step eyebrow="Wallet pass" title="Review, then seal" onBack={onBack}>
      <Review kind="pass" name={name} setName={setName} tags={tags} setTags={setTags}
        preview={<PassCheck check={check} onPlain={plain} onAnother={onAnother} />}
        onSeal={seal} disabled={busy || !check?.ok}
        secondary={{ label: "Choose another", onClick: onAnother }}
        fine="One check seals the signed original on this phone, so it can go back into Wallet unchanged." />
    </Step>
  );
}

