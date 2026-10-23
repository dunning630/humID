// Add to your vault (3.0.1): what it is, first. "Add" opens "What are you adding?", which lists
// each kind of document directly (Passport, Driver's license, State ID, a green card, another
// card, a payment card, a document page, a photo, a Wallet pass, a file), the last-used one on top.
// Picking one opens the camera made for it at once, with its outline (core/guide.js) and its
// readers already loading from the tap (the barcode reader for a license, the reader for the lines
// of <<< for a passport), so the camera is ready for that document when it opens. No camera
// runs before a kind is picked, and nothing guesses: the phone's own document scanner, and its
// four-point outline, isn't used here. Every kind ends in the one Review (review.jsx), then Seal.
//
// What the person was in the middle of survives a lock (core/drafts.js): the flow writes
// its draft as it goes, and main.jsx hands it back as S.push.value.draft after unlock.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon, kindIcon } from "../../brand/icons.jsx";
import { Banner } from "../../ui/kit.jsx";
import { fmtSize } from "../../ui/format.js";
import { suggestTags, kindFromType } from "../../core/categories.js";
import { shapeOf } from "../../core/addroute.js";
import { cleanCanvasAsync, paperOf, warmScan, modesForKind } from "../../core/scan.js";
import { warmPlace, stopWarmPlace } from "../../core/place.js";
import * as S from "../../core/state.js";
import { addDocument, checkPass, addPass, toast, markPicking, setPref, setDraft, clearDraft } from "../../core/index.js";
import { DocCamera } from "./camera.jsx";
import { IdFlow, ID_CHOICES, recordFrom } from "./ids.jsx";
import { CardFlow, cardTapReader, readFrontEitherWay, frontSaid } from "./cards.jsx";
import { Review, Step, PhotoChoice, canvasBlob, versionOf, PAPER_SHARE } from "./review.jsx";
import { PassCheck } from "./passes.jsx";
import { looksLikePass } from "@humid/wallet";
import { newRecord } from "@humid/idscan";

/* ---------------- opening and closing ---------------- */

const ID_KINDS = ID_CHOICES.map((c) => c.kind);

/** Where a picked kind starts: its own camera, straight away. */
function firstStep(key) {
  if (ID_KINDS.includes(key)) return { at: "id", start: { rec: newRecord(key), step: "camera" } };
  if (key === "card") return { at: "cardcam" };
  if (key === "page") return { at: "pagecam" };
  if (key === "photo") return { at: "camera" };
  return { at: "pick" };
}

/** Open the Add flow (the + button, the empty vault's button). It opens on the picker. */
let opened = 0;
export function openAdd(kind) { S.push.value = { type: "add", kind: kind || null, n: ++opened }; }
const closeAdd = () => { clearDraft(); if (S.push.value?.type === "add") S.push.value = null; };

/** Start loading what a kind's camera will read, the moment it is touched (before the camera opens). */
const warmed = new Set();
function warmFor(key) {
  if (warmed.has(key)) return;
  warmed.add(key);
  for (const m of modesForKind(key)) warmScan(m);
}

/** The picker's choices, in groups; the last-used kind is also shown first. */
function groups() {
  const ids = ID_CHOICES.map((c) => ({ key: c.kind, icon: c.icon, title: c.title, sub: c.sub }));
  const all = [
    { title: "IDs", items: ids.filter((c) => c.key !== "other") },
    { title: "Cards", items: [
      { key: "card", icon: "card", title: "Payment card", sub: "Credit or debit. Scan the front, tap it, or type it. Never the PIN." },
      ids.find((c) => c.key === "other"),
    ] },
    { title: "Documents and more", items: [
      { key: "page", icon: "scan", title: "Document", sub: "A letter, form or certificate, one page at a time." },
      { key: "photo", icon: "camera", title: "Photo", sub: "Anything else. Take the picture yourself." },
      { key: "pass", icon: "ticket", title: "Wallet pass", sub: "A boarding pass, ticket or membership from Apple Wallet (.pkpass). Checked against its issuer." },
      { key: "file", icon: "file", title: "File", sub: "PDF, image, any type up to 50 MB." },
    ] },
  ];
  const last = S.prefs.value.lastKind;
  const lastItem = last && all.flatMap((g) => g.items).find((c) => c.key === last);
  return lastItem ? [{ title: "Last time", items: [{ ...lastItem, featured: true }] }, ...all] : all;
}

/* ---------------- drafts ---------------- */

/** The draft to keep for a step, and which keys hold pictures. */
function draftOf(step, inner) {
  if (step.at === "photo") return { state: { at: "photo", kind: step.kind, shape: step.shape, pick: step.pick, shot: step.shot, ...inner }, images: ["shot"] };
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
  if (s.at === "photo") return s.shot ? { at: "photo", kind: s.kind, shot: s.shot, shape: s.shape, pick: s.pick, resume: { name: s.name, tags: s.tags } } : null;
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
  const [step, setStep] = useState(() => (open.draft && fromDraft(open.draft)) || (open.kind ? firstStep(open.kind) : { at: "pick" }));
  const [nfc, setNfc] = useState(null);
  const [inner, setInner] = useState(null);           // what the step inside is holding (for the draft)
  const chooser = useRef(null);
  const current = useRef(null);
  const when = useRef(null);
  const from = useRef(open.kind ? "close" : "pick");  // where Back from a step returns to: close | pick | cardcam | a review step
  useEffect(() => { cardTapReader().then(setNfc); }, []);
  // a location fix is usually ready by the time the review is (only where the permission is already granted: this never asks early)
  useEffect(() => { if (step.at === "camera" || step.at === "cardcam" || step.at === "pagecam" || step.at === "id") warmPlace(); }, [step.at]);
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
    if (f === "cardcam") return go({ at: "cardcam" }, "pick");
    if (typeof f === "object") return go(f, f.from ?? "pick"); // a review the picker was opened from (UX-23)
    closeAdd();
  };
  const toPicker = () => go({ at: "pick" }, "close");
  const choose = (accept) => { markPicking(); chooser.current.accept = accept || ""; chooser.current.click(); };

  /* ---------------- the cameras ---------------- */

  /** A photo (the whole view) or a document page (the page outline): to the photo review, with a clean scan made alongside. */
  function photographed(res, kind) {
    when.current = new Date();
    const shape = kind === "page" ? "page" : res.straightened ? shapeOf(res.canvas.width, res.canvas.height) : "page";
    // a straightened page also gets a clean scan. It is made in the background (off the main
    // thread): the review opens now, says whether the scan is suggested (a quick look at a small
    // copy), and offers the scan itself the moment it exists. Seal waits for it only if it is chosen.
    if (res.straightened) {
      try {
        const page = res.canvas;
        // started a moment from now: reading the page out of its canvas is main-thread work, and the review should be on screen first
        const cleanP = new Promise((r) => setTimeout(r, 350)).then(() => cleanCanvasAsync(page)).then((c) => c.canvas);
        cleanP.catch(() => {}); // the review handles a failure (low memory: the straightened photo is still offered)
        res = { ...res, cleanSuggested: kind === "page" || paperOf(res.canvas) >= PAPER_SHARE, cleanP };
      } catch { /* low memory: the straightened photo is still offered */ }
    }
    return () => go({ at: "photo", kind, shot: res, shape, pick: { which: !res.changed ? "original" : res.cleanSuggested ? "clean" : "proposed", turn: 0 } }, kind === "page" ? "pagecam" : "camera");
  }

  /* ---------------- a file ---------------- */

  const onFile = (e) => {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    e.currentTarget.accept = "";
    if (!f) return;
    current.current = f;
    if (looksLikePass(f)) {
      go({ at: "pass", file: f, check: { state: "checking" } }, "pick");
      checkPass(f).then((r) => { if (current.current === f) setStep((s) => (s.at === "pass" && s.file === f ? { ...s, check: r } : s)); });
      return;
    }
    go({ at: "file", file: f }, "pick");
  };

  /* ---------------- the picker ---------------- */

  /** A kind picked. `shot`: a photo already taken (a review's "say what it is"), kept as that kind's front. */
  async function picked(c, shot) {
    if (ID_KINDS.includes(c.key)) {
      if (shot) {
        try {
          const { rec, note } = await recordFrom({ kind: c.key, side: "front", canvas: shot.canvas });
          return go({ at: "id", start: { rec, note: note || { tone: "ok", text: "Front saved." }, step: "capture" } }, "pick");
        } catch { toast("Couldn't keep that photo. Scan it again.", "warn"); }
      }
      return go(firstStep(c.key), "pick");
    }
    if (c.key === "card") {
      if (shot) { const r = await readFrontEitherWay(shot.canvas); return go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "pick"); }
      return go({ at: "cardcam" }, "pick");
    }
    if (c.key === "pass") return choose(".pkpass,application/vnd.apple.pkpass");
    if (c.key === "file") return choose("");
    if (shot && step.back) return go(step.back, step.back.from ?? "pick"); // a photo or a page: it already is one
    go(firstStep(c.key), "pick");
  }

  /* ---------------- render ---------------- */

  // the payment card's other ways in, on the step card (tools on the bar would move the outline)
  const cardWays = (origin) => [
    { text: "Type it", icon: "pencil", onClick: () => go({ at: "card", start: {} }, origin) },
    ...(nfc?.available ? [{ text: nfc.kind === "reader" ? "Read a chip" : "Tap the card", icon: "nfc", onClick: () => go({ at: "card", start: { tap: true } }, origin) }] : []),
  ];

  return (
    <>
      <input ref={chooser} id="add-file" type="file" hidden onChange={onFile} />
      {step.at === "pick" && (
        <Step title="What are you adding?" onBack={step.back ? () => go(step.back, step.back.from ?? "pick") : closeAdd}>
          {step.shot && <Banner icon="check" title="Photo kept" text="It'll be the front. Say what it is so the right details are asked for." />}
          {groups().map((g) => (
            <section class="kinds-group" aria-label={g.title}>
              <h2 class="eyebrow">{g.title}</h2>
              <div class="kinds">
                {g.items.map((c) => (
                  <button class={`kind${c.featured ? " featured" : ""}`} data-kind={c.key} onPointerDown={() => warmFor(c.key)} onClick={() => { warmFor(c.key); picked(c, step.shot); }}>
                    <span class="ico"><Icon name={c.icon} /></span><span><strong>{c.title}</strong><span>{c.sub}</span></span><Icon name="chevron" />
                  </button>
                ))}
              </div>
            </section>
          ))}
          <p class="fine mt-3">Reading happens on this phone. Photos and details are sealed here before anything is sent.</p>
        </Step>
      )}
      {step.at === "camera" && (
        <DocCamera shape="full" eyebrow="Photo" title="Take the photo" hint="Anything you want to keep. Press the round button, or hold steady on a document and it takes the photo by itself."
          onCancel={back} onDone={(res) => photographed(res, "photo")} />
      )}
      {step.at === "pagecam" && (
        <DocCamera kind="page" shape="page" eyebrow="Document" title="One page" hint="Lay the page flat and fill the frame with it. It takes the photo by itself."
          onCancel={back} onDone={(res) => photographed(res, "page")} />
      )}
      {step.at === "cardcam" && (
        <DocCamera kind="card" side="front" shape="id1" expect="card" eyebrow="Payment card" title="The front of the card" hint="Number side up, filling the frame. Never the PIN."
          onCancel={back} extra={cardWays("cardcam")}
          onDone={async ({ canvas }) => { const r = await readFrontEitherWay(canvas); return { result: frontSaid(r.r), next: () => go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "cardcam") }; }} />
      )}
      {step.at === "photo" && <PhotoReview step={step} setStep={setStep} when={when} onBack={back} onDraft={setInner}
        onRetake={() => go({ at: step.kind === "page" ? "pagecam" : "camera" }, "pick")} onPick={() => go({ at: "pick", shot: step.shot, back: { ...step, from: from.current } }, "close")} />}
      {step.at === "file" && <FileReview step={step} onBack={back} onDraft={setInner} onAnother={() => choose("")} onPick={() => go({ at: "pick", back: { ...step, from: from.current } }, "close")} />}
      {step.at === "pass" && <PassReview step={step} setStep={setStep} onBack={back} onDraft={setInner} onAnother={() => choose(".pkpass,application/vnd.apple.pkpass")} />}
      {step.at === "id" && <IdFlow key={step.start.rec.createdAt} start={step.start} onExit={back} onDraft={setInner} />}
      {step.at === "card" && <CardFlow key={`card-${step.start.rec?.createdAt || ""}`} start={step.start} onExit={back} onDraft={setInner} />}
    </>
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
      if (ok) sealed(step.kind === "page" ? "page" : "photo");
    } catch (e) { toast(e?.message || "Couldn't save that photo. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Step eyebrow={step.kind === "page" ? "Document" : "Photo"} title="Review, then seal" onBack={onBack}>
      <Review kind="photo" name={name} setName={setName} focusName tags={tags} setTags={setTags}
        preview={<PhotoChoice shot={shot} which={pick.which} turn={pick.turn} onChange={setPick} onRetake={onRetake} />}
        note={step.shape === "card" ? <p class="small muted">Looks like a card, but nothing could be read from it. It's kept as a photo; <button class="linklike" type="button" onClick={onPick}>say what it is</button> to file it as an ID or a payment card.</p> : null}
        onChangeKind={onPick} onSeal={seal} disabled={busy || waiting}
        secondary={{ label: "Retake", onClick: onRetake }}
        fine="One live check seals it on this phone. Only the version shown is kept." />
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
        fine="One live check seals it on this phone. The original file isn't kept." />
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
        fine="One live check seals the signed original on this phone, so it can go back into Wallet unchanged." />
    </Step>
  );
}

