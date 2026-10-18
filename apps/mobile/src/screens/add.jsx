// Add to your vault: one flow, choose first. "Add" opens the list of what is being added
// and no camera starts until a kind is chosen. An ID goes to the ID flow, which says what
// to show and starts its camera on one tap (and reads a barcode or MRZ, per kind); a card
// and a photo get a short "what to hold up" screen with Start camera. Once the camera is
// open the photo goes where it belongs: an ID-1 card with a license barcode or a page with an MRZ to
// the ID flow (ids.jsx), a card with a payment number to the card flow (cards.jsx),
// anything else to the photo review. A slim bar on the camera offers a file (a .pkpass
// is checked as a Wallet pass), typing a card, and tapping one where NFC exists. A live
// label says what the camera thinks it sees, with "It's something else" for the picker.
// Detection never blocks: the photo is taken as it always was, then looked at.
import { useEffect, useRef, useState } from "preact/hooks";
import { Icon, kindIcon } from "../icons.jsx";
import { fmtSize } from "../ui.jsx";
import { suggestTags, kindFromType } from "../core/categories.js";
import { shapeOf, liveLabel, mrzBandLikely, idKindFrom, guideFor, LIGHT_TIP } from "../core/addroute.js";
import { cleanCanvas, grayOf, grab, rotateCanvas } from "../core/scan.js";
import * as S from "../core/state.js";
import { addDocument, checkPass, addPass, toast, markPicking } from "../core/controller.js";
import { DocCamera, IdFlow, ID_CHOICES, recordFrom, readStill, findBarcode } from "./ids.jsx";
import { CardFlow, cardTapReader, readFrontEitherWay } from "./cards.jsx";
import { Review, Push, PhotoChoice, canvasBlob, versionOf, PAPER_SHARE } from "./review.jsx";
import { looksLikePass } from "@humid/wallet";
import { newRecord } from "@humid/idscan";
import { PassCheck } from "./passes.jsx";
import { DEMO_BUILD } from "@humid/gate";

/** Open the Add flow (the FAB and the empty vault's button). */
export const openAdd = () => { S.sheet.value = { type: "add" }; };
const closeAdd = () => { if (S.sheet.value?.stage == null) S.sheet.value = null; };

/** The picker's choices: the ID kinds, then the other kinds. */
const PICK = [
  ...ID_CHOICES.map((c) => ({ ...c, go: "id" })),
  { kind: "card", icon: "card", title: "Payment card", sub: "Credit or debit. Scan the front, tap it, or type it. Never the PIN.", go: "card" },
  { kind: "pass", icon: "ticket", title: "Wallet pass", sub: "A boarding pass, ticket or membership from Apple Wallet (.pkpass). Checked against its issuer.", go: "pass" },
  { kind: "photo", icon: "camera", title: "Photo", sub: "Any document or card. HumID finds it and straightens it.", go: "photo" },
  { kind: "file", icon: "file", title: "File", sub: "PDF, image, any type up to 50 MB.", go: "file" },
];

export function Add() {
  const [step, setStep] = useState({ at: "pick" }); // { at: pick | ready | camera | photo | file | pass | id | card, ... }
  const [nfc, setNfc] = useState(null);
  const [label, setLabel] = useState(null);           // what the live view thinks it sees
  const chooser = useRef(null);
  const current = useRef(null);                       // the file on screen: a check that finishes for another one is dropped
  const when = useRef(null);
  const from = useRef("pick");                        // where Back from a sub-step returns to: pick | camera (the photo's ready screen) | readycard
  const barSeen = useRef(0);
  const looks = useRef(0);
  useEffect(() => { cardTapReader().then(setNfc); }, []);

  const go = (next, origin) => { from.current = origin || step.at; setStep(next); };
  const back = () => setStep(from.current === "pick" ? { at: "pick" } : { at: "ready", kind: from.current === "readycard" ? "card" : "photo" });
  const toPick = () => setStep({ at: "pick" });
  const toReady = (kind) => setStep({ at: "ready", kind });
  const choose = (accept) => { markPicking(); chooser.current.accept = accept || ""; chooser.current.click(); };

  /* ---------------- the camera ---------------- */

  /** The live label: from the outline's shape, and a quick look for a barcode on it now and then. */
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
   * The photo's taken. Look at it, cheapest first, and say where it goes. Throws keep
   * the camera open with the reason; the returned function runs once the tick has shown.
   */
  async function photographed(res) {
    when.current = new Date();
    const shape = res.straightened ? shapeOf(res.canvas.width, res.canvas.height) : "page";
    let found = null;
    if (res.straightened && shape === "card") {
      // a card is kept wide, the way the card flows photograph it
      const card = res.canvas.height > res.canvas.width ? rotateCanvas(res.canvas, 90) : res.canvas;
      res = { ...res, canvas: card };
      // a license barcode on an ID-1 card: the ID flow, this side being the back
      const r = await readStill(card, { barcode: true }, "id1", res.original);
      if (r.barcode && idKindFrom({ barcode: r.barcode })) found = { kind: "driver_license", side: "back", canvas: card, barcode: r.barcode };
      else {
        // a payment card's number (read either way up)
        const c = await readFrontEitherWay(card);
        if (c.r?.pan) found = { card: { canvas: c.canvas, read: c.r } };
      }
    } else if (res.straightened && shape === "page-td3") {
      // a passport page: only when the foot of the page looks like an MRZ is the reader loaded
      const band = grayOf(grab(res.canvas, { x: 0, y: Math.round(res.canvas.height * 0.66), w: res.canvas.width, h: Math.round(res.canvas.height * 0.34) }), 400);
      if (mrzBandLikely(band)) {
        const r = await readStill(res.canvas, { mrz: true }, "td3", null, { tryFlip: true });
        if (r.mrz?.valid) found = { kind: idKindFrom({ mrz: r.mrz }) || "passport", side: "front", canvas: r.flipped ? rotateCanvas(res.canvas, 180) : res.canvas, mrz: r.mrz, consensus: r.consensus };
      }
    }
    if (DEMO_BUILD) globalThis.__humidRoute = { shape, found: found ? (found.card ? "card" : found.kind) : "photo" }; // development builds: tests can see the routing
    if (found?.card) return () => go({ at: "card", start: { front: found.card } }, "camera");
    if (found) {
      const { rec, note } = await recordFrom(found).catch(() => { throw new Error("Couldn't save that photo. Try again, or choose one with Photo."); });
      return () => go({ at: "id", start: { rec, note, step: "auto" } }, "camera");
    }
    // a photo: a straightened page also gets a clean scan, made while the camera shows "Saving…"
    if (res.straightened) {
      await new Promise((r) => setTimeout(r, 0));
      try { const c = cleanCanvas(res.canvas); res = { ...res, clean: c.canvas, cleanSuggested: c.paper >= PAPER_SHARE }; }
      catch { /* low memory: the straightened photo is still offered */ }
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
    if (looksLikePass(f)) {
      go({ at: "pass", file: f, check: { state: "checking" } }, step.at === "pick" ? "pick" : "camera");
      checkPass(f).then((r) => { if (current.current === f) setStep((s) => (s.at === "pass" && s.file === f ? { ...s, check: r } : s)); });
      return;
    }
    go({ at: "file", file: f }, step.at === "pick" ? "pick" : "camera");
  };

  /* ---------------- the picker ---------------- */

  /** A choice from the picker. `shot`: a photo already taken, reused as the front where that makes sense. */
  async function picked(c, shot) {
    if (c.go === "id") {
      if (shot) {
        try {
          const { rec, note } = await recordFrom({ kind: c.kind, side: "front", canvas: shot.canvas });
          return go({ at: "id", start: { rec, note: note || { tone: "ok", text: "Front saved." }, step: "capture" } }, "pick");
        } catch { toast("Couldn't keep that photo. Scan it again.", "warn"); }
      }
      return go({ at: "id", start: { rec: newRecord(c.kind), step: "capture" } }, "pick");
    }
    if (c.go === "card") {
      if (shot) { const r = await readFrontEitherWay(shot.canvas); return go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "pick"); }
      return go({ at: "ready", kind: "card" }, "pick");
    }
    if (c.go === "pass") return choose(".pkpass,application/vnd.apple.pkpass");
    if (c.go === "file") return choose("");
    go({ at: "ready", kind: "photo" }, "pick");
  }

  /* ---------------- render ---------------- */

  const tools = (
    <>
      <button class="dc-tool" onClick={() => choose("")}><Icon name="file" /><span>File</span></button>
      <button class="dc-tool" onClick={() => go({ at: "card", start: {} }, "camera")}><Icon name="pencil" /><span>Type a card</span></button>
      {nfc?.available && <button class="dc-tool" onClick={() => go({ at: "card", start: { tap: true } }, "camera")}><Icon name="nfc" /><span>{nfc.kind === "reader" ? "Read a chip" : "Tap a card"}</span></button>}
    </>
  );
  const liveLabelEl = label ? { ...label, action: { text: "It's something else", onClick: () => go({ at: "pick" }, "camera") } } : { icon: "scan", text: "Point it at anything", action: { text: "It's something else", onClick: () => go({ at: "pick" }, "camera") } };

  return (
    <>
      <input ref={chooser} id="add-file" type="file" hidden onChange={onFile} />
      {step.at === "ready" && <Ready kind={step.kind} nfc={nfc} onBack={toPick}
        onStart={() => setStep({ at: step.kind === "card" ? "cardcam" : "camera" })}
        onType={() => go({ at: "card", start: {} }, "readycard")} onTap={() => go({ at: "card", start: { tap: true } }, "readycard")}
        onFile={() => choose("")} />}
      {step.at === "camera" && (
        <DocCamera shape="full" title="Photograph a document" hint="Point the camera at an ID, a card or a document. It finds the edges by itself."
          onCancel={() => toReady("photo")} onDone={photographed} onLook={looked} label={liveLabelEl} tools={tools} />
      )}
      {step.at === "cardcam" && (
        <DocCamera shape="id1" eyebrow="Payment card" title="The front of the card" hint="Fit the card in the frame, number side up. Never the PIN."
          onCancel={() => toReady("card")}
          onDone={async ({ canvas }) => { const r = await readFrontEitherWay(canvas); return () => go({ at: "card", start: { front: { canvas: r.canvas, read: r.r } } }, "readycard"); }} />
      )}
      {step.at === "pick" && (
        <Push title="What are you adding?" onBack={() => (step.shot ? toReady("photo") : closeAdd())} label="What to add">
          <div class="kinds">
            {PICK.map((c) => (
              <button class="kind" onClick={() => picked(c, step.shot)}><span class="ico"><Icon name={c.icon} /></span><span><strong>{c.title}</strong><span>{c.sub}</span></span><Icon name="chevron" /></button>
            ))}
          </div>
          <p class="fine" style={{ marginTop: 14 }}>The camera starts only after you choose. Reading happens on this phone. Photos and details are sealed here before anything is sent.</p>
        </Push>
      )}
      {step.at === "photo" && <PhotoReview step={step} setStep={setStep} when={when} onBack={back} onRetake={() => setStep({ at: "camera" })} onPick={() => go({ at: "pick", shot: step.shot }, "camera")} />}
      {step.at === "file" && <FileReview file={step.file} onBack={back} onAnother={() => choose("")} onPick={() => go({ at: "pick" }, "camera")} />}
      {step.at === "pass" && <PassReview step={step} setStep={setStep} onBack={back} onAnother={() => choose(".pkpass,application/vnd.apple.pkpass")} />}
      {step.at === "id" && <IdFlow key={step.start.rec.createdAt} start={step.start} onExit={back} />}
      {step.at === "card" && <CardFlow key={from.current + step.at} start={step.start} onExit={back} />}
    </>
  );
}

/* ---------------- before the camera ---------------- */

/** What to hold up and one clear "Start camera"; nothing touches the camera until it's tapped. */
function Ready({ kind, nfc, onBack, onStart, onType, onTap, onFile }) {
  const g = guideFor(kind);
  return (
    <Push eyebrow={g.eyebrow} title={g.title} onBack={onBack} label={`Before the camera: ${g.eyebrow}`}>
      <div class="banner" data-ready={kind}><span class="b-ico"><Icon name={kind === "card" ? "card" : "camera"} /></span><div><strong>What to show</strong><span>{g.hold}</span></div></div>
      <p class="small muted" style={{ marginTop: 12 }}>{LIGHT_TIP}</p>
      <div class="actions">
        <button class="btn primary block" data-start-camera onClick={onStart}><Icon name="camera" />Start camera</button>
        {kind === "card" && <button class="btn ghost block" onClick={onType}><Icon name="pencil" />Type it instead</button>}
        {kind === "card" && nfc?.available && <button class="btn ghost block" onClick={onTap}><Icon name="nfc" />{nfc.kind === "reader" ? "Read a chip" : "Tap the card"}</button>}
        {kind === "photo" && <button class="btn ghost block" onClick={onFile}><Icon name="file" />Choose a file or photo instead</button>}
      </div>
      <p class="fine" style={{ marginTop: 14 }}>The camera stays on this phone and stops when you leave this screen.</p>
    </Push>
  );
}

/* ---------------- the reviews ---------------- */

function PhotoReview({ step, setStep, when, onBack, onRetake, onPick }) {
  const [name, setName] = useState(() => `Photo ${(when.current || new Date()).toLocaleDateString()}`);
  const [tags, setTags] = useState([]);
  const [busy, setBusy] = useState(false);
  const { shot, pick } = step;
  const setPick = (p) => setStep((s) => ({ ...s, pick: p }));
  async function seal(place) {
    if (busy) return;
    setBusy(true);
    try {
      const c = versionOf(shot, pick.which, pick.turn);
      const blob = await canvasBlob(c, 0.9);
      const t = when.current || new Date();
      const tag = { original: "", clean: " (scan)", proposed: " (straightened)" }[pick.which] ?? "";
      const f = new File([blob], `Photo ${t.toLocaleDateString()} ${t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${tag}.jpg`, { type: "image/jpeg" });
      await addDocument({ file: f, name, tags, place });
    } catch (e) { toast(e?.message || "Couldn't save that photo. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Push eyebrow="Photo" title="Check it, then seal it" onBack={onBack} busy={S.sheet.value?.stage != null} label="Add a photo">
      <Review kind="photo" name={name} setName={setName} tags={tags} setTags={setTags}
        preview={<PhotoChoice shot={shot} which={pick.which} turn={pick.turn} onChange={setPick} onRetake={onRetake} />}
        note={step.shape === "card" ? <p class="small muted" style={{ marginTop: 8 }}>Looks like a card, but nothing could be read from it. It's kept as a photo; <button class="linklike" type="button" onClick={onPick}>say what it is</button> to file it as an ID or a payment card.</p> : null}
        onChangeKind={onPick} onSeal={seal} disabled={busy}
        secondary={{ label: "Retake", onClick: onRetake }}
        fine="One check seals it on this phone. Only the version shown is kept." />
    </Push>
  );
}

function FileReview({ file, onBack, onAnother, onPick }) {
  const [name, setName] = useState(() => file.name.replace(/\.[a-z0-9]{1,6}$/i, "").replace(/[_-]+/g, " ").slice(0, 80) || "Document");
  const kind = kindFromType(file.type, file.name) === "photo" ? "photo" : "file";
  const [tags, setTags] = useState(() => suggestTags(kind, file.name)); // a suggestion; the person can change it
  const [busy, setBusy] = useState(false);
  async function seal(place) {
    if (busy) return;
    setBusy(true);
    try {
      // a pass that failed its check is kept as an ordinary file, never under the pass type
      const f = looksLikePass(file) ? new File([file], file.name, { type: "application/octet-stream" }) : file;
      await addDocument({ file: f, name, tags, place });
    } catch (e) { toast(e?.message || "Couldn't seal that file. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Push eyebrow={kind === "photo" ? "Photo" : "File"} title="Check it, then seal it" onBack={onBack} busy={S.sheet.value?.stage != null} label="Add a file">
      <Review kind={kind} name={name} setName={setName} tags={tags} setTags={setTags}
        preview={(
          <div class="doc-hero">
            <span class="ico" data-kind={kind} style={{ display: "grid", placeItems: "center", borderRadius: 18, width: 64, height: 64, background: "var(--surface-3)" }}><Icon name={kindIcon(file.type)} /></span>
            <div style={{ minWidth: 0 }}><div class="name" style={{ fontWeight: 600, overflowWrap: "anywhere" }}>{file.name}</div><div class="muted small">{fmtSize(file.size)} · {file.type || "file"}</div></div>
          </div>
        )}
        onChangeKind={onPick} onSeal={seal} disabled={busy}
        secondary={{ label: "Choose another", onClick: onAnother }}
        fine="One check seals it on this phone. The original file isn't kept." />
    </Push>
  );
}

function PassReview({ step, setStep, onBack, onAnother }) {
  const { file, check } = step;
  const [typed, setName] = useState(null); // the name once edited; until then, the pass's own
  const name = typed ?? (check?.ok ? check.result.pass.description || check.result.pass.organization || "Pass" : "Pass");
  const [tags, setTags] = useState([]);
  const [busy, setBusy] = useState(false);
  const plain = () => setStep({ at: "file", file }); // keep a pass that failed its check as an ordinary file
  async function seal(place) {
    if (busy || !check?.ok) return;
    setBusy(true);
    try { await addPass({ checked: check, name, tags, place }); }
    catch (e) { toast(e?.message || "Couldn't seal that pass. Try again.", "error"); }
    finally { setBusy(false); }
  }
  return (
    <Push eyebrow="Wallet pass" title="Check it, then seal it" onBack={onBack} busy={S.sheet.value?.stage != null} label="Add a Wallet pass">
      <Review kind="pass" name={name} setName={setName} tags={tags} setTags={setTags}
        preview={<PassCheck check={check} onPlain={plain} onAnother={onAnother} />}
        onSeal={seal} disabled={busy || !check?.ok}
        secondary={{ label: "Choose another", onClick: onAnother }}
        fine="One check seals the signed original on this phone, so it can go back into Wallet unchanged." />
    </Push>
  );
}
