// Identity documents: scan a driver's license, passport or ID card with the
// camera (and its chip, where there is one), check the details, and seal one
// record into the vault. Also the camera itself (DocCamera), which "Take a
// photo" uses for any document, and the card view for a sealed ID.
import { useEffect, useReducer, useRef, useState } from "preact/hooks";
import { Icon } from "../icons.jsx";
import { Sheet, Steps, ChipAccess } from "../ui.jsx";
import * as S from "../core/state.js";
import { addIdRecord, chipReader, readChipInto, markPicking, toast, saveCopy } from "../core/controller.js";
import {
  KINDS, kindLabel, fieldsFor, newRecord, applyMrz, applyAamva, applyTyped, setImage, title as recordTitle, status as idStatus,
  provenance, fullName, niceName, countryName, regionName, parseAamva, MrzConsensus,
} from "@humid/idscan";
import { barcodeReader, mrzReader, releaseReaders, frameInVideo, grab, imageData, jpeg, imageUrl, fileToCanvas, mrzBand, portraitImage, looksBlank } from "../core/scan.js";
import { analyzeFrame, autoShutter, toGray } from "../core/detect.js";
import { DEMO_BUILD } from "@humid/gate";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- the camera ---------------- */

function cameraError(e) {
  if (e?.name === "NotAllowedError" || e?.name === "SecurityError") return "Camera access is off for HumID. Allow it in your phone's settings, or choose a photo instead.";
  if (e?.name === "NotFoundError" || e?.name === "OverconstrainedError") return "No camera found here. Choose a photo instead.";
  if (e?.name === "NotReadableError") return "Another app is using the camera. Close it and try again, or choose a photo instead.";
  return "The camera couldn't start. Choose a photo instead.";
}

/** Read a still photo: barcode (tried hard) and the MRZ from a few versions of the image, voting. */
async function readStill(c, read, shape) {
  const out = { barcode: null, mrz: null, consensus: false };
  if (read.barcode) {
    try {
      const bc = await barcodeReader();
      out.barcode = (await bc.read(imageData(grab(c, null, 2400))))[0] || null;
    } catch { /* reported as not found */ }
  }
  if (read.mrz && !out.barcode) {
    try {
      const ocr = await mrzReader();
      const vote = new MrzConsensus();
      for (const opts of [{}, { threshold: true }, { scale: 1.3 }]) {
        const r = vote.add(await ocr.read(mrzBand(c, shape, opts)));
        if (r.result) out.mrz = r.result;
        if (r.stable) { out.consensus = true; break; }
      }
      if (!out.mrz) out.mrz = vote.reads.at(-1) || null;
    } catch { /* reported as not found */ }
  }
  return out;
}

/** The document frame in the video's pixels, or the whole frame if the layout gives nothing usable. */
function frameRect(v, el, pad) {
  const r = el ? frameInVideo(v, el, pad) : null;
  return r && r.w >= 64 && r.h >= 40 ? r : null;
}

/**
 * A small grey copy of the area around the on-screen frame (15% margin), and where
 * the frame sits in it, for the auto-capture check (core/detect.js).
 */
function lookAround(v, el) {
  const outer = frameInVideo(v, el, 0.15), inner = frameInVideo(v, el, 0);
  if (!outer || !inner || inner.w < 64 || inner.h < 40) return null;
  const im = toGray(imageData(grab(v, outer, 320)));
  return { im, guide: { x0: (inner.x - outer.x) / outer.w, y0: (inner.y - outer.y) / outer.h, x1: (inner.x + inner.w - outer.x) / outer.w, y1: (inner.y + inner.h - outer.y) / outer.h } };
}

/** With a barcode or MRZ to read: if a document has sat lined up this long and still no read, take the photo anyway. */
const FALLBACK_MS = 9000;

/** A short buzz when a photo is taken (Android; iPhones have no web vibration). */
const buzz = () => { try { globalThis.navigator?.vibrate?.(14); } catch {} };

/**
 * Full-screen camera with a document-shaped frame.
 *   shape   "id1" (cards), "td3" (passport photo page) or "full" (any document)
 *   read    { barcode, mrz } — what to look for while the camera runs; it captures
 *           by itself the moment it reads one, or when the shutter is pressed
 *   auto    take the photo by itself once a document of this shape is lined up, lit,
 *           sharp and steady (core/detect.js). On by default for cards and passport
 *           pages; with a barcode or MRZ to read, it waits for the read, and takes the
 *           photo anyway after a document has sat lined up for a while without one
 *   onDone({ canvas, barcode, mrz, consensus, how }) — may be async: the camera stays
 *           open (showing "Saving…") until it settles, shows a tick when it succeeds,
 *           and goes back to live with the reason if it throws, so a photo is never
 *           silently lost
 *   saved   { text, img } — what the previous step saved, shown briefly at the top
 */
export function DocCamera({ shape = "id1", read = {}, auto = shape !== "full", eyebrow, title, hint, saved, onDone, onCancel, onSkip }) {
  const video = useRef(null), frame = useRef(null), file = useRef(null);
  const [phase, setPhase] = useState("starting"); // starting | live | reading | saved | error
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(hint || "");
  const [torch, setTorch] = useState(null);
  const [toldSaved, setToldSaved] = useState(!!saved);
  const [look, setLook] = useState(null);      // the last auto-capture check: { ok, aligned, found, hint, progress }
  const L = useRef({ stop: false, done: false, paused: false, stream: null, track: null, looping: false, holdUntil: 0 }).current;
  const codes = !!(read.barcode || read.mrz);
  const watching = auto || codes;
  useEffect(() => { if (!saved) return; const t = setTimeout(() => setToldSaved(false), 2600); return () => clearTimeout(t); }, []);

  const stopStream = () => { L.stream?.getTracks().forEach((t) => t.stop()); };
  async function finish(result) {
    if (L.done) return;
    L.done = true; L.stop = true; L.paused = true;
    setPhase("reading");
    let then;
    try {
      then = await onDone(result);
      buzz();
      setPhase("saved");
      await sleep(450);
      stopStream();
    } catch (e) {
      // Keep the camera open and say why: never drop back to the list as if nothing happened.
      L.done = false; L.paused = false;
      L.holdUntil = Date.now() + 2500; // let the reason be read before trying again by itself
      setStatus(e?.message || "Couldn't keep that photo. Try again.");
      setTimeout(() => setStatus(hint || ""), 2600);
      setPhase(L.stream ? "live" : "error");
      if (L.stream && watching) { L.stop = false; loop(); }
      return;
    }
    if (typeof then === "function") then();
  }

  async function loop() {
    if (L.looping) return;
    L.looping = true;
    try { await watch(); } finally { L.looping = false; }
  }

  async function watch() {
    const consensus = new MrzConsensus();
    const bc = read.barcode ? barcodeReader().catch(() => null) : null;
    const ocr = read.mrz ? mrzReader().catch(() => null) : null;
    if (read.mrz) setStatus("Getting the reader ready…");
    const shutter = autoShutter({ need: 4 });
    let turn = 0, sawMrz = false, prev = null, linedUpSince = 0;
    while (!L.stop) {
      await sleep(read.mrz ? 60 : codes ? 140 : 110);
      const v = video.current;
      if (L.paused || !v || v.readyState < 2 || !frame.current) continue;
      const rect = frameInVideo(v, frame.current, 0.05);
      if (!rect) continue;
      turn++;
      // Is a document lined up? Every look when there's nothing to read; every third otherwise.
      if (auto && (!codes || turn % 3 === 0) && Date.now() >= L.holdUntil) {
        try {
          const a = lookAround(v, frame.current);
          if (a) {
            const r = analyzeFrame(a.im, { guide: a.guide, shape, prev });
            if (DEMO_BUILD) globalThis.__humidLook = r; // development builds: tests can see why it waits
            prev = a.im;
            const fire = shutter.feed(r);
            setLook({ ok: r.ok, aligned: r.aligned, found: r.found, hint: r.hint, progress: shutter.progress });
            if (!codes) {
              if (fire && !L.stop) { L.stop = true; shoot("auto"); return; }
            } else {
              linedUpSince = r.aligned ? linedUpSince || Date.now() : 0;
              if (r.ok && linedUpSince && Date.now() - linedUpSince > FALLBACK_MS && !L.stop) { L.stop = true; shoot("auto"); return; }
            }
          }
        } catch { /* a bad frame: keep looking */ }
        if (!codes) continue;
      }
      const barcodeTurn = read.barcode && (!read.mrz || turn % 2 === 0);
      try {
        if (barcodeTurn) {
          const r = await bc;
          if (!r) continue;
          const [text] = await r.read(imageData(grab(v, rect, 2200)), { harder: false });
          if (text && !L.stop) { finish({ canvas: grab(v, frameRect(v, frame.current, 0.02)), barcode: text, how: "live" }); return; }
        } else if (read.mrz) {
          const r = await ocr;
          if (!r) { setStatus(hint || ""); continue; }
          const res = consensus.add(await r.read(mrzBand(grab(v, rect), shape)));
          if (res.best && !sawMrz) { sawMrz = true; setStatus("Reading… hold still"); }
          if (!res.best && !sawMrz) setStatus(hint || "");
          if (res.stable && !L.stop) { finish({ canvas: grab(v, frameRect(v, frame.current, 0.02)), mrz: res.result, consensus: true, how: "live" }); return; }
        }
      } catch { /* a bad frame: keep looking */ }
    }
  }

  useEffect(() => {
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error("no camera"), { name: "NotFoundError" });
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: false, video: { facingMode: { ideal: "environment" }, width: { ideal: 3840 }, height: { ideal: 2160 } },
        });
        if (L.stop) { stream.getTracks().forEach((t) => t.stop()); return; }
        L.stream = stream;
        L.track = stream.getVideoTracks()[0];
        try { await L.track.applyConstraints({ advanced: [{ focusMode: "continuous" }] }); } catch { /* not offered */ }
        try { if (L.track.getCapabilities?.().torch) setTorch(false); } catch { /* not offered */ }
        video.current.srcObject = stream;
        await video.current.play().catch(() => {});
        setPhase("live");
        if (watching) loop();
      } catch (e) { setPhase("error"); setError(cameraError(e)); }
    })();
    return () => { L.stop = true; L.stream?.getTracks().forEach((t) => t.stop()); };
  }, []);

  /** The shutter, or the auto-capture (how = "auto"). */
  async function shoot(how = "shutter") {
    const v = video.current;
    if (!v || L.done) return;
    L.paused = true;
    setPhase("reading");
    if (how === "auto") buzz();
    try {
      // Android can report a frame before it has one to give, or give a black one: wait briefly, try again.
      let c = null;
      for (let i = 0; i < 6 && !c; i++) {
        if (v.readyState >= 2 && v.videoWidth) {
          const got = shape === "full" ? grab(v, null) : grab(v, frameRect(v, frame.current, 0.02));
          if (!looksBlank(got)) c = got;
        }
        if (!c) await sleep(150);
      }
      if (!c) throw new Error("The camera gave a blank picture. Hold steady and try again.");
      const r = codes ? await readStill(c, read, shape) : {};
      await finish({ canvas: c, ...r, how });
    } catch (e) {
      L.paused = false;
      L.holdUntil = Date.now() + 2500;
      setStatus(e?.message || "Couldn't take the photo. Try again.");
      setTimeout(() => setStatus(hint || ""), 2600);
      setPhase(L.stream ? "live" : "error");
      if (L.stream && watching) { L.stop = false; loop(); }
    }
  }

  async function onFile(e) {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!f) return;
    L.paused = true;
    setPhase("reading");
    try {
      const c = await fileToCanvas(f);
      const r = read.barcode || read.mrz ? await readStill(c, read, shape) : {};
      await finish({ canvas: c, ...r, how: "file" });
    } catch {
      L.paused = false;
      setPhase(L.stream ? "live" : "error");
      toast("That file isn't a photo HumID can open.", "warn");
    }
  }

  async function toggleTorch() {
    try { await L.track.applyConstraints({ advanced: [{ torch: !torch }] }); setTorch(!torch); } catch { setTorch(null); }
  }

  const cancel = () => { L.stop = true; stopStream(); onCancel(); };
  const skip = () => { L.stop = true; stopStream(); onSkip(); };

  return (
    <div class="doccam" role="dialog" aria-modal="true" aria-label={title} data-phase={phase}
      data-look={phase !== "live" || !look ? undefined : look.ok ? "ok" : look.aligned || look.found ? "close" : "searching"}>
      <video ref={video} playsInline muted autoplay />
      <div class="dc-stage">
        <div class="dc-frame" data-shape={shape} ref={frame}>
          <i class="c tl" /><i class="c tr" /><i class="c bl" /><i class="c br" />
          {read.mrz && <span class="dc-mrz" data-shape={shape} />}
          {phase === "live" && look?.ok && <span class="dc-fill" style={{ "--p": look.progress }} aria-hidden="true" />}
          {phase === "reading" && <span class="dc-busy"><i /></span>}
          {phase === "saved" && <span class="dc-busy dc-saved" role="status" aria-label="Photo saved"><Icon name="check" /></span>}
        </div>
      </div>
      {toldSaved && saved && (
        <div class="dc-saved-chip" role="status">
          {saved.img && <img src={imageUrl(saved.img)} alt="" />}
          <span><Icon name="check" />{saved.text}</span>
        </div>
      )}
      <header class="dc-top">
        <button class="icon-btn" aria-label="Close the camera" data-back onClick={cancel}><Icon name="x" /></button>
        <div class="grow">{eyebrow && <div class="eyebrow">{eyebrow}</div>}<strong>{title}</strong></div>
        {torch != null && <button class="icon-btn" aria-label={torch ? "Turn the light off" : "Turn the light on"} aria-pressed={torch} onClick={toggleTorch}><Icon name="torch" /></button>}
      </header>
      <div class="dc-status" aria-live="polite">
        {phase === "error" ? error : phase === "reading" ? (codes ? "Reading the photo…" : "Saving the photo…") : phase === "saved" ? "Saved"
          : auto && !codes && look && status === (hint || "") ? look.hint : status}
      </div>
      <footer class="dc-bottom">
        <button class="dc-side" disabled={phase === "reading" || phase === "saved"} onClick={() => { markPicking(); file.current.click(); }}><Icon name="image" /><span>Photo</span></button>
        <button class="dc-shutter" aria-label="Take the photo" disabled={phase !== "live"} onClick={shoot}><i /></button>
        {onSkip ? <button class="dc-side" onClick={skip}><Icon name="chevron" /><span>Skip</span></button> : <span class="dc-side" aria-hidden="true" />}
      </footer>
      <input ref={file} type="file" accept="image/*" hidden onChange={onFile} />
    </div>
  );
}

/* ---------------- the ID flow ---------------- */

// What each kind of document asks the camera for, side by side.
const PLAN = {
  passport: [{ side: "front", shape: "td3", read: { mrz: true }, title: "The photo page", hint: "Fit the photo page in the frame, the two lines of <<< along the bottom." }],
  driver_license: [
    { side: "front", shape: "id1", read: {}, title: "Front of the license", hint: "Fit the card in the frame. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true }, title: "Back of the license", hint: "Fill the frame with the back. The barcode reads by itself." },
  ],
  id_card: [
    { side: "front", shape: "id1", read: {}, title: "Front of the card", hint: "Fit the card in the frame. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { barcode: true, mrz: true }, title: "Back of the card", hint: "Fill the frame with the back. A barcode or the lines of <<< read by themselves.", optional: true },
  ],
  residence_permit: [
    { side: "front", shape: "id1", read: {}, title: "Front of the permit", hint: "Fit the card in the frame. It takes the photo by itself." },
    { side: "back", shape: "id1", read: { mrz: true }, title: "Back of the permit", hint: "The three lines of <<< read by themselves.", optional: true },
  ],
  other: [
    { side: "front", shape: "id1", read: {}, title: "Front", hint: "Fit the card in the frame. It takes the photo by itself." },
    { side: "back", shape: "id1", read: {}, title: "Back", hint: "Fit the card in the frame. It takes the photo by itself.", optional: true },
  ],
};

const CHOICES = [
  { kind: "driver_license", icon: "idcard", title: "Driver's license", sub: "US or Canada. Reads the barcode on the back." },
  { kind: "passport", icon: "passport", title: "Passport", sub: "Reads the photo page, and the chip on phones with NFC." },
  { kind: "id_card", icon: "idcard", title: "ID card", sub: "A state ID, or a national ID card with a chip." },
  { kind: "other", icon: "file", title: "Another card", sub: "Insurance, membership, anything with two sides." },
];

const SOURCE = { chip: "Chip", barcode: "Barcode", mrz: "MRZ", typed: "You" };

export function IdSheet() {
  const st = S.sheet.value;
  const rec = useRef(null);
  const [, redraw] = useReducer((n) => n + 1, 0);
  const [step, setStep] = useState("kind");      // kind | capture | chip | review
  const [cam, setCam] = useState(null);         // the plan entry the camera is open for
  const [saved, setSaved] = useState(null);     // { text, img } the camera shows for the side just taken
  const [note, setNote] = useState(null);       // { tone, text } about the last capture
  const [nfc, setNfc] = useState(null);
  const [access, setAccess] = useState(null);
  const [name, setName] = useState("");
  const busy = st.stage != null;

  useEffect(() => () => { releaseReaders(); }, []);
  const r = rec.current;
  const plan = r ? PLAN[r.kind] || PLAN.other : [];
  const done = r ? plan.filter((p) => r.images[p.side]) : [];
  const next = r ? plan.find((p) => !r.images[p.side] && !r.skipped?.includes(p.side)) : null;

  const close = () => { if (!busy) S.sheet.value = null; };
  const choose = async (kind) => {
    rec.current = newRecord(kind);
    setStep("capture");
    setCam(PLAN[kind][0]);
    if (KINDS[kind].chip) chipReader().then(setNfc).catch(() => setNfc({ available: false }));
  };

  /**
   * The camera took a photo. Keep it (if this throws, the camera stays open and says
   * why), then return what happens once the camera has shown its tick: straight on to
   * the next side, or back to the sheet when everything's in or a read needs a look.
   */
  async function captured(p, { canvas, barcode, mrz, consensus }) {
    const rc = rec.current;
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
        ? { tone: "ok", text: `Machine-readable lines read${consensus ? "" : " (check them)"}: ${fullName(rc) || mrz.number}.` }
        : { tone: "warn", text: "Read part of the machine-readable lines. Check the details, or retake the photo." };
    }
    if (!n && (p.read.barcode || p.read.mrz)) n = { tone: "warn", text: p.read.barcode && !p.read.mrz ? "Couldn't read the barcode. Retake the back, or fill in the details yourself." : "Couldn't read the details from the photo. Retake it, or fill them in yourself." };
    if (!n) n = { tone: "ok", text: `${p.title} saved.` };
    setNote(n);
    redraw();
    const left = (PLAN[rc.kind] || PLAN.other).find((x) => !rc.images[x.side] && !rc.skipped?.includes(x.side));
    if (left && n.tone === "ok") {
      return () => { setSaved({ text: p.side === "front" ? "Front saved. Now turn it over." : `${p.title} saved.`, img }); setCam(left); };
    }
    return () => { setSaved(null); setCam(null); afterCapture(); };
  }

  function afterCapture() {
    const rc = rec.current;
    const left = (PLAN[rc.kind] || PLAN.other).find((p) => !rc.images[p.side] && !rc.skipped?.includes(p.side));
    if (left) { setStep("capture"); return; }
    // The chip step shows whenever this device has a chip reader, even one that's off
    // ("Turn on NFC"), and only until the chip has been read.
    setStep(KINDS[rc.kind]?.chip && nfc?.kind !== "none" && !rc.verified.chip ? "chip" : "review");
    setName(recordTitle(rc));
  }

  function skipSide(p) {
    setCam(null);
    const rc = rec.current;
    rc.skipped = [...(rc.skipped || []), p.side];
    redraw();
    afterCapture();
  }

  async function readChipNow() {
    const ok = await readChipInto(rec.current, access, { portrait: portraitImage });
    if (ok) {
      setNote({ tone: "ok", text: rec.current.verified.chip?.integrity ? "Chip read. The details match the issuing country's signed data." : "Chip read." });
      setName(recordTitle(rec.current));
      setStep("review");
      redraw();
    }
  }

  const head = (
    <div class="s-head"><div class="grow"><div class="eyebrow">{r ? kindLabel(r.kind) : "New ID"}</div>
      <h2 style={{ marginTop: 4 }}>{step === "kind" ? "Which document?" : step === "chip" ? "Read the chip" : step === "review" ? "Check the details" : "Scan it"}</h2></div>
      {!busy && <button class="icon-btn" aria-label="Close" onClick={close}><Icon name="x" /></button>}</div>
  );

  return (
    <>
      <Sheet onClose={close} label="Add an ID">
        {head}

        {step === "kind" && (
          <>
            <p class="lede">HumID reads the details for you, you check them, and one sealed record goes into your vault with its photos.</p>
            <div class="kinds">
              {CHOICES.map((c) => (
                <button class="kind" onClick={() => choose(c.kind)}><span class="ico"><Icon name={c.icon} /></span><span><strong>{c.title}</strong><span>{c.sub}</span></span><Icon name="chevron" /></button>
              ))}
            </div>
            <p class="fine" style={{ marginTop: 14 }}>Reading happens on this phone. Photos and details are encrypted here before anything is sent.</p>
          </>
        )}

        {step === "capture" && r && (
          <>
            {note && <Note {...note} />}
            <Thumbs rec={r} plan={plan} onRetake={(p) => setCam(p)} />
            {next && (
              <div class="actions">
                <button class="btn primary block" onClick={() => setCam(next)}><Icon name="camera" />{done.length ? `Now the ${next.side}` : `Scan the ${next.side}`}</button>
                {next.optional && <button class="btn ghost block" onClick={() => skipSide(next)}>No {next.side} to scan</button>}
              </div>
            )}
          </>
        )}

        {step === "chip" && r && (
          <>
            {note && <Note {...note} />}
            <div class="banner" style={{ marginTop: 12 }}><span class="b-ico"><Icon name="nfc" /></span>
              <div><strong>The chip has the verified details and photo</strong><span>{nfc?.kind === "reader" ? "Place the document on the card reader when asked." : "Hold the top of your phone flat against the document when asked."} It takes about 10 seconds.</span></div></div>
            {nfc && !nfc.available && <div class="banner warn" style={{ marginTop: 10 }}><span class="b-ico"><Icon name="info" /></span><div><strong>Can't read chips right now</strong><span>{nfc.reason}</span></div></div>}
            <ChipAccess onChange={setAccess} initial={chipAccessFrom(r)} title="Details that open the chip" note="They only open the chip. What it holds is sealed with this record." />
            <div class="actions">
              <button class="btn primary block" disabled={!access || !nfc?.available} onClick={readChipNow}><Icon name="nfc" />Read the chip</button>
              {nfc && !nfc.available && <button class="btn quiet block" onClick={async () => setNfc(await chipReader({ fresh: true }))}>Check again</button>}
              <button class="btn ghost block" onClick={() => setStep("review")}>Skip, use the photo</button>
            </div>
          </>
        )}

        {step === "review" && r && (
          busy ? <Steps current={{ seal: 0, upload: 1, done: 2 }[st.stage]} steps={["Sealing on this device", "Sending over HTP/1", "Stored · signature verified by the vault"]} />
            : <Review rec={r} name={name} setName={setName} note={note} plan={plan} onRetake={(p) => setCam(p)} onChange={redraw}
              onChip={KINDS[r.kind]?.chip && nfc && nfc.kind !== "none" && !r.verified.chip ? () => setStep("chip") : null}
              onSave={() => addIdRecord(r, name || recordTitle(r))} />
        )}
      </Sheet>
      {cam && (
        <DocCamera key={cam.side + (r?.images[cam.side] ? "-again" : "")} shape={cam.shape} read={cam.read} eyebrow={kindLabel(r.kind)} title={cam.title} hint={cam.hint}
          saved={saved} onCancel={() => { setSaved(null); setCam(null); }} onSkip={cam.optional ? () => { setSaved(null); skipSide(cam); } : null} onDone={(res) => captured(cam, res)} />
      )}
    </>
  );
}

/** What opens the chip, from the details read so far (ChipAccess takes ISO dates). */
const chipAccessFrom = (r) => ({ number: r.fields.number || "", birth: r.fields.birth || "", expiry: r.fields.expiry || "" });

function Note({ tone, text }) {
  return <div class={`banner ${tone === "warn" ? "warn" : ""}`} style={{ marginTop: 4 }}><span class="b-ico"><Icon name={tone === "warn" ? "info" : "check"} /></span><div><span>{text}</span></div></div>;
}

function Thumbs({ rec, plan, onRetake }) {
  const sides = [...plan.map((p) => p.side), ...(rec.images.portrait ? ["portrait"] : [])];
  return (
    <div class="id-thumbs">
      {sides.map((side) => {
        const img = rec.images[side];
        const p = plan.find((x) => x.side === side);
        return (
          <figure data-shape={side === "portrait" ? "portrait" : p?.shape}>
            {img ? <img src={imageUrl(img)} alt={`${side} of the document`} /> : <span class="empty-thumb">{rec.skipped?.includes(side) ? "Skipped" : "Not yet"}</span>}
            <figcaption>{side === "portrait" ? "Chip photo" : side === "front" ? "Front" : "Back"}{img && p && <button class="linklike" onClick={() => onRetake(p)}>Retake</button>}</figcaption>
          </figure>
        );
      })}
    </div>
  );
}

/* ---------------- check the details ---------------- */

function Review({ rec, name, setName, note, plan, onRetake, onChange, onChip, onSave }) {
  const [vals, setVals] = useState(() => Object.fromEntries(fieldsFor(rec.kind).map((f) => [f.key, rec.fields[f.key] ?? ""])));
  const [addr, setAddr] = useState(() => rec.address || { street: "", street2: "", city: "", region: "", postalCode: "", country: rec.fields.issuer || "" });
  const [more, setMore] = useState(false);
  const p = provenance(rec);
  const checks = rec.verified.mrz?.checks || {};
  const unsure = (k) => rec.source[k] === "mrz" && ((k === "number" && checks.number === false) || (k === "birth" && checks.birth === false) || (k === "expiry" && checks.expiry === false) || (k === "optional" && checks.optional === false));
  const set = (k) => (e) => setVals({ ...vals, [k]: e.currentTarget.type === "checkbox" ? e.currentTarget.checked : e.currentTarget.value });
  const fields = fieldsFor(rec.kind);
  const main = fields.filter((f) => !f.optional || vals[f.key] !== "" && vals[f.key] != null);
  const extra = fields.filter((f) => f.optional && (vals[f.key] === "" || vals[f.key] == null));
  const missing = rec.kind === "other" ? [] : ["surname", "number"].filter((k) => !String(vals[k] || "").trim());

  // Typed changes go into the record before anything that leaves this form (sealing,
  // a retake, the chip), so nothing typed is lost.
  const commit = () => {
    const typed = Object.fromEntries(Object.entries(vals).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v]).filter(([k, v]) => (rec.fields[k] ?? "") !== (v ?? "")));
    applyTyped(rec, typed);
    const a = Object.fromEntries(Object.entries(addr).map(([k, v]) => [k, String(v || "").trim()]));
    if (Object.values(a).some(Boolean) && JSON.stringify(a) !== JSON.stringify(rec.address || {})) { rec.address = a; rec.addressSource = "typed"; }
    onChange();
  };
  const save = () => { commit(); onSave(); };
  const retake = (side) => { commit(); onRetake(side); };
  const toChip = onChip && (() => { commit(); onChip(); });

  return (
    <>
      {note && <Note {...note} />}
      <div class={`id-proof lvl-${p.level}`}><Icon name={p.level.startsWith("chip") ? "nfc" : p.level === "barcode" ? "barcode" : p.level.startsWith("mrz") ? "scan" : "pencil"} /><span>{p.text}</span></div>
      <Thumbs rec={rec} plan={plan} onRetake={retake} />
      {toChip && <button class="btn quiet block" style={{ marginTop: 12 }} onClick={toChip}><Icon name="nfc" />Read the chip for verified details</button>}

      <div class="id-form">
        {main.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={rec.source[f.key]} unsure={unsure(f.key)} />)}
        {rec.kind !== "passport" && (rec.address || rec.kind === "driver_license" || rec.kind === "id_card") && (
          <fieldset class="id-addr">
            <legend>Address</legend>
            <input aria-label="Street" placeholder="Street" value={addr.street} onInput={(e) => setAddr({ ...addr, street: e.currentTarget.value })} />
            <input aria-label="Apartment, suite" placeholder="Apartment, suite (optional)" value={addr.street2} onInput={(e) => setAddr({ ...addr, street2: e.currentTarget.value })} />
            <div class="split3">
              <input aria-label="City" placeholder="City" value={addr.city} onInput={(e) => setAddr({ ...addr, city: e.currentTarget.value })} />
              <input aria-label="State" placeholder="State" maxLength={3} class="up" value={addr.region} onInput={(e) => setAddr({ ...addr, region: e.currentTarget.value.toUpperCase() })} />
              <input aria-label="ZIP or postal code" placeholder="ZIP" value={addr.postalCode} onInput={(e) => setAddr({ ...addr, postalCode: e.currentTarget.value })} />
            </div>
          </fieldset>
        )}
        {extra.length > 0 && !more && <button class="linklike" style={{ marginTop: 12 }} onClick={() => setMore(true)}>Add more details ({extra.map((f) => f.label.toLowerCase()).slice(0, 3).join(", ")}…)</button>}
        {more && extra.map((f) => <FieldInput f={f} value={vals[f.key]} onInput={set(f.key)} source={null} />)}
      </div>

      <div class="field">
        <label for="id-name">Name in your vault</label>
        <input id="id-name" value={name} maxLength={120} onInput={(e) => setName(e.currentTarget.value)} autocomplete="off" />
      </div>
      {missing.length > 0 && <p class="small" style={{ color: "var(--amber-hi)", marginTop: 10 }}>Add the {missing.map((k) => (k === "number" ? "document number" : "surname")).join(" and ")} before sealing.</p>}
      <div class="actions">
        <button class="btn primary block" disabled={missing.length > 0} onClick={save}><Icon name="fingerprint" />Seal &amp; store</button>
      </div>
      <p class="fine" style={{ marginTop: 12 }}>The details, photos{rec.raw.chip ? " and the chip's signed data" : ""} are sealed together on this phone (ML-KEM-1024 + X25519, signed with ML-DSA-87). Only your face or fingerprint opens them.</p>
    </>
  );
}

function FieldInput({ f, value, onInput, source, unsure }) {
  const id = `idf-${f.key}`;
  const tag = source && <span class={`src src-${source}`} title={`From the ${SOURCE[source] || source}`}>{SOURCE[source] || source}</span>;
  let input;
  if (f.type === "date") input = <input id={id} type="date" value={value || ""} onInput={onInput} />;
  else if (f.type === "sex") input = (
    <select id={id} value={value || ""} onChange={onInput}><option value="">—</option><option value="F">Female</option><option value="M">Male</option><option value="X">Unspecified (X)</option></select>
  );
  else if (f.type === "bool") input = <label class="check"><input id={id} type="checkbox" checked={value === true} onChange={onInput} /><span>Yes</span></label>;
  else input = <input id={id} class={f.mono ? "mono up" : f.type === "country" || f.type === "region" ? "up" : ""} value={value ?? ""} onInput={onInput} autocomplete="off" spellcheck={false}
    maxLength={f.type === "country" ? 3 : f.type === "region" ? 3 : 80} />;
  const hint = f.type === "country" && value ? countryName(value) : f.type === "region" && value ? regionName(value) : null;
  return (
    <div class={`field id-field${unsure ? " unsure" : ""}`}>
      <label for={id}>{f.label}{tag}</label>
      {input}
      {unsure ? <span class="hint warn">Check this against the document: its check digit didn't agree.</span> : hint && hint !== value ? <span class="hint">{hint}</span> : null}
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
  const st = idStatus(rec);
  const p = provenance(rec);
  const copy = async (text) => { try { await navigator.clipboard.writeText(text); toast("Copied. Clipboards can be read by other apps: clear it when you're done.", "ok"); } catch { toast("Couldn't copy here.", "warn"); } };
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
  return (
    <div class="id-view">
      <div class="id-card-hero">
        {rec.images[side] && <img src={imageUrl(rec.images[side])} alt={`${side === "portrait" ? "Photo from the chip" : `${side} of the document`}`} data-side={side} />}
        {sides.length > 1 && (
          <div class="cats" role="tablist" style={{ justifyContent: "center", marginTop: 10 }}>
            {sides.map((s) => <button role="tab" aria-pressed={side === s} onClick={() => setSide(s)}>{s === "portrait" ? "Chip photo" : s === "front" ? "Front" : "Back"}</button>)}
          </div>
        )}
      </div>
      <h2 style={{ marginTop: 14 }}>{fullName(rec) || recordTitle(rec)}</h2>
      <div class="id-badges">
        <span class={`pill ${st.state === "expired" ? "danger" : st.state === "expiring" ? "amber" : st.state === "valid" ? "mint" : ""}`}>
          <Icon name="clock" />{st.state === "expired" ? `Expired ${fmtDay(rec.fields.expiry)}` : st.state === "expiring" ? `Expires in ${st.days} days` : st.state === "valid" ? `Valid to ${fmtDay(rec.fields.expiry)}` : "No expiry date"}
        </span>
        <span class={`pill ${p.level === "chip" || p.level === "barcode" || p.level === "mrz" ? "mint" : ""}`}><Icon name={p.level.startsWith("chip") ? "nfc" : p.level === "barcode" ? "barcode" : p.level.startsWith("mrz") ? "scan" : "pencil"} />{p.level.startsWith("chip") ? "From the chip" : p.level === "barcode" ? "From the barcode" : p.level.startsWith("mrz") ? "From the MRZ" : "Typed"}</span>
      </div>
      <div class="card" style={{ marginTop: 14 }}>
        {rows.map((f) => (
          <div class="row">
            <span class="k">{f.label}</span>
            <span class={`v${f.mono ? " mono" : ""}`}>{show(f)}{(f.key === "number" || f.key === "discriminator") && <button class="copy" aria-label={`Copy ${f.label.toLowerCase()}`} onClick={() => copy(String(rec.fields[f.key]))}><Icon name="copy" /></button>}</span>
          </div>
        ))}
        {rec.address && (
          <div class="row"><span class="k">Address</span><span class="v">{[rec.address.street, rec.address.street2].filter(Boolean).join(", ")}<br />{[rec.address.city, [rec.address.region, rec.address.postalCode].filter(Boolean).join(" ")].filter(Boolean).join(", ")}</span></div>
        )}
      </div>
      <p class="fine" style={{ marginTop: 12 }}>{p.text}.{rec.edited?.length ? ` You edited: ${rec.edited.map((k) => fieldsFor(rec.kind).find((f) => f.key === k)?.label.toLowerCase() || k).join(", ")}.` : ""}</p>
      {rec.raw?.mrz && <pre class="mrz-lines" aria-label="Machine-readable zone">{rec.raw.mrz.join("\n")}</pre>}
      <div class="actions"><button class="btn quiet block" onClick={() => saveCopy(item)}><Icon name="download" />Save a copy (JSON with photos)</button></div>
    </div>
  );
}
