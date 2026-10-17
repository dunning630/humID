// Vault: list, search, categories, add, item details, preview.
import { useEffect, useRef, useState } from "preact/hooks";
import { guessCategory } from "../core/categories.js";
import { Mark } from "../brand.jsx";
import { Icon, CATEGORIES, categoryOf, kindIcon } from "../icons.jsx";
import { Sheet, Steps, fmtSize, fmtDate, fmtAgo, AssurancePill, OfflineBanner, CheckinBar, ErasedBanner, usePlaceStamp } from "../ui.jsx";
import { rotateCanvas, cleanCanvas } from "../core/scan.js";
import { formatCoords, formatAccuracy, mapLink, validStamp } from "../core/place.js";
import * as S from "../core/state.js";
import { addDocument, checkPass, addPass, toast, openItem, saveCopy, exportSealed, deleteItem, renameItem, closeViewer, markPicking, lockNow, setDecoy, setPinned, loadRecovery, loadDevices } from "../core/controller.js";
import { DocCamera, IdView } from "./ids.jsx";
import { status as idStatus, kindLabel } from "@humid/idscan";
import { CardView } from "./cards.jsx";
import { BRANDS, expiryStatus, showExpiry } from "@humid/cards";
import { looksLikePass, STYLE_LABEL } from "@humid/wallet";
import { PassView, PassCheck } from "./passes.jsx";

export function Vault() {
  const list = S.visibleItems.value;
  const all = S.items.value;
  const u = S.usage.value;
  return (
    <main class="screen with-tabs">
      <div class="topbar">
        <div class="grow">
          <h1>Vault</h1>
          <div class="sub"><Icon name="lock" />{all.length} {all.length === 1 ? "item" : "items"} · sealed on this device{u ? ` · ${fmtSize(u.bytes)}` : ""}</div>
        </div>
        <button class="icon-btn" aria-label="Lock now" onClick={lockNow}><Icon name="lock" /></button>
      </div>

      <OfflineBanner />
      <CheckinBar />
      <ErasedBanner />

      {S.alerts.value.length > 0 && (
        <button class="banner bad alert-banner" onClick={() => { S.tab.value = "security"; window.scrollTo({ top: 0 }); }}>
          <span class="b-ico"><Icon name="alert" /></span>
          <div><strong>Someone is recovering your HumID</strong><span>From {S.alerts.value[0].platform}. If this isn't you, cancel it in Security.</span></div>
        </button>
      )}

      <ProtectionCard />

      {all.length > 0 && (
        <>
          <label class="search">
            <Icon name="search" />
            <input autocorrect="off" spellcheck={false} id="vault-search" type="search" placeholder="Search your vault" value={S.query.value} onInput={(e) => (S.query.value = e.currentTarget.value)} autocomplete="off" />
          </label>
          <div class="chips" role="group" aria-label="Filter by category">
            <button class="chip" aria-pressed={S.filter.value === "all"} onClick={() => (S.filter.value = "all")}>All <span class="count">{S.counts.value.all}</span></button>
            {CATEGORIES.filter((c) => S.counts.value[c.id]).map((c) => (
              <button class="chip" aria-pressed={S.filter.value === c.id} onClick={() => (S.filter.value = c.id)}><Icon name={c.icon} />{c.label} <span class="count">{S.counts.value[c.id]}</span></button>
            ))}
          </div>
        </>
      )}

      {S.loading.value && all.length === 0 && <p class="muted small" style={{ marginTop: 20 }}>Loading your vault…</p>}

      {!S.loading.value && all.length === 0 && (
        <div class="empty">
          <Mark />
          <h3>Your vault is empty</h3>
          <p>Scan your license or passport, or add any document. It's sealed on this phone before it goes anywhere.</p>
          {!S.offline.value && <button class="btn primary" onClick={() => (S.sheet.value = { type: "id" })}><Icon name="idcard" />Scan an ID</button>}
          {!S.offline.value && <button class="btn ghost" style={{ marginTop: 10 }} onClick={() => (S.sheet.value = { type: "add" })}><Icon name="plus" />Add a document</button>}
          {!S.offline.value && <button class="btn ghost" style={{ marginTop: 10 }} onClick={() => (S.sheet.value = { type: "card" })}><Icon name="card" />Add a payment card</button>}
        </div>
      )}

      {all.length > 0 && list.length === 0 && <p class="muted" style={{ marginTop: 24, textAlign: "center" }}>Nothing matches “{S.query.value}”.</p>}

      <div class="list">
        {list.map((it) => <ItemRow item={it} key={it.id} />)}
      </div>

      {all.length > 0 && !S.offline.value && (
        <button class="fab" aria-label="Add a document" onClick={() => (S.sheet.value = { type: "add" })}><Icon name="plus" /></button>
      )}
    </main>
  );
}

const brandName = (id) => BRANDS.find((b) => b.id === id)?.name || "Card";

function ItemRow({ item }) {
  const cat = categoryOf(item.category);
  const card = item.cardInfo;
  if (card) {
    const cs = expiryStatus(card.expiry);
    return (
      <button class="item" data-pinned={item.pinned ? "1" : undefined} onClick={() => (S.sheet.value = { type: "item", id: item.id })}>
        <span class="ico" data-cat={cat.id}><Icon name="card" /></span>
        <span style={{ minWidth: 0 }}>
          <div class="name">{item.pinned && <Icon name="pushpin" />}{item.name}</div>
          <div class="meta">{brandName(card.brand)} •••• {card.last4} · {cs.state === "expired" ? <b class="warn-text">expired</b> : cs.state === "expiring" ? <b class="warn-text">expires {showExpiry(card.expiry)}</b> : card.expiry ? `expires ${showExpiry(card.expiry)}` : "no expiry"}</div>
        </span>
        <span class="end"><Icon name="chevron" /></span>
      </button>
    );
  }
  const pi = item.passInfo;
  if (pi) {
    const when = pi.relevant || pi.expires;
    const gone = pi.voided || (pi.expires && Date.parse(pi.expires) < Date.now());
    return (
      <button class="item" data-pinned={item.pinned ? "1" : undefined} onClick={() => (S.sheet.value = { type: "item", id: item.id })}>
        <span class="ico" data-cat={cat.id}><Icon name="ticket" /></span>
        <span style={{ minWidth: 0 }}>
          <div class="name">{item.pinned && <Icon name="pushpin" />}{item.name}</div>
          <div class="meta">{STYLE_LABEL[pi.style] || "Pass"} · {pi.issuer || pi.organization}{gone ? <> · <b class="warn-text">{pi.voided ? "voided" : "expired"}</b></> : when ? ` · ${fmtDate(when)}` : ""}</div>
        </span>
        <span class="end"><Icon name="chevron" /></span>
      </button>
    );
  }
  const id = item.idInfo;
  const st = id ? idStatus({ fields: { expiry: id.expiry } }, new Date(), S.prefs.value.expiryWarnDays) : null;
  return (
    <button class="item" data-pinned={item.pinned ? "1" : undefined} onClick={() => (S.sheet.value = { type: "item", id: item.id })}>
      <span class="ico" data-cat={cat.id}><Icon name={id ? (id.kind === "passport" ? "passport" : "idcard") : item.category === "other" || item.category === "personal" ? kindIcon(item.type) : cat.icon} /></span>
      <span style={{ minWidth: 0 }}>
        <div class="name">{item.pinned && <Icon name="pushpin" />}{item.name}</div>
        <div class="meta">{id
          ? <>{kindLabel(id.kind)} · {st.state === "expired" ? <b class="warn-text">expired</b> : st.state === "expiring" ? <b class="warn-text">expires in {st.days} days</b> : id.expiry ? `expires ${fmtDate(`${id.expiry}T12:00:00`)}` : "no expiry"}</>
          : <>{cat.label} · {fmtSize(item.size)} · {fmtAgo(item.uploadedAt)}</>}</div>
      </span>
      <span class="end"><Icon name="chevron" /></span>
    </button>
  );
}

/* ---------------- finish protecting it ---------------- */

/** Opens a step in Security: a sheet, or the Recovery card when the person has a choice to make there. */
function goSecurity(target) {
  S.tab.value = "security";
  if (target === "#recovery") setTimeout(() => document.getElementById("recovery")?.scrollIntoView({ block: "start", behavior: "smooth" }), 80);
  else S.sheet.value = { type: target };
}

/**
 * What's left to make this HumID survive a lost phone, with a button for each, until it's
 * done. Hidden in a duress (decoy) session, which must look like an ordinary account.
 */
export function ProtectionCard() {
  const decoy = S.decoy.value;
  useEffect(() => { if (!decoy) { loadRecovery(); loadDevices(); } }, [decoy]);
  const rec = S.recovery.value, devices = S.devices.value, id = S.identity.value;
  if (decoy || S.offline.value || !rec || !devices) return null; // offline: nothing here could be done until it reconnects
  const items = [
    { done: !!rec.proofs?.card, icon: "idcard", label: "Seal card", todo: "Make the card that's one of your proofs", target: "cardInfo" },
    { done: !!(rec.proofs?.witness || rec.proofs?.anchor), icon: "users", label: "A second proof", todo: "Witnesses who vouch for you, or your ID chip", target: "#recovery" },
    { done: devices.length >= 2, icon: "key", label: "A second device", todo: "Another phone or computer, so a lost phone isn't an emergency", target: "addDevice" },
  ];
  const n = items.filter((i) => i.done).length;
  if (n === items.length) return null;
  return (
    <section class="card protect" aria-labelledby="protect-h">
      <div class="c-head"><h3 id="protect-h">Finish protecting your HumID</h3><span class="pill amber">{n} of {items.length}</span></div>
      <div class="meter" role="progressbar" aria-label="Protection" aria-valuemin={0} aria-valuemax={items.length} aria-valuenow={n}><i style={{ width: `${(n / items.length) * 100}%` }} /></div>
      {items.map((i) => (
        <button class="proof-row linkrow" data-done={i.done ? "1" : "0"} disabled={i.done} onClick={() => goSecurity(i.target)}>
          <span class="p-ico"><Icon name={i.done ? "check" : i.icon} /></span>
          <span><strong>{i.label}</strong><span>{i.done ? "Done" : i.todo}</span></span>
          {!i.done && <Icon name="chevron" />}
        </button>
      ))}
      {!S.duressSetting.value?.enabled && (
        <button class="proof-row linkrow" data-done="0" onClick={() => goSecurity("duress")}>
          <span class="p-ico"><Icon name="siren" /></span>
          <span><strong>Optional: duress gesture</strong><span>If you're ever forced to unlock, show only chosen documents</span></span>
          <Icon name="chevron" />
        </button>
      )}
    </section>
  );
}

/* ---------------- add ---------------- */

const canvasBlob = (c, q = 0.9) => new Promise((res, rej) => c.toBlob((b) => (b ? res(b) : rej(new Error("Couldn't save that photo. Try again."))), "image/jpeg", q));

/** How much of a page must look like paper for the clean scan to be the suggested version. */
const PAPER_SHARE = 0.45;

/** The canvas for a choice: "clean" (the clean scan), "proposed" (straightened) or "original", turned `turn` (not the original). */
const versionOf = (shot, which, turn) =>
  which === "original" ? shot.original : rotateCanvas(which === "clean" && shot.clean ? shot.clean : shot.canvas, turn);

/**
 * A photo from the camera, in up to three versions: a clean scan (the page straightened,
 * turned the way it reads, and evened out to look like it came off a flatbed scanner:
 * shadows gone, paper white, ink crisp), the straightened photo with its true colours
 * and light, or the photo exactly as taken. The clean scan is suggested when the page
 * looks like paper; otherwise the straightened photo is. Either can be turned by hand if
 * the guess was wrong. Shows the chosen one; onChange({ which, turn }).
 */
function PhotoChoice({ shot, which, turn, onChange, onRetake }) {
  const [url, setUrl] = useState(null);
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
  const did = shot.straightened ? `Found the document's edges and straightened it${shot.rotate ? ", then turned it upright" : ""}` : "Turned it upright";
  const suggested = shot.clean && shot.cleanSuggested ? "clean" : "proposed";
  const tag = (w) => suggested === w && <span class="tag">Suggested</span>;
  const note = !shot.changed ? "Sealed as taken: no document edges found to straighten."
    : which === "original" ? "The photo exactly as the camera took it."
    : which === "clean" ? `${did}, then evened out the light like a scanner: shadows gone, paper white. Not right? Turn it, or pick another version.`
    : `${did}, keeping its true colours and light. Not right? Turn it, or seal the original.`;
  return (
    <div class="photo-choice">
      {shot.changed && (
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
        {which !== "original" && (
          <div class="photo-turn">
            <button class="icon-btn" aria-label="Turn left" onClick={() => onChange({ which, turn: (turn + 270) % 360 })}><Icon name="turn" /></button>
            <button class="icon-btn" aria-label="Turn right" onClick={() => onChange({ which, turn: (turn + 90) % 360 })}><Icon name="turn" /></button>
          </div>
        )}
      </figure>
      <p class="fine photo-note">
        {note}
        {" "}<button class="linklike" onClick={onRetake}>Retake</button>
      </p>
    </div>
  );
}

export function AddSheet() {
  const st = S.sheet.value;
  const [file, setFile] = useState(null);
  const [shot, setShot] = useState(null);      // a camera photo: { canvas (proposal), original, straightened, rotate, changed, clean, cleanSuggested }
  const [pick, setPick] = useState({ which: "proposed", turn: 0 });
  const [name, setName] = useState("");
  const [cat, setCat] = useState("other");
  const [camera, setCamera] = useState(false);
  const [busy, setBusy] = useState(false);
  const [passCheck, setPassCheck] = useState(null); // a Wallet pass: null | { state: "checking" } | { ok, result | reason }
  const chooser = useRef(null);
  const current = useRef(null); // the file on screen: a check that finishes for another one is dropped
  const place = usePlaceStamp();
  const close = () => { if (!st.stage) S.sheet.value = null; };
  const choose = (input) => { markPicking(); input.current.click(); };
  const when = useRef(null);
  // Keep the photo before the camera closes. Encoding waits for Seal, so it's quick.
  const photographed = async (res) => {
    when.current = new Date();
    // a straightened page also gets a clean scan, made while the camera shows "Saving…"
    if (res.straightened) {
      await new Promise((r) => setTimeout(r, 0));
      try { const c = cleanCanvas(res.canvas); res = { ...res, clean: c.canvas, cleanSuggested: c.paper >= PAPER_SHARE }; }
      catch { /* low memory: the straightened photo is still offered */ }
    }
    return () => {
      setCamera(false);
      setShot(res);
      setPick({ which: !res.changed ? "original" : res.cleanSuggested ? "clean" : "proposed", turn: 0 });
      setFile(null);
      setName(`Photo ${when.current.toLocaleDateString()}`);
    };
  };
  const onFile = (e) => {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    e.currentTarget.accept = ""; // "Add a Wallet pass" narrows the chooser for one pick
    if (!f) return;
    setShot(null);
    setFile(f);
    setName(f.name.replace(/\.[a-z0-9]{1,6}$/i, "").replace(/[_-]+/g, " ").slice(0, 80) || "Document");
    setCat(guessCategory(f.name, f.type)); // a suggestion; the person can change it
    setPassCheck(null);
    current.current = f;
    if (looksLikePass(f)) {
      setPassCheck({ state: "checking" });
      checkPass(f).then((r) => {
        if (current.current !== f) return;
        setPassCheck(r);
        if (r.ok) setName(r.result.pass.description || r.result.pass.organization || "Pass");
      });
    }
  };
  /** The file to seal: the chosen version of a camera photo, or the chosen file. */
  async function toSeal() {
    if (!shot) return file;
    const c = versionOf(shot, pick.which, pick.turn);
    const blob = await canvasBlob(c, 0.9);
    const t = when.current || new Date();
    const tag = { original: "", clean: " (scan)", proposed: " (straightened)" }[pick.which] ?? "";
    return new File([blob], `Photo ${t.toLocaleDateString()} ${t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${tag}.jpg`, { type: "image/jpeg" });
  }
  async function seal() {
    if (busy) return;
    setBusy(true);
    try {
      if (passCheck?.ok) await addPass({ checked: passCheck, name, place: place.take() });
      else {
        // a pass that failed its check is kept as an ordinary file, never under the pass type
        const f = file && looksLikePass(file) ? new File([file], file.name, { type: "application/octet-stream" }) : await toSeal();
        await addDocument({ file: f, name, category: cat, place: place.take() });
      }
    }
    catch (e) { toast(e?.message || "Couldn't save that photo. Try again.", "error"); }
    finally { setBusy(false); }
  }
  const stageIdx = { seal: 0, upload: 1, done: 2 }[st.stage];
  const have = file || shot;
  const reset = () => { setFile(null); setShot(null); setPassCheck(null); current.current = null; };
  const plainFile = () => { setPassCheck(null); setCat("other"); }; // keep a pass that failed its check as an ordinary file

  return (
    <Sheet onClose={close} label="Add a document">
      <div class="s-head"><div class="grow"><div class="eyebrow">New document</div><h2 style={{ marginTop: 4 }}>{have ? "Seal it into your vault" : "Add to your vault"}</h2></div>
        {!st.stage && <button class="icon-btn" aria-label="Close" onClick={close}><Icon name="x" /></button>}</div>

      <input ref={chooser} type="file" hidden onChange={onFile} />

      {!have && (
        <>
          <button class="kind featured" onClick={() => (S.sheet.value = { type: "id" })}>
            <span class="ico"><Icon name="idcard" /></span>
            <span><strong>Scan an ID</strong><span>Driver's license, passport or ID card. HumID reads the details, and the chip where there is one.</span></span>
            <Icon name="chevron" />
          </button>
          <button class="kind" style={{ marginTop: 10 }} onClick={() => (S.sheet.value = { type: "card" })}>
            <span class="ico"><Icon name="card" /></span>
            <span><strong>Add a payment card</strong><span>Credit or debit. Scan both sides, tap it, or type it. Never the PIN.</span></span>
            <Icon name="chevron" />
          </button>
          <button class="kind" style={{ marginTop: 10 }} onClick={() => { chooser.current.accept = ".pkpass,application/vnd.apple.pkpass"; choose(chooser); }}>
            <span class="ico"><Icon name="ticket" /></span>
            <span><strong>Add a Wallet pass</strong><span>A boarding pass, ticket or membership card shared from Apple Wallet as a .pkpass file. HumID checks it's genuinely from its issuer.</span></span>
            <Icon name="chevron" />
          </button>
          <div class="source" style={{ marginTop: 10 }}>
            <button onClick={() => setCamera(true)}><Icon name="camera" /><strong>Take a photo</strong><span>Any document or card. HumID finds it and straightens it.</span></button>
            <button onClick={() => { chooser.current.accept = ""; choose(chooser); }}><Icon name="file" /><strong>Choose a file</strong><span>PDF, image, any type up to 50 MB</span></button>
          </div>
        </>
      )}
      {camera && <DocCamera shape="full" title="Take a photo" hint="Point the camera at the document. It finds the edges by itself." onCancel={() => setCamera(false)} onDone={photographed} />}

      {have && st.stage == null && (
        <>
          {passCheck ? <PassCheck check={passCheck} onPlain={plainFile} onAnother={() => { reset(); choose(chooser); }} />
            : shot ? <PhotoChoice shot={shot} which={pick.which} turn={pick.turn} onChange={setPick} onRetake={() => setCamera(true)} />
            : (
              <div class="doc-hero">
                <span class="ico item" style={{ padding: 0, border: 0, background: "none" }}><span class="ico" data-cat={cat}><Icon name={kindIcon(file.type)} /></span></span>
                <div style={{ minWidth: 0 }}><div class="name" style={{ fontWeight: 600, overflowWrap: "anywhere" }}>{file.name}</div><div class="muted small">{fmtSize(file.size)} · {file.type || "file"}</div></div>
              </div>
            )}
          <div class="field">
            <label for="doc-name">Name</label>
            <input autocorrect="off" spellcheck={false} id="doc-name" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" />
          </div>
          {!passCheck && <div class="field">
            <label>Category</label>
            <div class="cats">
              {CATEGORIES.map((c) => <button aria-pressed={cat === c.id} onClick={() => setCat(c.id)}><Icon name={c.icon} />{c.label}</button>)}
            </div>
          </div>}
          {place.element}
          <div class="actions">
            <button class="btn primary block" disabled={busy || (passCheck && !passCheck.ok)} onClick={seal}><Icon name="fingerprint" />{shot && shot.changed ? (pick.which === "original" ? "Seal the original" : pick.which === "clean" ? "Seal the clean scan" : "Seal the straightened photo") : "Seal & store"}</button>
            <button class="btn ghost block" onClick={reset}>{shot ? "Start again" : "Choose another"}</button>
          </div>
          <p class="fine" style={{ marginTop: 12 }}>Encrypted on this phone with ML-KEM-1024 + X25519 and signed with ML-DSA-87 before upload. {shot ? "Only the version you seal is kept; the other is discarded." : "The original isn't kept."} The location, if stamped, is sealed with the name, so the vault server can't read it.</p>
        </>
      )}

      {have && st.stage != null && (
        <Steps current={stageIdx} steps={["Sealing on this device", "Sending over HTP/1", "Stored · signature verified by the vault"]} />
      )}
    </Sheet>
  );
}

/** Where a document was sealed, if it was stamped: coordinates, accuracy, and a map link opened only on a tap. */
function SealedAt({ place }) {
  if (!validStamp(place)) return null;
  return (
    <div class="row"><span class="k">Sealed at</span>
      <span class="v place-v">
        <span class="mono" style={{ fontSize: 12 }}>{formatCoords(place)}</span>
        <span class="muted small">{formatAccuracy(place.accuracy)} · as the phone reported · <a href={mapLink(place)} target="_blank" rel="noopener noreferrer">Show on a map</a></span>
      </span>
    </div>
  );
}

/* ---------------- item ---------------- */

export function ItemSheet() {
  const st = S.sheet.value;
  const item = S.items.value.find((i) => i.id === st.id);
  const [mode, setMode] = useState("view"); // view | edit | confirm
  const [name, setName] = useState(item?.name || "");
  const [cat, setCat] = useState(item?.category || "other");
  if (!item) return null;
  const c = categoryOf(item.category);
  const close = () => (S.sheet.value = null);
  const off = !!S.offline.value;

  return (
    <Sheet onClose={close} label={item.name}>
      <div class="doc-hero">
        <span class="ico" data-cat={c.id} style={{ display: "grid", placeItems: "center", borderRadius: 18, width: 64, height: 64, background: "var(--surface-3)" }}><Icon name={kindIcon(item.type)} /></span>
        <div style={{ minWidth: 0 }}><div class="eyebrow">{c.label}</div><h2 style={{ marginTop: 4 }}>{item.name}</h2></div>
      </div>

      {mode === "view" && (
        <>
          <div class="card" style={{ marginTop: 14 }}>
            <div class="row"><span class="k">Size</span><span class="v">{fmtSize(item.size)} · sealed {fmtSize(item.envelopeSize)}</span></div>
            <div class="row"><span class="k">Sealed</span><span class="v">{fmtDate(item.sealedAt || item.uploadedAt)}</span></div>
            <SealedAt place={item.place} />
            <div class="row"><span class="k">Sealed with</span><span class="v"><AssurancePill assurance={item.assurance} /></span></div>
            <div class="row"><span class="k">Encryption</span><span class="v mono" style={{ fontSize: 12 }}>ML-KEM-1024 + X25519 · AES-256-GCM</span></div>
            <div class="row"><span class="k">Signature</span><span class="v mono" style={{ fontSize: 12 }}>ML-DSA-87 ✓ verified by vault</span></div>
          </div>
          {off && (
            <div class="banner warn" role="note" style={{ marginTop: 14 }}>
              <span class="b-ico"><Icon name="signal" /></span>
              <div><strong>Opening needs a connection</strong><span>The document itself and its key are only in your vault. Nothing here can open it offline.</span></div>
            </div>
          )}
          <div class="actions">
            <button class="btn secure block" disabled={off} onClick={() => openItem(item)}><Icon name="eye" />Open</button>
            <div class="split">
              <button class="btn quiet" disabled={off} onClick={() => saveCopy(item)}><Icon name="download" />Save copy</button>
              <button class="btn quiet" disabled={off} onClick={() => setMode("edit")}><Icon name="pencil" />Rename</button>
            </div>
            <div class="split">
              <button class="btn quiet" disabled={off} onClick={() => exportSealed(item)}><Icon name="lock" />Sealed copy</button>
              <button class="btn danger" disabled={off} onClick={() => setMode("confirm")}><Icon name="trash" />Delete</button>
            </div>
          </div>
          {!off && (
            <label class="toggle" style={{ marginTop: 12 }}>
              <span><strong>Pin to the top</strong><span>Sealed with the item, so it's pinned on all your devices.</span></span>
              <input type="checkbox" role="switch" checked={!!item.pinned} onChange={(e) => setPinned(item, e.currentTarget.checked)} />
              <i aria-hidden="true" />
            </label>
          )}
          {S.duressSetting.value?.enabled && !S.decoy.value && !off && (
            <label class="toggle" style={{ marginTop: 12 }}>
              <span><strong>Show in decoy view</strong><span>What someone sees if you unlock with your duress gesture.</span></span>
              <input type="checkbox" role="switch" checked={!!item.decoy} onChange={(e) => setDecoy(item, e.currentTarget.checked)} />
              <i aria-hidden="true" />
            </label>
          )}
          <p class="fine" style={{ marginTop: 12 }}>Opening, saving and deleting each need a fresh biometric check. Every one is recorded in Activity.</p>
        </>
      )}

      {mode === "edit" && (
        <>
          <div class="field"><label for="rename">Name</label><input autocorrect="off" spellcheck={false} id="rename" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" /></div>
          <div class="field"><label>Category</label><div class="cats">{CATEGORIES.map((x) => <button aria-pressed={cat === x.id} onClick={() => setCat(x.id)}><Icon name={x.icon} />{x.label}</button>)}</div></div>
          <div class="actions">
            <button class="btn primary block" onClick={() => renameItem(item, name, cat)}>Save changes</button>
            <button class="btn ghost block" onClick={() => setMode("view")}>Cancel</button>
          </div>
        </>
      )}

      {mode === "confirm" && (
        <>
          <div class="banner bad" style={{ marginTop: 14 }}><span class="b-ico"><Icon name="trash" /></span><div><strong>Delete “{item.name}”?</strong><span>It's removed from the vault server. Exported copies you saved elsewhere aren't affected.</span></div></div>
          <div class="actions">
            <button class="btn danger block" onClick={() => deleteItem(item)}><Icon name="fingerprint" />Confirm with biometric &amp; delete</button>
            <button class="btn ghost block" onClick={() => setMode("view")}>Keep it</button>
          </div>
        </>
      )}
    </Sheet>
  );
}

/* ---------------- viewer ---------------- */

export function Viewer() {
  const v = S.viewer.value;
  if (!v) return null;
  const isImg = v.type.startsWith("image/");
  const isPdf = v.type === "application/pdf";
  if (v.pass || v.passError) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Decrypted in memory · verified</div></div>
      </header>
      <div class="body id-body"><PassView v={v} /></div>
      <div class="wipe">Closing wipes the decrypted pass from memory.</div>
    </div>
  );
  if (v.cardRecord) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Decrypted in memory · verified</div></div>
      </header>
      <div class="body id-body"><CardView record={v.cardRecord} /></div>
      <div class="wipe">Closing wipes the decrypted card from memory.</div>
    </div>
  );
  if (v.idRecord) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Decrypted in memory · verified</div></div>
      </header>
      <div class="body id-body"><IdView record={v.idRecord} item={v.item} /></div>
      <div class="wipe">Closing wipes the decrypted copy from memory.</div>
    </div>
  );
  return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Decrypted in memory · verified</div></div>
        <button class="icon-btn" aria-label="Save a copy" onClick={() => saveCopy(v.item)}><Icon name="download" /></button>
      </header>
      <div class="body">
        {v.text != null && <pre>{v.text}</pre>}
        {isImg && <img src={v.url} alt={v.name} />}
        {isPdf && <iframe src={v.url} title={v.name} />}
        {!isImg && !isPdf && v.text == null && (
          <div class="empty" style={{ marginTop: 0 }}>
            <Icon name="file" />
            <p>This file type can't be previewed here. Save a copy to open it in another app.</p>
            <button class="btn secure" onClick={() => saveCopy(v.item)}><Icon name="download" />Save a copy</button>
          </div>
        )}
      </div>
      <div class="wipe">Closing wipes the decrypted copy from memory.</div>
    </div>
  );
}
