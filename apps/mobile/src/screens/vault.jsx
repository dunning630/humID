// Vault: list, search, categories, add, item details, preview.
import { useRef, useState } from "preact/hooks";
import { Mark } from "../brand.jsx";
import { Icon, CATEGORIES, categoryOf, kindIcon } from "../icons.jsx";
import { Sheet, Steps, fmtSize, fmtDate, fmtAgo, AssurancePill } from "../ui.jsx";
import * as S from "../core/state.js";
import { addDocument, openItem, saveCopy, exportSealed, deleteItem, renameItem, closeViewer, markPicking, lockNow } from "../core/controller.js";

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

      {all.length > 0 && (
        <>
          <label class="search">
            <Icon name="search" />
            <input id="vault-search" type="search" placeholder="Search your vault" value={S.query.value} onInput={(e) => (S.query.value = e.currentTarget.value)} autocomplete="off" />
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
          <p>Add a passport scan, insurance card or any document. It's sealed on this phone before it goes anywhere.</p>
          <button class="btn primary" onClick={() => (S.sheet.value = { type: "add" })}><Icon name="plus" />Add a document</button>
        </div>
      )}

      {all.length > 0 && list.length === 0 && <p class="muted" style={{ marginTop: 24, textAlign: "center" }}>Nothing matches “{S.query.value}”.</p>}

      <div class="list">
        {list.map((it) => <ItemRow item={it} key={it.id} />)}
      </div>

      {all.length > 0 && (
        <button class="fab" aria-label="Add a document" onClick={() => (S.sheet.value = { type: "add" })}><Icon name="plus" /></button>
      )}
    </main>
  );
}

function ItemRow({ item }) {
  const cat = categoryOf(item.category);
  return (
    <button class="item" onClick={() => (S.sheet.value = { type: "item", id: item.id })}>
      <span class="ico" data-cat={cat.id}><Icon name={item.category === "other" || item.category === "personal" ? kindIcon(item.type) : cat.icon} /></span>
      <span style={{ minWidth: 0 }}>
        <div class="name">{item.name}</div>
        <div class="meta">{cat.label} · {fmtSize(item.size)} · {fmtAgo(item.uploadedAt)}</div>
      </span>
      <span class="end"><Icon name="chevron" /></span>
    </button>
  );
}

/* ---------------- add ---------------- */

export function AddSheet() {
  const st = S.sheet.value;
  const [file, setFile] = useState(null);
  const [name, setName] = useState("");
  const [cat, setCat] = useState("identity");
  const cam = useRef(null), pick = useRef(null);
  const close = () => { if (!st.stage) S.sheet.value = null; };
  const choose = (input) => { markPicking(); input.current.click(); };
  const onFile = (e) => {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = "";
    if (!f) return;
    setFile(f);
    setName(f.name.replace(/\.[a-z0-9]{1,5}$/i, "").replace(/[_-]+/g, " ").slice(0, 80) || "Document");
    if (f.type.startsWith("image/") && cat === "other") setCat("identity");
  };
  const stageIdx = { seal: 0, upload: 1, done: 2 }[st.stage];

  return (
    <Sheet onClose={close} label="Add a document">
      <div class="s-head"><div class="grow"><div class="eyebrow">New document</div><h2 style={{ marginTop: 4 }}>{file ? "Seal it into your vault" : "Add to your vault"}</h2></div>
        {!st.stage && <button class="icon-btn" aria-label="Close" onClick={close}><Icon name="x" /></button>}</div>

      <input ref={cam} type="file" accept="image/*" capture="environment" hidden onChange={onFile} />
      <input ref={pick} type="file" hidden onChange={onFile} />

      {!file && (
        <div class="source">
          <button onClick={() => choose(cam)}><Icon name="camera" /><strong>Take a photo</strong><span>Passport, license, card</span></button>
          <button onClick={() => choose(pick)}><Icon name="file" /><strong>Choose a file</strong><span>PDF, image, any type up to 50 MB</span></button>
        </div>
      )}

      {file && st.stage == null && (
        <>
          <div class="doc-hero">
            <span class="ico item" style={{ padding: 0, border: 0, background: "none" }}><span class="ico" data-cat={cat}><Icon name={kindIcon(file.type)} /></span></span>
            <div style={{ minWidth: 0 }}><div class="name" style={{ fontWeight: 600, overflowWrap: "anywhere" }}>{file.name}</div><div class="muted small">{fmtSize(file.size)} · {file.type || "file"}</div></div>
          </div>
          <div class="field">
            <label for="doc-name">Name</label>
            <input id="doc-name" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" />
          </div>
          <div class="field">
            <label>Category</label>
            <div class="cats">
              {CATEGORIES.map((c) => <button aria-pressed={cat === c.id} onClick={() => setCat(c.id)}><Icon name={c.icon} />{c.label}</button>)}
            </div>
          </div>
          <div class="actions">
            <button class="btn primary block" onClick={() => addDocument({ file, name, category: cat })}><Icon name="fingerprint" />Seal &amp; store</button>
            <button class="btn ghost block" onClick={() => setFile(null)}>Choose another</button>
          </div>
          <p class="fine" style={{ marginTop: 12 }}>Encrypted on this phone with ML-KEM-1024 + X25519 and signed with ML-DSA-87 before upload. The original isn't kept.</p>
        </>
      )}

      {file && st.stage != null && (
        <Steps current={stageIdx} steps={["Sealing on this device", "Sending over HTP/1", "Stored · signature verified by the vault"]} />
      )}
    </Sheet>
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
            <div class="row"><span class="k">Sealed with</span><span class="v"><AssurancePill assurance={item.assurance} /></span></div>
            <div class="row"><span class="k">Encryption</span><span class="v mono" style={{ fontSize: 12 }}>ML-KEM-1024 + X25519 · AES-256-GCM</span></div>
            <div class="row"><span class="k">Signature</span><span class="v mono" style={{ fontSize: 12 }}>ML-DSA-87 ✓ verified by vault</span></div>
          </div>
          <div class="actions">
            <button class="btn secure block" onClick={() => openItem(item)}><Icon name="eye" />Open</button>
            <div class="split">
              <button class="btn quiet" onClick={() => saveCopy(item)}><Icon name="download" />Save copy</button>
              <button class="btn quiet" onClick={() => setMode("edit")}><Icon name="pencil" />Rename</button>
            </div>
            <div class="split">
              <button class="btn quiet" onClick={() => exportSealed(item)}><Icon name="lock" />Sealed copy</button>
              <button class="btn danger" onClick={() => setMode("confirm")}><Icon name="trash" />Delete</button>
            </div>
          </div>
          <p class="fine" style={{ marginTop: 12 }}>Opening, saving and deleting each need a fresh biometric check. Every one is recorded in Activity.</p>
        </>
      )}

      {mode === "edit" && (
        <>
          <div class="field"><label for="rename">Name</label><input id="rename" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" /></div>
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
  return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" onClick={closeViewer}><Icon name="x" /></button>
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
