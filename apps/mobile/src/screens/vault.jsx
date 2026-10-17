// Vault: list, search, kinds and tags, item details, preview.
import { useState } from "preact/hooks";
import { KINDS, TAGS, kindOf, tagOf } from "../core/categories.js";
import { Mark } from "../brand.jsx";
import { Icon, kindIcon } from "../icons.jsx";
import { Sheet, fmtSize, fmtDate, fmtAgo, AssurancePill, OfflineBanner } from "../ui.jsx";
import { openExternal } from "../core/external.js";
import { formatCoords, formatAccuracy, mapLink, validStamp } from "../core/place.js";
import * as S from "../core/state.js";
import { openItem, saveCopy, exportSealed, deleteItem, renameItem, closeViewer, lockNow, setDecoy, setPinned } from "../core/controller.js";
import { IdView } from "./ids.jsx";
import { status as idStatus, kindLabel } from "@humid/idscan";
import { CardView } from "./cards.jsx";
import { BRANDS, expiryStatus, showExpiry } from "@humid/cards";
import { STYLE_LABEL } from "@humid/wallet";
import { PassView } from "./passes.jsx";
import { TagPicker, Push } from "./review.jsx";
import { openAdd } from "./add.jsx";

export function Vault() {
  const list = S.visibleItems.value;
  const all = S.items.value;
  const u = S.usage.value;
  return (
    <main class="screen with-tabs">
      <div class="topbar">
        <div class="grow">
          <h1>Vault</h1>
          <div class="sub"><Icon name="lock" />{all.length} {all.length === 1 ? "item" : "items"} · sealed on this phone{u ? ` · ${fmtSize(u.bytes)}` : ""}</div>
        </div>
        <button class="icon-btn" aria-label="Lock now" onClick={lockNow}><Icon name="lock" /></button>
      </div>

      <OfflineBanner />

      {S.alerts.value.length > 0 && (
        <button class="banner bad alert-banner" onClick={() => { S.tab.value = "you"; window.scrollTo({ top: 0 }); }}>
          <span class="b-ico"><Icon name="alert" /></span>
          <div><strong>Someone is recovering your HumID</strong><span>From {S.alerts.value[0].platform}. If this isn't you, cancel it under You.</span></div>
        </button>
      )}

      {all.length > 0 && (
        <>
          <label class="search">
            <Icon name="search" />
            <input autocorrect="off" spellcheck={false} id="vault-search" type="search" placeholder="Search your vault" value={S.query.value} onInput={(e) => (S.query.value = e.currentTarget.value)} autocomplete="off" />
          </label>
          <div class="chips" role="group" aria-label="Filter by kind">
            <button class="chip" aria-pressed={S.filter.value === "all"} onClick={() => (S.filter.value = "all")}>All <span class="count">{S.counts.value.all}</span></button>
            {KINDS.filter((k) => S.counts.value[k.id]).map((k) => (
              <button class="chip" aria-pressed={S.filter.value === k.id} onClick={() => (S.filter.value = k.id)}><Icon name={k.icon} />{k.label} <span class="count">{S.counts.value[k.id]}</span></button>
            ))}
          </div>
          <TagFilters />
        </>
      )}

      {S.loading.value && all.length === 0 && <p class="muted small" style={{ marginTop: 20 }}>Loading your vault…</p>}

      {!S.loading.value && all.length === 0 && (
        <div class="empty">
          <Mark />
          <h3>Nothing here yet</h3>
          <p>Your IDs, cards and documents, sealed on this phone before they go anywhere.</p>
          {!S.offline.value && <button class="btn primary" onClick={openAdd}><Icon name="plus" />Add to your vault</button>}
        </div>
      )}

      {all.length > 0 && list.length === 0 && <p class="muted" style={{ marginTop: 24, textAlign: "center" }}>Nothing matches “{S.query.value}”.</p>}

      <div class="list">
        {list.map((it) => <ItemRow item={it} key={it.id} />)}
      </div>

      {all.length > 0 && !S.offline.value && (
        <button class="fab" aria-label="Add to your vault" onClick={openAdd}><Icon name="plus" /></button>
      )}
    </main>
  );
}

/** The secondary row: filter by tag, offered only when something carries a tag. */
function TagFilters() {
  const [open, setOpen] = useState(false);
  const tc = S.tagCounts.value;
  const used = TAGS.filter((t) => tc[t.id]);
  if (!used.length) { if (S.tagFilter.value) S.tagFilter.value = null; return null; }
  const on = S.tagFilter.value;
  return (
    <div class="tagfilters" data-open={open || on ? "1" : "0"}>
      {!open && !on && <button class="linklike" onClick={() => setOpen(true)}>More filters</button>}
      {(open || on) && (
        <div class="chips" role="group" aria-label="Filter by tag">
          <button class="chip" aria-pressed={!on} onClick={() => { S.tagFilter.value = null; setOpen(false); }}>Any tag</button>
          {used.map((t) => (
            <button class="chip" aria-pressed={on === t.id} onClick={() => (S.tagFilter.value = on === t.id ? null : t.id)}><Icon name={t.icon} />{t.label} <span class="count">{tc[t.id]}</span></button>
          ))}
        </div>
      )}
    </div>
  );
}

export const brandName = (id) => BRANDS.find((b) => b.id === id)?.name || "Card";

/** The small tag labels after an item's facts. */
export function TagLabels({ tags }) {
  const list = (tags || []).map(tagOf).filter(Boolean);
  if (!list.length) return null;
  return <>{list.map((t) => <span class="tag" key={t.id}>{t.label}</span>)}</>;
}

/** One line of facts about an item, as the list and the item screen show it. */
export function itemMeta(item) {
  const card = item.cardInfo;
  if (card) {
    const cs = expiryStatus(card.expiry);
    return <>{brandName(card.brand)} •••• {card.last4} · {cs.state === "expired" ? <b class="warn-text">expired</b> : cs.state === "expiring" ? <b class="warn-text">expires {showExpiry(card.expiry)}</b> : card.expiry ? `expires ${showExpiry(card.expiry)}` : "no expiry"}</>;
  }
  const pi = item.passInfo;
  if (pi) {
    const when = pi.relevant || pi.expires;
    const gone = pi.voided || (pi.expires && Date.parse(pi.expires) < Date.now());
    return <>{STYLE_LABEL[pi.style] || "Pass"} · {pi.issuer || pi.organization}{gone ? <> · <b class="warn-text">{pi.voided ? "voided" : "expired"}</b></> : when ? ` · ${fmtDate(when)}` : ""}</>;
  }
  const id = item.idInfo;
  if (id) {
    const st = idStatus({ fields: { expiry: id.expiry } }, new Date(), S.prefs.value.expiryWarnDays);
    return <>{kindLabel(id.kind)} · {st.state === "expired" ? <b class="warn-text">expired</b> : st.state === "expiring" ? <b class="warn-text">expires in {st.days} days</b> : id.expiry ? `expires ${fmtDate(`${id.expiry}T12:00:00`)}` : "no expiry"}</>;
  }
  return <>{kindOf(item.kind).one} · {fmtSize(item.size)} · {fmtAgo(item.uploadedAt)}</>;
}

/** The icon for an item: its kind's, or the file type's for a file. */
export const itemIcon = (item) => item.idInfo ? (item.idInfo.kind === "passport" ? "passport" : "idcard") : item.kind === "file" ? kindIcon(item.type) : kindOf(item.kind).icon;

function ItemRow({ item }) {
  return (
    <button class="item" data-kind={item.kind} data-pinned={item.pinned ? "1" : undefined} onClick={() => (S.sheet.value = { type: "item", id: item.id })}>
      <span class="ico" data-kind={item.kind}><Icon name={itemIcon(item)} /></span>
      <span style={{ minWidth: 0 }}>
        <div class="name">{item.pinned && <Icon name="pushpin" />}{item.name}</div>
        <div class="meta">{itemMeta(item)}<TagLabels tags={item.tags} /></div>
      </span>
      <span class="end"><Icon name="chevron" /></span>
    </button>
  );
}

/** The location stamp, if there is one: coordinates, accuracy, and a map opened only on a tap. */
function SealedAt({ place }) {
  if (!validStamp(place)) return null;
  return (
    <div class="row"><span class="k">Location stamp</span>
      <span class="v place-v">
        <span class="mono" style={{ fontSize: 12 }}>{formatCoords(place)}</span>
        <span class="muted small">{formatAccuracy(place.accuracy)} · as the phone reported · <button class="linklike" type="button" onClick={() => openExternal(mapLink(place))}>Show on a map</button></span>
      </span>
    </div>
  );
}

/* ---------------- item ---------------- */

/**
 * An item, pushed over the vault: the preview first (a locked placeholder with one Open;
 * a card's masked number; a pass's summary), then the facts, then an overflow menu
 * (Rename · Pin · Show in decoy · Export sealed · Delete). Save a copy lives in the
 * opened Viewer, which has its own check. Open, Export and Delete are each one check.
 */
export function Item() {
  const st = S.sheet.value;
  const item = S.items.value.find((i) => i.id === st.id);
  const [mode, setMode] = useState("view"); // view | menu | edit | delete
  const [name, setName] = useState(item?.name || "");
  const [tags, setTags] = useState(item?.tags || []);
  if (!item) return null;
  const k = kindOf(item.kind);
  const close = () => (S.sheet.value = null);
  const off = !!S.offline.value;
  const card = item.cardInfo, pi = item.passInfo, id = item.idInfo;
  const decoyOffered = S.duressInfo.value?.setting?.enabled && !S.decoy.value && !off;

  return (
    <>
      <Push label={item.name} eyebrow={k.one} title={item.name} onBack={close} right={!off && mode !== "edit" && mode !== "delete" && <button class="icon-btn" aria-label="More" aria-haspopup="menu" onClick={() => setMode("menu")}><Icon name="more" /></button>}>
        {mode !== "edit" && mode !== "delete" && (
          <>
            <div class="item-hero" data-kind={item.kind}>
              {card ? (
                <>
                  <div class={`pay-card brand-${card.brand}`} aria-label={`${brandName(card.brand)} card`}>
                    <div class="pc-top"><span class="pc-brand">{brandName(card.brand)}</span>{expiryStatus(card.expiry).state === "expired" && <span class="pc-flag">Expired</span>}</div>
                    <div class="pc-number mono" data-card="number">•••• {card.last4}</div>
                    <div class="pc-bottom"><span>{card.nickname || " "}</span><span class="mono">{showExpiry(card.expiry)}</span></div>
                  </div>
                  <button class="btn secure block" disabled={off} onClick={() => openItem(item)}><Icon name="eye" />Show the number</button>
                </>
              ) : pi ? (
                <>
                  <span class="big" data-kind="pass"><Icon name="ticket" /></span>
                  <div><div style={{ fontWeight: 600 }}>{STYLE_LABEL[pi.style] || "Pass"} · {pi.issuer || pi.organization}</div><div class="muted small">{pi.voided ? "Voided" : pi.expires ? `${Date.parse(pi.expires) < Date.now() ? "Expired" : "Expires"} ${fmtDate(pi.expires)}` : pi.relevant ? fmtDate(pi.relevant) : "Checked against its issuer when it was added"}</div></div>
                  <button class="btn secure block" disabled={off} onClick={() => openItem(item)}><Icon name="eye" />Open</button>
                </>
              ) : (
                <>
                  <span class="big" data-kind={item.kind}><Icon name={itemIcon(item)} /></span>
                  <div class="muted small">{id ? `${kindLabel(id.kind)} · sealed with its photos` : "Sealed. Nothing here can show it until a check opens it."}</div>
                  <button class="btn secure block" disabled={off} onClick={() => openItem(item)}><Icon name="eye" />Open</button>
                </>
              )}
            </div>
            {off && (
              <div class="banner warn" role="note" style={{ marginTop: 14 }}>
                <span class="b-ico"><Icon name="signal" /></span>
                <div><strong>Opening needs a connection</strong><span>The document itself and its key are only in your vault. Nothing here can open it offline.</span></div>
              </div>
            )}
            <div class="card" style={{ marginTop: 14 }}>
              <div class="row"><span class="k">Kind</span><span class="v">{k.one}</span></div>
              {item.tags?.length > 0 && <div class="row"><span class="k">Tags</span><span class="v"><TagLabels tags={item.tags} /></span></div>}
              <div class="row"><span class="k">Size</span><span class="v">{fmtSize(item.size)}</span></div>
              <div class="row"><span class="k">Sealed</span><span class="v">{fmtDate(item.sealedAt || item.uploadedAt)}</span></div>
              <SealedAt place={item.place} />
              {(id?.expiry || card?.expiry || pi?.expires) && <div class="row"><span class="k">Expires</span><span class="v">{id ? fmtDate(`${id.expiry}T12:00:00`) : card ? showExpiry(card.expiry) : fmtDate(pi.expires)}</span></div>}
              <div class="row"><span class="k">Sealed with</span><span class="v"><AssurancePill assurance={item.assurance} /></span></div>
            </div>
            <p class="fine" style={{ marginTop: 12 }}>Opening, saving and deleting each need a fresh check. Every one is recorded in Activity.</p>
          </>
        )}

        {mode === "edit" && (
          <>
            <div class="field"><label for="rename">Name</label><input autocorrect="off" spellcheck={false} id="rename" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" /></div>
            <TagPicker tags={tags} onChange={setTags} />
            <div class="actions">
              <button class="btn primary block" onClick={() => renameItem(item, name, tags)}>Save changes</button>
              <button class="btn ghost block" data-back onClick={() => setMode("view")}>Cancel</button>
            </div>
          </>
        )}

        {mode === "delete" && (
          <>
            <div class="banner bad" style={{ marginTop: 14 }}><span class="b-ico"><Icon name="trash" /></span><div><strong>Delete {item.name}?</strong><span>It's gone from your vault for good. Copies you saved elsewhere stay.</span></div></div>
            <div class="actions">
              <button class="btn danger block" onClick={() => deleteItem(item)}><Icon name="fingerprint" />Delete</button>
              <button class="btn ghost block" data-back onClick={() => setMode("view")}>Keep it</button>
            </div>
          </>
        )}
      </Push>

      {mode === "menu" && (
        <Sheet onClose={() => setMode("view")} label="More">
          <div class="s-head"><div class="grow"><div class="eyebrow">{k.one}</div><h2 style={{ marginTop: 4 }}>{item.name}</h2></div>
            <button class="icon-btn" aria-label="Close" data-back onClick={() => setMode("view")}><Icon name="x" /></button></div>
          <div class="menu" role="menu">
            <button role="menuitem" onClick={() => setMode("edit")}><Icon name="pencil" />Rename</button>
            <button role="menuitem" onClick={() => { setMode("view"); setPinned(item, !item.pinned); }}><Icon name="pushpin" />{item.pinned ? "Unpin" : "Pin to the top"}</button>
            {decoyOffered && <button role="menuitem" onClick={() => { setMode("view"); setDecoy(item, !item.decoy); }}><Icon name="eye" />{item.decoy ? "Hide from the decoy view" : "Show in decoy view"}</button>}
            <button role="menuitem" onClick={() => { setMode("view"); exportSealed(item); }}><Icon name="lock" />Export sealed</button>
            <button role="menuitem" class="danger" onClick={() => setMode("delete")}><Icon name="trash" />Delete</button>
          </div>
        </Sheet>
      )}
    </>
  );
}

/* ---------------- viewer ---------------- */

export function Viewer() {
  const v = S.viewer.value;
  if (!v) return null;
  const isImg = v.type.startsWith("image/");
  const isPdf = v.type === "application/pdf";
  if (v.pass || v.passError) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name} onCopy={(e) => e.preventDefault()}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Open only on this phone · wiped when you close it</div></div>
      </header>
      <div class="body id-body"><PassView v={v} /></div>
          </div>
  );
  if (v.cardRecord) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name} onCopy={(e) => e.preventDefault()}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Open only on this phone · wiped when you close it</div></div>
      </header>
      <div class="body id-body"><CardView record={v.cardRecord} /></div>
          </div>
  );
  if (v.idRecord) return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name} onCopy={(e) => e.preventDefault()}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Open only on this phone · wiped when you close it</div></div>
      </header>
      <div class="body id-body"><IdView record={v.idRecord} item={v.item} /></div>
          </div>
  );
  return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name} onCopy={(e) => e.preventDefault()}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="name">{v.name}</div><div class="muted small">Open only on this phone · wiped when you close it</div></div>
        <button class="icon-btn" aria-label="Save a copy" onClick={() => saveCopy(v.item)}><Icon name="download" /></button>
      </header>
      <div class="body">
        {v.text != null && <pre>{v.text}</pre>}
        {isImg && <img src={v.url} alt={v.name} />}
        {/* Not sandboxed: Chromium (Android, Windows, this test runner) refuses to show a PDF inside a sandboxed
            frame at all, whatever the allow-list (checked with sandbox="", allow-scripts, and both with
            allow-same-origin: every one gives the broken-document icon). The blob is this origin's own
            decrypted bytes; copying and selection are blocked on the viewer instead. */}
        {isPdf && <iframe src={v.url} title={v.name} referrerpolicy="no-referrer" />}
        {!isImg && !isPdf && v.text == null && (
          <div class="empty" style={{ marginTop: 0 }}>
            <Icon name="file" />
            <p>This file type can't be shown here. Save a copy to open it in another app.</p>
            <button class="btn secure" onClick={() => saveCopy(v.item)}><Icon name="download" />Save a copy</button>
          </div>
        )}
      </div>
          </div>
  );
}
