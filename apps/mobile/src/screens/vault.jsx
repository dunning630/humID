// Vault: the list, search, kinds and tags; the item screen; the viewer.
import { useEffect, useState } from "preact/hooks";
import { KINDS, TAGS, kindOf, tagOf } from "../core/categories.js";
import { Hand } from "../brand/mark.jsx";
import { Icon, kindIcon } from "../brand/icons.jsx";
import { Pushed, Sheet, Menu, Confirm, Banner, Empty, Row, AssurancePill, useNow } from "../ui/kit.jsx";
import { fmtSize, fmtDate, fmtTime, fmtAgo, fmtLeft } from "../ui/format.js";
import { sealTime } from "../core/sealtime.js";
import { openExternal } from "../core/external.js";
import { formatCoords, formatAccuracy, mapLink, validStamp } from "../core/place.js";
import * as S from "../core/state.js";
import { openItem, saveCopy, exportSealed, deleteItem, renameItem, closeViewer, lockNow, setDecoy, setPinned, cancelRecovery, checkIn } from "../core/index.js";
import { TagPicker } from "../ui/tags.jsx";
// Opening Add is a push; the flow itself (camera, readers) is a chunk main.jsx loads then.
const openAdd = () => { S.push.value = { type: "add", kind: null, n: Date.now() }; };
import { lazy, Suspense } from "preact/compat";

// The viewers for IDs, payment cards and Wallet passes live with the add flow's chunk.
const IdView = lazy(() => import("./add/ids.jsx").then((m) => ({ default: m.IdView })));
const CardView = lazy(() => import("./add/cards.jsx").then((m) => ({ default: m.CardView })));
const PassView = lazy(() => import("./add/passes.jsx").then((m) => ({ default: m.PassView })));

/* ---------------- banners every tab shows ---------------- */

export function TabBanners() {
  return (
    <>
      <OfflineBanner />
      <HeartbeatBar />
      <ErasedBanner />
    </>
  );
}

function OfflineBanner() {
  const o = S.offline.value;
  if (!o) return null;
  return <Banner tone="amber" icon="signal" title="Offline · read only" text={`Your vault as it was ${o.savedAt ? fmtAgo(o.savedAt) : "last time you were online"}. Opening or changing anything needs a connection.`} action={S.online.value ? (S.link.value.state === "up" ? "Reconnect" : "Try again") : null} onAction={() => import("../core/index.js").then((m) => m.reconnect())} />;
}

/** Heartbeat, while armed: when the next one is due, in the server's time, with the button. */
function HeartbeatBar() {
  const st = S.checkin.value;
  const armed = st && (st.state === "armed" || st.state === "locked") && !S.offline.value;
  const now = useNow(armed ? 1000 : 3_600_000) + (st?.offsetMs || 0);
  if (!armed) return null;
  const left = st.deadline - now;
  const missed = st.state === "locked" || left <= 0;
  const soon = !missed && left <= 30 * 60_000;
  const skew = Math.abs(st.offsetMs || 0) > 60_000;
  return (
    <Banner tone={missed ? "danger" : soon ? "amber" : ""} icon={missed ? "alert" : "clock"} role="status"
      title={missed ? "Heartbeat missed" : `Heartbeat due by ${fmtTime(st.deadline)}`}
      text={missed ? `Your vault opens nothing until you do. Erased in ${fmtLeft(st.erasesAt - now)}.` : `${left < 3_600_000 ? `${Math.max(1, Math.ceil(left / 60_000))} min` : fmtLeft(left)} left${skew ? " · your phone's clock is off; this is your vault's time" : ""}`}
      action="Heartbeat" onAction={() => checkIn()} />
  );
}

/** After a Heartbeat erase, on the Vault for a week: what happened, said once, plainly. */
function ErasedBanner() {
  const st = S.checkin.value;
  if (st?.state !== "erased" || !st.erasedAt || Date.now() - st.erasedAt > 7 * 86_400_000 || S.offline.value) return null;
  return <Banner tone="danger" icon="trash" title="Your vault was erased by Heartbeat" text={`${fmtAgo(st.erasedAt)}. Those documents can't be opened again, by anyone. Your HumID still works, and anything sealed since is here.`} />;
}

/* ---------------- the vault ---------------- */

export function Vault() {
  const list = S.visibleItems.value;
  const all = S.items.value;
  const u = S.usage.value;
  const off = !!S.offline.value;
  const alert = S.alerts.value[0];
  return (
    <main class="screen tabs">
      <header class="top">
        <div class="grow">
          <h1>Vault</h1>
          <div class="small muted">{all.length} {all.length === 1 ? "item" : "items"} · sealed on this phone{u ? ` · ${fmtSize(u.bytes)}` : ""}</div>
        </div>
        <button class="icon-btn" aria-label="Lock now" onClick={lockNow}><Icon name="lock" /></button>
      </header>
      <TabBanners />
      {alert && <Banner tone="danger" icon="alert" title="Someone is recovering your HumID" text={`From ${alert.platform}. If this isn't you, cancel it now.`} action="Cancel it" onAction={() => cancelRecovery(alert)} />}

      {all.length > 0 && (
        <div class="stack">
          <label class="search">
            <Icon name="search" />
            <input autocorrect="off" spellcheck={false} id="vault-search" type="search" placeholder="Search your vault" value={S.query.value} onInput={(e) => (S.query.value = e.currentTarget.value)} autocomplete="off" />
            {S.query.value && <button class="icon-btn" style={{ width: 36, height: 36 }} aria-label="Clear search" onClick={() => (S.query.value = "")}><Icon name="x" /></button>}
          </label>
          <div class="chips" role="group" aria-label="Filter by kind">
            <button class="chip" aria-pressed={S.filter.value === "all"} onClick={() => (S.filter.value = "all")}>All <span class="n">{S.counts.value.all}</span></button>
            {KINDS.filter((k) => S.counts.value[k.id]).map((k) => (
              <button class="chip" aria-pressed={S.filter.value === k.id} onClick={() => (S.filter.value = k.id)}><Icon name={k.icon} />{k.label} <span class="n">{S.counts.value[k.id]}</span></button>
            ))}
          </div>
          <TagFilters />
        </div>
      )}

      {S.loading.value && all.length === 0 && <p class="muted small" style={{ marginTop: 20 }}>Loading your vault…</p>}
      {!S.loading.value && all.length === 0 && (
        <Empty icon="vault" title="Nothing here yet" text="Your IDs, cards and documents, sealed on this phone before they go anywhere.">
          <Hand size={56} />
          {!off && <button class="btn primary" onClick={() => openAdd()}><Icon name="plus" />Add to your vault</button>}
          {off && <p class="fine">Adding needs a connection.</p>}
        </Empty>
      )}
      {all.length > 0 && list.length === 0 && <p class="muted center" style={{ marginTop: 24 }}>{S.query.value ? `Nothing matches “${S.query.value}”.` : S.tagFilter.value ? "Nothing with this tag." : "Nothing of this kind."}</p>}

      {list.length > 0 && <div class="rows" style={{ marginTop: 14 }}>{list.map((it) => <ItemRow item={it} key={it.id} />)}</div>}

      {all.length > 0 && (
        <button class="btn primary" style={{ position: "fixed", right: "max(16px, calc(50% - var(--col) / 2 + 16px))", bottom: "calc(var(--safe-b) + var(--tabbar-h) + 16px)", zIndex: 31, width: 56, height: 56, padding: 0, borderRadius: 999, opacity: off ? 0.5 : 1 }}
          aria-label="Add to your vault" onClick={() => (off ? import("../core/index.js").then((m) => m.toast("Adding needs a connection to your vault.", "warn")) : openAdd())}>
          <Icon name="plus" />
        </button>
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
  if (!open && !on) return <button class="link muted" style={{ minHeight: 32 }} onClick={() => setOpen(true)}>More filters</button>;
  return (
    <div class="chips" role="group" aria-label="Filter by tag">
      <button class="chip" aria-pressed={!on} onClick={() => { S.tagFilter.value = null; setOpen(false); }}>Any tag</button>
      {used.map((t) => <button class="chip" aria-pressed={on === t.id} onClick={() => (S.tagFilter.value = on === t.id ? null : t.id)}><Icon name={t.icon} />{t.label} <span class="n">{tc[t.id]}</span></button>)}
    </div>
  );
}

/* ---------------- one item in the list ---------------- */

const CARD_BRANDS = { visa: "Visa", mastercard: "Mastercard", amex: "American Express", discover: "Discover", jcb: "JCB", diners: "Diners Club", unionpay: "UnionPay" };
export const brandName = (id) => CARD_BRANDS[id] || "Card";
const showExpiry = (e) => (e ? `${String(e.month).padStart(2, "0")}/${String(e.year).slice(-2)}` : "");
const expiryState = (iso, warnDays) => {
  if (!iso) return { state: "none" };
  const d = Math.round((Date.parse(`${iso}T12:00:00`) - Date.now()) / 86_400_000);
  return d < 0 ? { state: "expired", days: d } : d <= warnDays ? { state: "expiring", days: d } : { state: "ok", days: d };
};
const cardExpiryState = (e) => {
  if (!e?.year) return { state: "none" };
  const end = new Date(e.year, e.month, 0, 23, 59);
  const d = Math.round((end - Date.now()) / 86_400_000);
  return d < 0 ? { state: "expired" } : d <= 60 ? { state: "expiring" } : { state: "ok" };
};
const PASS_STYLES = { boardingPass: "Boarding pass", coupon: "Coupon", eventTicket: "Ticket", storeCard: "Store card", generic: "Pass" };
const ID_KINDS = { passport: "Passport", driver_license: "Driver's license", id_card: "ID card", residence_permit: "Residence permit" };

export function TagLabels({ tags }) {
  const list = (tags || []).map(tagOf).filter(Boolean);
  if (!list.length) return null;
  return <>{list.map((t) => <span class="pill" key={t.id} style={{ padding: "1px 8px" }}>{t.label}</span>)}</>;
}

/** One line of facts about an item, as the list and the item screen show it. */
export function itemMeta(item) {
  const card = item.cardInfo;
  if (card) {
    const cs = cardExpiryState(card.expiry);
    return <>{brandName(card.brand)} •••• {card.last4} · {cs.state === "expired" ? <b class="bad">expired</b> : cs.state === "expiring" ? <b class="warn">expires {showExpiry(card.expiry)}</b> : card.expiry ? `expires ${showExpiry(card.expiry)}` : "no expiry"}</>;
  }
  const pi = item.passInfo;
  if (pi) {
    const when = pi.relevant || pi.expires;
    const gone = pi.voided || (pi.expires && Date.parse(pi.expires) < Date.now());
    return <>{PASS_STYLES[pi.style] || "Pass"} · {pi.issuer || pi.organization}{gone ? <> · <b class="bad">{pi.voided ? "voided" : "expired"}</b></> : when ? ` · ${fmtDate(when)}` : ""}</>;
  }
  const id = item.idInfo;
  if (id) {
    const st = expiryState(id.expiry, S.prefs.value.expiryWarnDays);
    return <>{ID_KINDS[id.kind] || "ID"} · {st.state === "expired" ? <b class="bad">expired</b> : st.state === "expiring" ? <b class="warn">expires in {st.days} days</b> : id.expiry ? `expires ${fmtDate(`${id.expiry}T12:00:00`)}` : "no expiry"}</>;
  }
  return <>{kindOf(item.kind).one} · {fmtSize(item.size)} · {fmtAgo(item.uploadedAt)}</>;
}

export const itemIcon = (item) => item.idInfo ? (item.idInfo.kind === "passport" ? "passport" : "idcard") : item.kind === "file" ? kindIcon(item.type) : kindOf(item.kind).icon;

function ItemRow({ item }) {
  return (
    <button class="item" data-kind={item.kind} data-pinned={item.pinned ? "1" : undefined} onClick={() => (S.push.value = { type: "item", id: item.id })}>
      <span class="kind" data-k={item.kind}><Icon name={itemIcon(item)} /></span>
      <span style={{ minWidth: 0 }}>
        <div class="name ellipsis">{item.pinned && <Icon name="pushpin" style={{ width: 14, height: 14, display: "inline", verticalAlign: "-2px", marginRight: 4 }} />}{item.name}</div>
        <div class="meta">{itemMeta(item)}<TagLabels tags={item.tags} /></div>
      </span>
      <Icon name="chevron" />
    </button>
  );
}

/* ---------------- the item screen ---------------- */

function Fact({ k, v }) { return <Row chevron={false} title={k} trail={<span class="t2" style={{ textAlign: "right", whiteSpace: "normal" }}>{v}</span>} />; }

/**
 * An item, pushed over the vault: the preview first (one Open = one check), then the
 * facts, then a menu whose items each say what they do.
 */
export function Item() {
  const st = S.push.value;
  const item = S.items.value.find((i) => i.id === st?.id);
  const [mode, setMode] = useState("view"); // view | menu | edit | delete
  const [name, setName] = useState(item?.name || "");
  const [tags, setTags] = useState(item?.tags || []);
  if (!item) return null;
  const k = kindOf(item.kind);
  const sealed = sealTime(item);
  const close = () => (S.push.value = null);
  const off = !!S.offline.value;
  const card = item.cardInfo, pi = item.passInfo, id = item.idInfo;
  const decoyOffered = S.duressInfo.value?.setting?.enabled && !S.decoy.value && !off;
  const open = () => openItem(item);
  return (
    <>
      <Pushed title={item.name} onBack={mode === "view" ? close : () => setMode("view")} trailing={!off && mode === "view" && <button class="icon-btn" aria-label="More" aria-haspopup="menu" onClick={() => setMode("menu")}><Icon name="more" /></button>}>
        {(mode === "view" || mode === "menu") && (
          <>
            <div class="eyebrow" style={{ marginBottom: 8 }}>{k.one}</div>
            <div class="card center stack" style={{ alignItems: "center" }}>
              {card ? (
                <div class={`pay-card brand-${card.brand}`} aria-label={`${brandName(card.brand)} card`} style={{ width: "100%" }}>
                  <div class="pc-top"><span class="pc-brand">{brandName(card.brand)}</span>{cardExpiryState(card.expiry).state === "expired" && <span class="pc-flag">Expired</span>}</div>
                  <div class="pc-number mono" data-card="number">•••• {card.last4}</div>
                  <div class="pc-bottom"><span>{card.nickname || " "}</span><span class="mono">{showExpiry(card.expiry)}</span></div>
                </div>
              ) : (
                <span class="icon-btn" style={{ width: 72, height: 72, background: "var(--surface-3)", color: "var(--text-2)" }}><Icon name={pi ? "ticket" : itemIcon(item)} /></span>
              )}
              <div class="small muted">{card ? "The number and code open only after a check, for 30 seconds." : pi ? `${PASS_STYLES[pi.style] || "Pass"} · ${pi.issuer || pi.organization} · checked against its issuer when it was added` : id ? `${ID_KINDS[id.kind] || "ID"} · sealed with its photos` : "Sealed. Nothing here can show it until a check opens it."}</div>
              <button class="btn primary block" disabled={off} onClick={open}><Icon name="fingerprint" />{card ? "Show the number" : "Open"}</button>
            </div>
            {off && <div style={{ marginTop: 14 }}><Banner tone="amber" icon="signal" title="Opening needs a connection" text="The document and its key are only in your vault. Nothing here can open it offline." /></div>}
            <div class="rows" style={{ marginTop: 14 }}>
              <Fact k="Kind" v={k.one} />
              {item.tags?.length > 0 && <Fact k="Tags" v={<TagLabels tags={item.tags} />} />}
              <Fact k="Size" v={fmtSize(item.size)} />
              {sealed && <Fact k="Sealed" v={<>{fmtDate(sealed.at)}, {fmtTime(sealed.at)}{sealed.by === "phone" && <span class="muted"> (phone's clock)</span>}</>} />}
              {sealed?.phoneAt && <Fact k="Phone's clock" v={<span class="amber">said {fmtDate(sealed.phoneAt)}, {fmtTime(sealed.phoneAt)}. The time above is your vault's.</span>} />}
              {validStamp(item.place) && <Fact k="Location stamp" v={<><span class="mono small">{formatCoords(item.place)}</span><br /><span class="muted small">{formatAccuracy(item.place.accuracy)} · as the phone reported · <button class="link" style={{ minHeight: 0 }} type="button" onClick={() => openExternal(mapLink(item.place))}>Map</button></span></>} />}
              {item.placeNote && !validStamp(item.place) && <Fact k="Location stamp" v={<span class="muted">None: {item.placeNote}</span>} />}
              {(id?.expiry || card?.expiry || pi?.expires) && <Fact k="Expires" v={id ? fmtDate(`${id.expiry}T12:00:00`) : card ? showExpiry(card.expiry) : fmtDate(pi.expires)} />}
              <Fact k="Sealed with" v={<AssurancePill assurance={item.assurance} />} />
            </div>
            <p class="fine" style={{ marginTop: 12 }}>Opening, saving a copy and deleting each need a fresh check. Every one is recorded in Activity.</p>
          </>
        )}
        {mode === "edit" && (
          <div class="stack">
            <div class="field"><label for="rename">Name</label><input autocorrect="off" spellcheck={false} id="rename" class="input" value={name} onInput={(e) => setName(e.currentTarget.value)} maxLength={120} autocomplete="off" /></div>
            <TagPicker tags={tags} onChange={setTags} />
            <div class="actions">
              <button class="btn primary block" onClick={async () => { if (await renameItem(item, name, tags)) setMode("view"); }}>Save changes</button>
              <button class="btn ghost block" data-back onClick={() => setMode("view")}>Cancel</button>
            </div>
          </div>
        )}
        {mode === "delete" && (
          <>
            <div style={{ marginTop: 8 }}><Banner tone="danger" icon="trash" title={`Delete ${item.name}?`} text="It's gone from your vault for good. Copies you saved elsewhere stay." /></div>
            <div class="actions">
              <button class="btn danger solid block" onClick={async () => { if (await deleteItem(item)) close(); }}><Icon name="fingerprint" />Delete</button>
              <button class="btn ghost block" data-back onClick={() => setMode("view")}>Keep it</button>
            </div>
          </>
        )}
      </Pushed>
      {mode === "menu" && (
        <Sheet onClose={() => setMode("view")} eyebrow={k.one} title={item.name}>
          <div class="rows">
            <Row icon="pencil" title="Rename" sub="And change its tags" onClick={() => setMode("edit")} />
            <Row icon="pushpin" title={item.pinned ? "Unpin" : "Pin to the top"} sub="On every device; your vault can't see which are pinned" onClick={() => { setMode("view"); setPinned(item, !item.pinned); }} />
            {decoyOffered && <Row icon="eye" title={item.decoy ? "Hide from the decoy view" : "Show in decoy view"} sub="What a forced unlock shows instead of your real vault" onClick={() => { setMode("view"); setDecoy(item, !item.decoy); }} />}
            <Row icon="lock" title="Export sealed" sub="A backup copy only your HumID can open" onClick={() => { setMode("view"); exportSealed(item); }} />
            <Row icon="trash" danger title="Delete" sub="Gone from your vault for good" onClick={() => setMode("delete")} />
          </div>
        </Sheet>
      )}
    </>
  );
}

/* ---------------- the viewer ---------------- */

function ViewerShell({ v, children, trailing }) {
  const now = useNow(1000);
  const open = Math.round((now - (v.openedAt || now)) / 1000);
  return (
    <div class="viewer" role="dialog" aria-modal="true" aria-label={v.name} onCopy={(e) => e.preventDefault()}>
      <header>
        <button class="icon-btn" aria-label="Close and wipe" data-back onClick={closeViewer}><Icon name="x" /></button>
        <div class="grow"><div class="title ellipsis">{v.name}</div><div class="muted small">Open only on this phone · wiped when you close it</div></div>
        {trailing}
      </header>
      <div class="body">{children}</div>
      <div class="timer">Open for {open < 60 ? `${open} s` : fmtLeft(open * 1000)}. Close it when you're done.</div>
    </div>
  );
}

export function Viewer() {
  const v = S.viewer.value;
  if (!v) return null;
  const isImg = v.type.startsWith("image/");
  const isPdf = v.type === "application/pdf";
  const fallback = <p class="muted small center">Opening…</p>;
  if (v.pass || v.passError) return <ViewerShell v={v}><Suspense fallback={fallback}><PassView v={v} /></Suspense></ViewerShell>;
  if (v.cardRecord) return <ViewerShell v={v}><Suspense fallback={fallback}><CardView record={v.cardRecord} /></Suspense></ViewerShell>;
  if (v.idRecord) return <ViewerShell v={v}><Suspense fallback={fallback}><IdView record={v.idRecord} item={v.item} /></Suspense></ViewerShell>;
  const [confirm, setConfirm] = useState(false);
  return (
    <ViewerShell v={v} trailing={<button class="icon-btn" aria-label="Save a copy" onClick={() => setConfirm(true)}><Icon name="download" /></button>}>
      {v.text != null && <pre>{v.text}</pre>}
      {isImg && <img src={v.url} alt={v.name} />}
      {/* Not sandboxed: Chromium refuses to show a PDF inside a sandboxed frame at all (checked with every
          allow-list). The blob is this origin's own decrypted bytes; copying and selection are blocked instead. */}
      {isPdf && <iframe src={v.url} title={v.name} referrerpolicy="no-referrer" />}
      {!isImg && !isPdf && v.text == null && (
        <Empty icon="file" title="Can't be shown here" text="Save a copy to open it in another app.">
          <button class="btn primary" onClick={() => setConfirm(true)}><Icon name="download" />Save a copy</button>
        </Empty>
      )}
      {confirm && <Confirm title="Save an unsealed copy?" text="The copy on this device won't be sealed: any app, backup or person with the phone can read it. Saving needs its own check and is recorded in Activity." action="Save a copy" danger={false} onClose={() => setConfirm(false)} onConfirm={() => saveCopy(v.item)} />}
    </ViewerShell>
  );
}
