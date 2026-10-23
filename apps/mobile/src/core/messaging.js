// Person to person (HumID 4.0, docs/MESSAGING.md), in the app. Loaded on demand after
// unlock, only when the server runs a relay; nothing here is in the first paint.
//
// The human-to-human rule (@humid/msg live.js) is applied here, at every step:
//
//   make an invite     a live check (it releases the account seed the persona comes from)
//   ask to connect     a live check; the request carries its live stamp
//   see who's asking   a live check (the request opens only with the persona's keys)
//   approve            a live check; the acceptance carries its live stamp
//   send anything      a live check; every message carries its live stamp
//   read               the holder's own live check within the freshness window; until then,
//                      what arrived stays ciphertext on this phone, counted but never opened
//   receive            every conversation is strict: a message without a valid live stamp
//                      is discarded unread, and nothing it says is applied
//
// Storage (one messaging device per account, for now):
//   "list"   the contact list and open invites, sealed under a key from the account seed
//            (R.msgKey, derived inside the unlock check and wiped on lock)
//   "c:<id>" one conversation (ratchet + history), sealed under a NEW random key every save;
//            that key is kept only wrapped under R.msgKey, in the same record, replaced each save
//   "w:<id>" ciphertext from the relay waiting for a fresh check, or a contact request waiting
//            for review; which conversation or invite, and when it came, sealed with it
//   "o:<id>" something to post that isn't part of a conversation (an invite bundle, or what a
//            deleted conversation still had to send), sealed like "w:"; a conversation's own
//            unposted messages live inside its sealed save instead (PC-28). Sent a few seconds
//            later, retried on every poll.
//
// The relay is reached from sessions that never sign in (one per deposit; one per conversation
// for polling, replaced every few minutes), so no account is ever attached to a mailbox; the server still sees the network address that
// posts, and a VPN or Tor is how to hide that. Stamps come from the signed-in session, inside a live step-up
// over exactly the blinded values, so the issuer learns that this account asked, never for what.
import * as M from "@humid/msg";
import { batch } from "@preact/signals";
import * as S from "./state.js";
import { R, wipe } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withKeys, withStepUp, needVault } from "./interrupt.js";

const POLL_MS = 12_000;
const FAST_POLL_MS = 2_500;   // while a screen is waiting on the other phone (an invite on show, a request out)
let fastUntil = 0;
const MAX_LABEL = 40;
const te = new TextEncoder(), td = new TextDecoder();

let started = false;
let keyset = null;
let timer = null;
let polling = null;
let list = null;              // { v, contacts: [], invites: [] }  (decrypted, in memory while unlocked)
const convs = new Map();      // conversation id (hex) → Conversation
const reviews = new Map();    // request id → { shown, invite, persona } between "see who's asking" and approve/decline
let listWrite = Promise.resolve();
let openThread = null;        // the conversation on screen, if any
let lapseTimer = null;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const rid = () => hex(crypto.getRandomValues(new Uint8Array(12)));
const now = () => Date.now();
/* global __HUMID_ALLOW_DEMO__ */
// The freshness window (live.js). Development builds only may shorten it (localStorage
// humidLiveWindowMs, 30 s to 5 min) so a browser test can watch it lapse in real time;
// release builds fold this to the constant and carry no override.
const WINDOW = (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)
  ? (() => { try { const w = Number(globalThis.localStorage?.getItem("humidLiveWindowMs")); return w >= M.MIN_LIVE_WINDOW_MS && w <= M.LIVE_WINDOW_MS ? w : M.LIVE_WINDOW_MS; } catch { return M.LIVE_WINDOW_MS; } })()
  : M.LIVE_WINDOW_MS;
const fresh = () => M.canRead({ ownAt: S.liveAt.value || null, now: now(), windowMs: WINDOW });

/* ---------------- sealing under R.msgKey ---------------- */

async function aes(key, usage) { return crypto.subtle.importKey("raw", key, "AES-GCM", false, [usage]); }
async function seal(value, aad) {
  if (!R.msgKey) throw Object.assign(new Error("Locked"), { code: "locked" });
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: te.encode(aad) }, await aes(R.msgKey, "encrypt"), value));
  const out = new Uint8Array(12 + ct.length); out.set(nonce); out.set(ct, 12);
  return out;
}
async function unseal(blob, aad) {
  if (!R.msgKey) throw Object.assign(new Error("Locked"), { code: "locked" });
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: te.encode(aad) }, await aes(R.msgKey, "decrypt"), blob.subarray(12)));
}

/* ---------------- the contact list ---------------- */

async function loadList() {
  const rec = await R.store.getMsg("list");
  if (!rec) return { v: 1, contacts: [], invites: [] };
  const o = M.fromPlain(JSON.parse(td.decode(await unseal(rec.blob, "HUMID-MSG-v1 list"))));
  return o?.v === 1 ? o : { v: 1, contacts: [], invites: [] };
}
function saveList() {
  const snapshot = te.encode(JSON.stringify(M.toPlain(list)));
  listWrite = listWrite.then(async () => {
    await R.store.putMsg({ id: "list", blob: await seal(snapshot, "HUMID-MSG-v1 list") });
  });
  return listWrite;
}
const contactOf = (id) => list?.contacts.find((c) => c.id === id) || null;

/* ---------------- conversations ---------------- */

/** Every change is saved (new key, wrapped) before anything goes out (Conversation persist). */
const persistFor = (id) => async ({ blob, key }) => {
  try { await R.store.putMsg({ id: `c:${id}`, blob, key: await seal(key, `HUMID-MSG-v1 conversation key ${id}`) }); }
  finally { wipe(key); }
};

async function openConv(id) {
  if (convs.has(id)) return convs.get(id);
  const rec = await R.store.getMsg(`c:${id}`);
  if (!rec) return null;
  const key = await unseal(rec.key, `HUMID-MSG-v1 conversation key ${id}`);
  try {
    const c = await M.Conversation.open(key, rec.blob, { convId: unhex(id), persist: persistFor(id), requireLive: true });
    convs.set(id, c);
    return c;
  } finally { wipe(key); }
}
const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));

/** first: what started it (the request, or the accept), kept in its sealed outbox until posted. */
async function addConv(session, contact, { peerAt = null, first = null } = {}) {
  const id = hex(session.convId);
  const outbox = first ? [{ id: first.id || `first-${rid()}`, box: first.box, wire: first.wire, retractTag: first.retractTag || null, kind: "first", at: now() }] : [];
  const c = new M.Conversation(session, null, { persist: persistFor(id), requireLive: true, live: { peerAt }, outbox });
  convs.set(id, c);
  list.contacts.push({ ...contact, id });
  await c.seal().then(persistFor(id));
  await saveList();
  return c;
}

/* ---------------- posting: through an outbox, so nothing is lost to a dropped connection ---------------- */

// What the server could still put together (security review M2, MSG-02): it sees the address that
// asks for a stamp and the address that posts to a mailbox. Posts therefore go out a few seconds
// later, each from a relay session of its own; each conversation is polled from its own session,
// replaced every few minutes; a VPN or Tor hides the address.
const JITTER_MS = [1500, 6000];
const RELAY_SESSION_MS = 5 * 60_000;
let flushTimer = null;
/*
 * Two outboxes (PC-28). What a conversation sends is kept INSIDE its sealed save (Conversation
 * pending/posted), written in the same step as the ratchet move that made it, so a crash can't
 * lose a message or leave a gap. Everything else (an invite bundle) waits in an "o:" record,
 * sealed under R.msgKey like "w:", so the box id, unsend tag and time aren't in the clear (MSG-13).
 */
function soon() {
  clearTimeout(flushTimer);
  const [lo, hi] = JITTER_MS;
  flushTimer = setTimeout(() => { if (started) flush().catch(() => {}); }, lo + Math.floor(Math.random() * (hi - lo)));
}
async function post(items) {
  for (const x of items) {
    const id = `o:${rid()}`;
    const body = te.encode(JSON.stringify(M.toPlain({ at: now(), box: x.box, wire: x.wire, tag: x.retractTag || null })));
    await R.store.putMsg({ id, blob: await seal(body, `HUMID-MSG-v1 outbox ${id}`) });
  }
  soon();
}
async function openOutbox(rec) {
  try { return { id: rec.id, ...M.fromPlain(JSON.parse(td.decode(await unseal(rec.blob, `HUMID-MSG-v1 outbox ${rec.id}`)))) }; }
  catch { return null; }
}
/** Refused for good (malformed, oversized): retrying won't help. Offline, busy or full: try again later. */
const finalRefusal = (e) => e?.status >= 400 && e?.status < 500 && e?.status !== 429;
// Each deposit and each unsend from a relay session of its own (MSG-02), opened for it and closed
// after: the relay can't tie what this phone posts to what it fetches, or one post to another.
async function oneShot(fn) {
  const r = R.api.relay();
  try { return await fn(r); } finally { r.close(); }
}
const putOnce = (box, wire, tag) => oneShot((r) => r.put(box, wire, tag));
async function flush() {
  // conversations, oldest first, from their sealed outboxes
  for (const c of convs.values()) {
    const done = [];
    for (const p of c.pending()) {
      try { await putOnce(p.box, p.wire, p.retractTag); done.push(p.id); }
      catch (e) { if (finalRefusal(e)) done.push(p.id); else break; }
    }
    if (done.length) await c.posted(done).catch(() => {});
  }
  const out = [];
  for (const r of (await R.store.listMsg()).filter((x) => x.id.startsWith("o:"))) {
    // a record from before outbox records were sealed: posted as it is
    const o = r.blob ? await openOutbox(r) : r;
    if (o) out.push(o); else await R.store.delMsg(r.id);
  }
  for (const r of out.sort((a, b) => a.at - b.at)) {
    try { await putOnce(r.box, r.wire, r.tag); await R.store.delMsg(r.id); }
    catch (e) {
      if (finalRefusal(e)) await R.store.delMsg(r.id);
      else break;
    }
  }
}

/* ---------------- stamps: one live check, the exact blinded values ---------------- */

/**
 * The stamp keys: this epoch's and the next (an hour each), and the retired ones whose stamps
 * can still arrive. Fetched at start and again before the published ones run out (MSG-01).
 */
let archive = [];     // retired stamp keys (public), merged across fetches
let keysAt = 0;       // when the keys were last fetched
async function loadKeys() {
  // after the first fetch, only the keys retired since (the server leaves out what this phone has)
  const since = keyset ? Math.max(0, ...archive.map((k) => k.notAfter)) : 0;
  const k = await R.api.msgKeys({ since });
  const pub = k.stamp.keys || [];
  const ids = new Set(pub.map((x) => x.id));
  const today = new Date(now()).toISOString().slice(0, 10);
  const merged = new Map([...archive, ...(keyset?.published || []).map((x) => ({ id: x.id, n: x.n64, e: x.e64, notBefore: x.notBefore, notAfter: x.notAfter, acceptUntil: x.acceptUntil })), ...(k.stamp.archive || [])]
    .filter((x) => !ids.has(x.id) && x.notAfter <= now() && !(x.acceptUntil && x.acceptUntil < today)).map((x) => [x.id, x]));
  archive = [...merged.values()].sort((a, b) => b.notAfter - a.notAfter).slice(0, M.MAX_ARCHIVED_STAMP_KEYS);
  keyset = M.importStampKeys(pub, { passKeys: (k.passKeyIds || []).map((id) => ({ id })), archive });
  keysAt = now();
}
/**
 * Keys good for at least the next few minutes, so a stamp asked for now uses the right epoch's
 * key, and never more than a day old (MSG-07: a key announced since is known before it's used).
 */
async function freshKeys() {
  if (!keyset || keyset.until - now() < 10 * 60_000 || now() - keysAt > 24 * 3600_000) await loadKeys();
}

/** A stamper for the step-up `proof` of ONE live check (used once, up to the server's limit). */
function stampWith(proof) {
  let used = false;
  // at: the time the stamped messages will carry; it picks this epoch's stamp key (MSG-01)
  const many = async (commits, { at = now() } = {}) => {
    if (used) throw Object.assign(new Error("That live check was already used. Try again."), { code: "stamp_used" });
    if (commits.length > (S.server.value?.policy?.messaging?.stampsPerCheck || 1)) throw Object.assign(new Error("That's more than one live check can approve. Try a smaller step."), { code: "too_many_stamps" });
    used = true;
    const drafts = commits.map((c) => M.blindStamp(keyset, c, { at }));
    let sigs;
    try { sigs = await R.api.stamp({ kid: drafts[0].draft.kid, blinded: drafts.map((d) => d.blinded) }, proof); }
    catch (e) {
      // The key changed under us (an epoch ended mid-check, or this phone's list was stale). The
      // check's approval is used up, so fetch the keys now; the next check will use the right one.
      if (e?.code === "key_changed") { await loadKeys().catch(() => {}); throw Object.assign(new Error("The server just changed its stamp key. Nothing was sent. Try again."), { code: "key_changed" }); }
      throw e;
    }
    return drafts.map((d, i) => M.finalizeStamp(keyset, d.draft, sigs[i]));
  };
  return Object.assign(async (c, opts) => (await many([c], opts))[0], { many });
}
/**
 * Can this device get live stamps? Only a phone whose secure chip proves the check: the server
 * refuses anything else (stamp_needs_proven_phone, MSG-03), whatever lets it sign in.
 */
export const canStamp = () => S.server.value?.policy?.messaging?.stampNeeds === "any" || S.session.value?.assurance === "hardware";
const NEEDS_PHONE = "Connecting and sending need a phone whose secure chip proves a live face or fingerprint check. This device can't, so it can only read what's here.";

/** Run fn inside one live check that also produces stamps. fn gets { seed, stamper }. */
function live(purpose, label, fn) {
  needVault();
  if (!canStamp()) throw Object.assign(new Error(NEEDS_PHONE), { code: "stamp_needs_proven_phone" });
  return freshKeys().then(() => withStepUp("stamp", [], purpose, label, ({ seed, proof }) => fn({ seed, stamper: stampWith(proof) })));
}

/* ---------------- what the screens see ---------------- */

function publish() {
  if (!list) return;
  const t = now();
  const pendingBy = new Map();
  for (const [id, n] of pendingCount) pendingBy.set(id, n);
  const contacts = list.contacts.map((ct) => {
    const c = convs.get(ct.id);
    const msgs = c && fresh() ? c.messages(t) : [];
    const last = msgs[msgs.length - 1];
    const status = c ? c.status : "erased";
    const unreadIn = msgs.filter((m) => m.dir === "in" && m.at > (ct.lastRead || 0)).length;
    return {
      id: ct.id, label: ct.label, peerId: c?.session.peerId || ct.peerId || "", status,
      created: ct.createdAt, safetyVerified: ct.safetyVerified || false, safetyMismatch: ct.safetyMismatch || 0, duressAlert: !!ct.duressAlert, duressAt: ct.duressAt || 0, showHere: ct.showHere !== false,
      peerAt: c?.peerLiveAt ?? null, timer: c?.timer ?? 0,
      waiting: pendingBy.get(ct.id) || 0, unread: unreadIn,
      last: last ? { at: last.at, dir: last.dir, text: last.kind === "text" ? td.decode(last.body) : "Voice note or photo" } : null,
      lastAt: last?.at || ct.lastAt || ct.createdAt,
    };
  }).sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0));
  const invites = list.invites.filter((i) => !i.closed).map((i) => ({ id: i.id, code: i.code, expires: i.expires, label: i.label, created: i.createdAt, waiting: requestsFor(i.id) }));
  S.msg.value = {
    ready: true, error: null, contacts, invites, canStamp: canStamp(),
    // one row per invite until its requests are opened (MSG-09: junk is never listed), then one
    // per real request
    requests: requestRows(),
    newCount: contacts.reduce((n, c) => n + c.waiting + c.unread, 0) + requestRows().length,
  };
  if (openThread) showThread(openThread);
}
const pendingCount = new Map(); // conversation id → ciphertexts waiting to be read

/*
 * What arrived and waits for a fresh check: one record per object, with an opaque id. Which
 * conversation or invite it belongs to, and when it came, are sealed with it (security review L3).
 */
async function putWaiting(meta, wire) {
  const id = `w:${rid()}`;
  const body = te.encode(JSON.stringify(M.toPlain({ ...meta, wire })));
  await R.store.putMsg({ id, blob: await seal(body, `HUMID-MSG-v1 waiting ${id}`) });
  return id;
}
async function openWaiting(rec) {
  if (!rec?.id?.startsWith("w:")) return null;
  try { return { id: rec.id, ...M.fromPlain(JSON.parse(td.decode(await unseal(rec.blob, `HUMID-MSG-v1 waiting ${rec.id}`)))) }; }
  catch { return null; }
}
async function listWaiting() {
  const out = [];
  for (const r of await R.store.listMsg()) { const w = await openWaiting(r); if (w) out.push(w); }
  return out.sort((a, b) => a.at - b.at);
}
const requests = new Map();     // request id → { id, invite, at }
function requestRows() {
  const rows = [], unopened = new Map();
  for (const r of requests.values()) {
    const label = list?.invites.find((i) => i.id === r.invite)?.label || "";
    if (reviews.has(r.id)) rows.push({ id: r.id, invite: r.invite, label, at: r.at, opened: true });
    else if (!unopened.has(r.invite)) unopened.set(r.invite, { id: r.id, invite: r.invite, label, at: r.at, count: 1 });
    else unopened.get(r.invite).count++;
  }
  return [...rows, ...unopened.values()];
}
const requestsFor = (inviteId) => [...requests.values()].filter((r) => r.invite === inviteId).length;

/** The open conversation's messages, only while its holder's check is fresh. */
function showThread(id) {
  const c = convs.get(id);
  const ct = contactOf(id);
  if (!c || !ct) { S.thread.value = null; return; }
  if (!fresh()) { S.thread.value = { id, locked: true, waiting: pendingCount.get(id) || 0, count: Math.min(12, c.messages(now()).length) }; return; }
  const msgs = c.messages(now()).map((m) => ({
    id: m.id, dir: m.dir, kind: m.kind, at: m.at, expiresAt: m.expiresAt, live: m.dir === "out" ? true : m.live === true, duress: !!m.duress,
    text: m.kind === "text" ? td.decode(m.body) : null,
  }));
  // messages known not to have arrived: a later one did, these didn't (a relay that drops, or a
  // phone that was off past the relay's 14 days)
  const missing = c.session.status === "erased" ? 0 : c.session.gaps({ now: now() }).missing;
  S.thread.value = { id, locked: false, messages: msgs, notices: ct.notices || [], missing };
}

/** Re-render when the holder's check lapses, so content disappears on time. */
function scheduleLapse() {
  clearTimeout(lapseTimer);
  const until = (S.liveAt.value || 0) + WINDOW - now();
  if (until > 0) lapseTimer = setTimeout(() => publish(), until + 50);
}

/* ---------------- start, stop, poll ---------------- */

/**
 * After unlock, when the server offers messaging.
 *
 * A duress unlock (security review H2) opens nothing real: no conversation is loaded, nothing is
 * fetched or decrypted, nothing is sent. The tab shows an ordinary empty inbox, and anything
 * tried there answers the way a busy server would, like the vault's decoy session. What arrives
 * meanwhile waits at the relay (14 days) for the next real unlock.
 */
export async function start() {
  if (started || !S.messagingOn.value || !R.msgKey) return;
  started = true;
  if (S.decoy.value) {
    R.hooks.stopMessaging = stop;
    S.msg.value = { ready: true, error: null, contacts: [], invites: [], requests: [], newCount: 0 };
    return;
  }
  try {
    await loadKeys();
    list = await loadList();
    for (const ct of list.contacts) { try { await openConv(ct.id); } catch { /* a conversation that won't open is shown as ended */ } }
    await countWaiting();
    R.hooks.stopMessaging = stop;
    publish();
    scheduleLapse();
    poll();
  } catch (e) {
    started = false;
    S.msg.value = { ready: false, error: friendly(e) || "Messages aren't available right now.", contacts: [], invites: [], requests: [], newCount: 0 };
  }
}

/** On lock: everything decrypted is forgotten; what's stored stays sealed. */
export function stop() {
  started = false;
  clearTimeout(timer); clearTimeout(lapseTimer);
  clearTimeout(flushTimer);
  for (const e of pollSessions.values()) e.relay.close();
  pollSessions.clear();
  for (const r of reviews.values()) r.shown?._accept && wipe(r.shown._accept.rk0);
  // Ratchet keys and message bodies are overwritten in memory, not left for the garbage collector (L4).
  for (const c of convs.values()) c.unload().catch(() => {});
  reviews.clear(); convs.clear(); pendingCount.clear(); requests.clear();
  list = null; keyset = null; archive = []; keysAt = 0; openThread = null;
  batch(() => { S.msg.value = null; S.thread.value = null; });
}

async function countWaiting() {
  pendingCount.clear(); requests.clear();
  for (const w of await listWaiting()) {
    if (w.conv) pendingCount.set(w.conv, (pendingCount.get(w.conv) || 0) + 1);
    if (w.invite) requests.set(w.id, { id: w.id, invite: w.invite, at: w.at });
  }
}

export function poll() {
  clearTimeout(timer);
  if (!started) return Promise.resolve();
  polling ||= (async () => {
    try {
      if (!document.hidden && !S.offline.value) {
        await freshKeys().catch(() => {}); // a day old at most, and the next epoch's before it starts
        await flush();
        await fetchAll();
        await expireInvites();
        if (fresh()) await readWaiting();
      }
    } catch { /* offline or busy: next time */ }
    finally {
      polling = null;
      if (started) { publish(); timer = setTimeout(poll, now() < fastUntil ? FAST_POLL_MS : POLL_MS); }
    }
  })();
  return polling;
}

/*
 * Fetching (security review MSG-02, MSG-04). What the relay could put together from polls is
 * kept as small as the design allows:
 *   - each conversation (and each open invite) is polled from a relay session of its own, never
 *     together with another, so one request never names two of a holder's personas;
 *   - in a random order, with a random pause between them;
 *   - only yesterday's and today's mailboxes (tomorrow's only near midnight UTC), so one day's
 *     poll doesn't already name the next day's mailbox.
 * After time away, a conversation fetches every day since it was last polled (`lastPolled`,
 * sealed in the contact list), up to the 14 days the relay keeps anything, so nothing sent
 * while this phone was off is missed. What still goes missing shows in the thread (gaps()).
 */
const POLL_GAP_MS = [150, 900];
const MAX_PAGES = 8;            // pages per batch of up to 64 boxes, per poll
const MAX_TAKEN_PER_POLL = 1000; // objects per conversation or invite, per poll (a relay keeps at most 500 per box)
const pollSessions = new Map(); // conversation or invite id → { relay, born }
function pollRelay(id) {
  let e = pollSessions.get(id);
  if (!e || now() - e.born > RELAY_SESSION_MS) { e?.relay.close(); e = { relay: R.api.relay(), born: now() }; pollSessions.set(id, e); }
  return e.relay;
}
const pause = (lo, hi) => new Promise((r) => setTimeout(r, lo + Math.floor(Math.random() * (hi - lo))));
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) { const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

/**
 * Empty a conversation's (or invite's) mailboxes through `take`, 64 boxes at a time. The relay
 * decides `more` and how much comes back, so a hostile one could keep a phone fetching and
 * storing for ever: at most MAX_PAGES pages per batch and MAX_TAKEN_PER_POLL objects per poll.
 * A page is never cut short (the relay has already handed it over); the rest waits for the
 * next poll, and `complete` is false so lastPolled doesn't move on. Anything that isn't one of
 * the wire sizes is dropped unstored.
 */
export async function drainRelay(take, boxes, keep) {
  let taken = 0, complete = true;
  for (let j = 0; j < boxes.length; j += 64) {
    const ask = boxes.slice(j, j + 64);
    let more = true;
    for (let page = 0; more; page++) {
      if (page >= MAX_PAGES || taken >= MAX_TAKEN_PER_POLL) { complete = false; break; }
      const r = await take(ask);
      more = r?.more === true;
      for (const wires of Object.values(r?.got || {})) {
        if (!Array.isArray(wires)) continue;
        for (const wire of wires) {
          if (!(wire instanceof Uint8Array) || !M.isWireSize(wire.length)) continue;
          taken++;
          await keep(wire);
        }
      }
    }
    if (!complete) break;
  }
  return { taken, complete };
}

async function fetchAll() {
  const t = now();
  const targets = [];
  for (const ct of list.contacts) {
    const c = convs.get(ct.id);
    if (!c || c.status === "erased" || c.status === "closed") continue;
    targets.push({ id: ct.id, ct, boxes: c.session.inboxesSince(ct.lastPolled ?? null, t) });
  }
  // an invite's reply box stops being polled once it holds MAX_REQUESTS_PER_INVITE (MSG-09: a flood)
  for (const inv of list.invites) if (!inv.closed && inv.expires > t && requestsFor(inv.id) < MAX_REQUESTS_PER_INVITE) targets.push({ id: inv.id, invite: inv.id, boxes: [inv.state.replyBox] });
  let polled = false;
  for (const [i, x] of shuffle(targets).entries()) {
    if (i) await pause(...POLL_GAP_MS);
    if (!started) return;
    const { complete } = await drainRelay((ask) => pollRelay(x.id).take(ask), x.boxes, async (wire) => {
      // Stored before anything else, as ciphertext: the relay no longer has it.
      if (x.ct) { await putWaiting({ conv: x.id, at: now() }, wire); pendingCount.set(x.id, (pendingCount.get(x.id) || 0) + 1); }
      else if (requestsFor(x.invite) < MAX_REQUESTS_PER_INVITE) { const at = now(); const id = await putWaiting({ invite: x.invite, at }, wire); requests.set(id, { id, invite: x.invite, at }); }
    });
    if (x.ct && complete) { x.ct.lastPolled = t; polled = true; }
  }
  if (polled) await saveList();
}

/** Open what's waiting. Only with a fresh check: the holder is proven live right now. */
async function readWaiting() {
  if (!fresh()) return;
  const waiting = (await listWaiting()).filter((w) => w.conv);
  let changed = false, refetched = false;
  for (const r of waiting) {
    const c = convs.get(r.conv);
    const ct = contactOf(r.conv);
    if (c && ct && c.status !== "erased") {
      try {
        // receivedAt: when it came off the relay, so reading late doesn't make an old check look fresh (H1)
        let m;
        try { m = await c.receive(r.wire, { stampKeys: keyset, now: now(), receivedAt: r.at, holdUnknownKey: true }); }
        catch (e) {
          // Stamped under a key this phone hasn't fetched (MSG-07): nothing moved. Fetch the keys
          // once and open it again; a key still unknown then was never published, and the message
          // is discarded as not live.
          if (e?.code !== "unknown_stamp_key") throw e;
          if (!refetched) { refetched = true; await loadKeys(); }
          m = await c.receive(r.wire, { stampKeys: keyset, now: now(), receivedAt: r.at });
        }
        if (m.refused) note(ct, "A message couldn't be confirmed as sent with a live check, so it was discarded unread.");
        else if (m.duress && ct.duressAlert) { ct.duressAt = now(); note(ct, "They may be under duress: their last message was sent from a duress unlock."); }
        if (m.kind === "close" && !m.refused) note(ct, "They ended this conversation.");
        if (m.kind === "delete" && !m.refused && m.deleted) note(ct, `They deleted ${m.deleted === 1 ? "a message" : `${m.deleted} messages`} for both of you.`);
        if (m.kind === "accept" && !m.refused) note(ct, "They approved you with a live check. You're connected.");
        if (!m.refused) ct.lastAt = Math.max(ct.lastAt || 0, m.at || 0);
        changed = true;
      } catch (e) {
        // try again later; nothing was applied (a save failed, or the keys couldn't be fetched)
        if (e?.code === "persist_failed" || e?.code === "unknown_stamp_key" || e?.status || e instanceof TypeError) break;
        // not_for_us, replay_or_old, malformed, closed: nothing to show; drop it
      }
    }
    await R.store.delMsg(r.id);
    pendingCount.set(r.conv, Math.max(0, (pendingCount.get(r.conv) || 1) - 1));
  }
  if (changed) await saveList();
}
function note(ct, text) { ct.notices = [...(ct.notices || []), { at: now(), text }].slice(-5); }

async function expireInvites() {
  const t = now();
  let changed = false;
  for (const inv of list.invites) {
    if (!inv.closed && inv.expires <= t) { M.closeInvite(inv.state); inv.closed = true; changed = true; }
  }
  const before = list.invites.length;
  list.invites = list.invites.filter((i) => !i.closed || requestsFor(i.id) > 0);
  if (changed || list.invites.length !== before) await saveList();
}

/* ---------------- the actions ---------------- */

const decoyBusy = () => { if (S.decoy.value) throw Object.assign(new Error("Messages are busy right now. Try again in a few minutes."), { code: "busy" }); };


const report = (e) => { if (!cancelled(e)) toast(friendly(e), "error"); return null; };
const cleanLabel = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, MAX_LABEL);

/**
 * Two people mid-connection: poll every few seconds while a screen waits on the other phone
 * (an invite on show, a request out), so the next step appears by itself. Stops after 3 minutes.
 */
export function waitingOnOther(on) {
  fastUntil = on ? now() + 3 * 60_000 : 0;
  if (on) poll();
}

/**
 * Read: one live check, then everything waiting opens and stays readable for the window.
 * With a conversation on screen (and "show them when you're here" on, the default), the same
 * check stamps an empty "I'm here" for that one contact, so they see you live while you read.
 */
export async function verifyToRead() {
  try {
    decoyBusy();
    const id = openThread, c = id && convs.get(id), ct = id && contactOf(id);
    let sent = null;
    if (c && ct && c.status === "connected" && ct.showHere !== false && !S.offline.value && canStamp()) {
      await live("read", `Open ${ct.label}`, async ({ stamper }) => { sent = await c.here({ stamper, now: now() }); });
    } else {
      await withKeys("read", "Open your messages", async () => {});
    }
    if (sent) soon(); // already in the conversation's sealed outbox
    await readWaiting();
    publish();
    scheduleLapse();
    return true;
  } catch (e) { return report(e); }
}

/** Make an invite: one live check. Returns { code, qr, expires } to show in person. */
export async function makeInvite({ label = "" } = {}) {
  needVault();
  try {
    decoyBusy();
    // approving whoever uses it takes a stamp, so don't hand out an invite this device can't finish
    if (!canStamp()) throw Object.assign(new Error(NEEDS_PHONE), { code: "stamp_needs_proven_phone" });
    let made = null;
    await withKeys("invite", "Make an invite", async ({ seed }) => {
      const inv = await M.createInvite(seed, { now: now() });
      M.wipePersona(inv.persona);
      made = inv;
    });
    const entry = { id: made.box, code: made.code, expires: made.state.expires, label: cleanLabel(label), createdAt: now(), state: made.state };
    list.invites.push(entry);
    await saveList();
    await post([{ box: made.box, wire: made.wire, retractTag: made.retractTag }]);
    publish();
    return { id: entry.id, code: made.code, expires: entry.expires, qr: M.inviteQrPayload(made.code, entry.expires) };
  } catch (e) { return report(e); }
}

export function inviteQr(code, expires) { try { return M.inviteQrPayload(code, expires); } catch { return null; } }
export const parseInviteQr = (text) => M.parseInviteQr(text);

/** Take an invite down: its bundle comes off the relay and requests to it can never be read. */
export async function cancelInvite(id) {
  const inv = list?.invites.find((i) => i.id === id);
  if (!inv) return;
  const { box, retract } = M.cancelInvite(inv.state);
  inv.closed = true;
  list.invites = list.invites.filter((i) => i !== inv);
  for (const r of [...requests.values()].filter((x) => x.invite === id)) { requests.delete(r.id); await R.store.delMsg(r.id); }
  await saveList();
  if (retract) await oneShot((r) => r.retract(box, retract)).catch(() => {});
  publish();
}

/** Someone's code, typed or scanned: fetch and check their invite. No check needed: nothing is sent. */
export async function openCode(code) {
  needVault();
  try {
    decoyBusy();
    const parsed = M.parseInviteCode(code);
    const box = M.inviteBoxOf(parsed.secret);
    const { got } = await oneShot((r) => r.take([box], { keep: true }));
    const wire = got[box]?.[0];
    if (!wire) throw Object.assign(new Error("No invite with that code. It may have expired or been cancelled. Ask for a new one."), { code: "no_invite" });
    const opened = await M.openInvite(parsed, wire, { now: now() });
    if (list.contacts.some((c) => convs.get(c.id)?.session.peerId === opened.id)) throw Object.assign(new Error("You're already connected with this person."), { code: "already" });
    return { id: opened.id, expires: opened.expires, _opened: opened };
  } catch (e) { report(e); return null; }
}

/** Ask to connect: one live check; the request carries its stamp. */
export async function askToConnect(found, { label, intro = "" }) {
  try {
    decoyBusy();
    let made = null;
    await live("connect", "Ask to connect", async ({ seed, stamper }) => {
      made = await M.requestContact(seed, found._opened, { intro: String(intro || "").slice(0, 280), stamper, requireLive: true, now: now() });
    });
    const salt = made.persona.salt;
    M.wipePersona(made.persona);
    await addConv(made.session, { label: cleanLabel(label) || "New contact", role: "b", personaSalt: salt, createdAt: now(), reqBox: made.box, retract: made.retract, peerId: found.id }, { first: made });
    soon();
    publish();
    return { id: hex(made.session.convId), safetyCode: made.session.safetyCode };
  } catch (e) { return report(e); }
}

/** Withdraw a request before it's read. true: it never arrived. */
export async function withdrawRequest(id) {
  const ct = contactOf(id);
  if (!ct?.retract) return false;
  // still in the outbox (never posted): it never left this phone
  const unposted = convs.get(id)?.pending().some((p) => p.kind === "first");
  const removed = unposted || await oneShot((r) => r.retract(ct.reqBox, ct.retract)).catch(() => false);
  if (removed) await forgetLocal(id);
  else toast("They've already seen your request. Delete the conversation instead.", "warn");
  publish();
  return removed;
}

/** See who's asking: one live check (the request opens only with this invite's persona keys). */
/*
 * Request floods (security review MSG-09). Anyone who saw an invite code can post junk to its
 * reply box. So one "See who's asking" check opens EVERY request waiting for that invite: what
 * isn't live, isn't for this invite, or was already handled is dropped without being shown, and
 * only real requests are listed. At most MAX_REQUESTS_PER_INVITE are kept, and the reply box is
 * no longer polled once that many have arrived.
 */
const MAX_REQUESTS_PER_INVITE = 20;
const UNREADABLE = ["not_live", "bad_signature", "malformed", "not_for_us", "replay_or_old", "invite_used", "invite_expired", "unsupported_version"];

export async function reviewRequest(reqId) {
  const r = requests.get(reqId);
  const inv = list.invites.find((i) => i.id === r?.invite);
  if (!r || !inv) return null;
  // this one first, then every other one waiting for the same invite
  const ids = [reqId, ...[...requests.values()].filter((x) => x.invite === inv.id && x.id !== reqId && !reviews.has(x.id)).map((x) => x.id)];
  const recs = [];
  for (const id of ids) { const rec = await openWaiting(await R.store.getMsg(id)); if (rec) recs.push(rec); }
  if (!recs.length) return null;
  try {
    const opened = [], dropped = [];
    let persona = null;
    await withKeys("review", "See who's asking", async ({ seed }) => {
      const p = M.personaFromSalt(seed, inv.state.personaSalt);
      try {
        for (const rec of recs) {
          try { opened.push({ rec, shown: await M.readRequest(inv.state, p, rec.wire, { stampKeys: keyset, requireLive: true, now: now() }) }); }
          catch (e) { if (UNREADABLE.includes(e?.code)) dropped.push(rec.id); else throw e; }
        }
      } finally { persona = { pub: p.pub, id: p.id }; M.wipePersona(p); }
    });
    // Never shown: what isn't live, isn't for this invite, or was already handled.
    for (const id of dropped) { requests.delete(id); await R.store.delMsg(id); }
    for (const { rec, shown } of opened) {
      // The request's own live stamp proves them live: when it was made, never later than it arrived.
      reviews.set(rec.id, { shown, invite: inv, persona, at: now(), peerAt: M.peerLiveAt({ live: shown.live, sentAt: shown.at, receivedAt: rec.at }) });
    }
    publish();
    const mine = opened.find((o) => o.rec.id === reqId) || opened[0];
    if (!mine) {
      toast(dropped.length === 1 ? "That request wasn't made with a live check, or wasn't for this invite, so it was discarded unread." : `${dropped.length} requests couldn't be confirmed as made with a live check, so they were discarded unread.`, "warn");
      return null;
    }
    const { rec, shown } = mine;
    return { id: rec.id, from: shown.from, intro: shown.intro, live: shown.live === true, safetyCode: shown.safetyCode, at: shown.at, label: inv.label, others: opened.length - 1, discarded: dropped.length };
  } catch (e) { return report(e); }
}

/** A request already opened by the same check (MSG-09): shown without another one. */
export function reviewedRequest(reqId) {
  const rv = reviews.get(reqId);
  if (!rv) return null;
  const { shown, invite } = rv;
  return { id: reqId, from: shown.from, intro: shown.intro, live: shown.live === true, safetyCode: shown.safetyCode, at: shown.at, label: invite.label, others: 0, discarded: 0 };
}

/** Approve: one live check; the acceptance carries its stamp. */
export async function approveRequest(reqId, { label, safetyVerified = false }) {
  const rv = reviews.get(reqId);
  if (!rv) return null;
  try {
    let sent = null, session = null;
    // the invite is spent only once the acceptance is stamped (MSG-08): a failed check, a busy
    // server or a changed stamp key leaves it as it was, and Approve works again
    await live("approve", `Approve ${cleanLabel(label) || "this person"}`, async ({ stamper }) => {
      ({ session, sent } = await M.approveRequest(rv.invite.state, rv.persona, rv.shown, (s) => new M.Conversation(s, null, { requireLive: true }).accept({ stamper, now: now() }), { now: now() }));
    });
    reviews.delete(reqId);
    requests.delete(reqId); await R.store.delMsg(reqId);
    if (rv.invite.state.closed) list.invites = list.invites.filter((i) => i !== rv.invite);
    await addConv(session, { label: cleanLabel(label) || "New contact", role: "a", personaSalt: rv.invite.state.personaSalt, createdAt: now(), lastAt: now(), peerId: rv.shown.from, safetyVerified: typeof safetyVerified === "string" ? `${safetyVerified.slice(0, 20)}, ${new Date().toLocaleDateString()}` : !!safetyVerified }, { peerAt: rv.peerAt, first: sent });
    soon();
    publish();
    return hex(session.convId);
  } catch (e) { return report(e); }
}

/** Decline: nothing is sent; the request can't be shown again. */
export async function declineRequest(reqId) {
  const rv = reviews.get(reqId);
  if (rv) { M.declineRequest(rv.invite.state, rv.shown); reviews.delete(reqId); await saveList(); }
  requests.delete(reqId); await R.store.delMsg(reqId);
  publish();
}

/** Open a conversation on screen. */
export function showConversation(id) {
  openThread = id;
  const ct = contactOf(id);
  if (ct && fresh()) { ct.lastRead = now(); saveList(); }
  showThread(id);
  if (fresh()) readWaiting().then(publish);
}
export function closeConversation() { openThread = null; S.thread.value = null; }

/** Send text: one live check, one stamp. */
export async function send(id, text) {
  const c = convs.get(id);
  const ct = contactOf(id);
  const body = String(text || "");
  if (!c || !ct || !body.trim()) return false;
  try {
    let r = null;
    await live("send", `Send to ${ct.label}`, async ({ stamper }) => {
      await readWaiting(); // the check makes this holder live: read what's waiting first
      r = await c.send(body, { stamper, now: now() });
    });
    ct.lastAt = now(); ct.lastRead = now();
    await saveList();
    if (r) soon(); // saved in the conversation's sealed outbox with the ratchet step that made it
    publish();
    return true;
  } catch (e) { return report(e); }
}

/** Delete one message: for me (no check: nothing is sent), or for both (one live check). */
export async function deleteMessage(id, msgId, { forBoth = false } = {}) {
  const c = convs.get(id);
  if (!c) return;
  try {
    if (!forBoth) { await c.delete(msgId); publish(); return true; }
    let r = null;
    await live("delete", "Delete for both of you", async ({ stamper }) => { r = await c.delete(msgId, { forBoth: true, stamper, now: now() }); });
    if (r.unsend) await retractOnce(r.unsend);
    soon();
    publish();
    return true;
  } catch (e) { return report(e); }
}

/** Disappearing messages, for both of you: one live check. ms = 0 turns it off. */
export async function setTimer(id, ms) {
  const c = convs.get(id);
  if (!c) return;
  try {
    let r = null;
    await live("timer", ms ? "Turn on disappearing messages" : "Turn off disappearing messages", async ({ stamper }) => { r = await c.setTimer(ms, { stamper, now: now() }); });
    if (r) soon();
    publish();
    return true;
  } catch (e) { return report(e); }
}

/** How many live checks deleting this conversation for both takes (1, or more past 500 of your messages). */
export function deleteSteps(id) {
  const c = convs.get(id);
  return c ? c.forgetPlan({ forBoth: true, now: now(), perCheck: S.server.value?.policy?.messaging?.stampsPerCheck || 1 }).steps : 0;
}

const retractOnce = (u) => oneShot((r) => r.retract(u.box, u.retract)).catch(() => false);

/**
 * Delete a conversation. For me: nothing is sent, no check needed beyond the unlock.
 * For both: one live check stamps the deletes and the end together; with more than one check
 * can stamp (over 500 of your messages), it's "step 1 of 2", and so on, each its own check.
 * Nothing is erased until the last step's stamps and messages are made and saved (PC-28): if a
 * check fails or is cancelled, the conversation is still here, and what was done so far stays
 * done (those messages are already deleted for both).
 */
export async function deleteConversation(id, { forBoth = false } = {}) {
  const c = convs.get(id);
  if (!c) { await forgetLocal(id); publish(); return true; }
  try {
    let r = null;
    if (forBoth && c.status === "connected") {
      const perCheck = S.server.value?.policy?.messaging?.stampsPerCheck || 1;
      const steps = c.forgetPlan({ forBoth: true, now: now(), perCheck }).steps;
      for (let step = 1; !r?.done; step++) {
        const label = steps > 1 ? `Delete for both of you (step ${Math.min(step, steps)} of ${steps})` : "Delete for both of you";
        await live("delete", label, async ({ stamper }) => { r = await c.forget({ forBoth: true, stamper, perCheck, now: now() }); });
        for (const u of r.unsend) await retractOnce(u);
        if (!r.done) { soon(); toast(`Step ${step} of ${steps} done. One more live check finishes deleting.`, "info"); }
      }
    } else {
      r = await c.forget({ now: now() });
      for (const u of r.unsend) await retractOnce(u);
    }
    // The conversation (and its sealed outbox) is about to go: what still has to reach the relay
    // moves to the sealed "o:" outbox, which outlives it.
    const out = [...(r.pending || []), ...r.send];
    if (out.length) await post(out);
    await forgetLocal(id);
    publish();
    return true;
  } catch (e) { return report(e); }
}

async function forgetLocal(id) {
  convs.delete(id);
  list.contacts = list.contacts.filter((c) => c.id !== id);
  for (const w of (await listWaiting()).filter((x) => x.conv === id)) await R.store.delMsg(w.id);
  pendingCount.delete(id);
  await R.store.delMsg(`c:${id}`);
  await saveList();
  if (openThread === id) closeConversation();
}

/** Local-only details: the name you know them by, safety code compared, duress alerts. */
export async function updateContact(id, patch) {
  const ct = contactOf(id);
  if (!ct) return;
  if ("label" in patch) ct.label = cleanLabel(patch.label) || ct.label;
  // what the holder said about the comparison: false, or how they compared ("in person", "on a video call")
  if ("safetyVerified" in patch) {
    ct.safetyVerified = typeof patch.safetyVerified === "string" ? `${patch.safetyVerified.slice(0, 20)}, ${new Date().toLocaleDateString()}` : !!patch.safetyVerified;
    if (ct.safetyVerified) ct.safetyMismatch = 0;
  }
  // the holder compared the safety code and it was DIFFERENT: someone may be in between (MSG-06)
  if (patch.safetyMismatch) { ct.safetyMismatch = now(); ct.safetyVerified = false; }
  if ("duressAlert" in patch) ct.duressAlert = !!patch.duressAlert;
  if ("showHere" in patch) ct.showHere = !!patch.showHere;
  if (patch.clearNotices) ct.notices = [];
  await saveList();
  publish();
}

/** The safety code to compare in person, and the persona ID they know you by. */
export function safetyOf(id) {
  const c = convs.get(id);
  return c ? { safetyCode: c.session.safetyCode, mine: c.session.myId, theirs: c.session.peerId } : null;
}

/** The validated human-to-human state of a conversation (live.js). */
export function liveStateOf(id) {
  const c = convs.get(id);
  return M.liveState({ ownAt: S.liveAt.value || null, peerAt: c?.peerLiveAt ?? null, now: now(), windowMs: WINDOW });
}

/**
 * Network-wide: how many live stamps were issued today (messages, requests, approvals, receipts
 * and deletes alike), rounded down to a hundred. Null when the server publishes no figure for
 * today (it does only once enough checks were made that the number says nothing about anyone).
 */
export async function humanToday() {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const d = (await R.api.msgStats())?.find((x) => x.day === today);
    return d ? d.stamps : null;
  } catch { return null; }
}

export const LIVE_WINDOW_MS = WINDOW;
/** Requests that arrived for one invite (the invite screen turns into "they're asking"). */
export const requestsForInvite = (inviteId) => [...requests.values()].filter((r) => r.invite === inviteId).map((r) => r.id);

export const TIMERS = [[0, "Off"], [3600_000, "1 hour"], [86_400_000, "1 day"], [7 * 86_400_000, "1 week"]];
