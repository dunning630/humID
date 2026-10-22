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
//   "p:<id>" ciphertext from the relay, waiting for a fresh check to be read
//   "r:<id>" a contact request waiting for review
//   "o:<id>" something to post that hasn't reached the relay yet (retried on every poll)
//
// The relay is reached from its own session that never signs in, so the server can't link
// this account to any mailbox. Stamps come from the signed-in session, inside a live step-up
// over exactly the blinded values, so the issuer learns that this account asked, never for what.
import * as M from "@humid/msg";
import { batch } from "@preact/signals";
import * as S from "./state.js";
import { R, wipe } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withKeys, withStepUp, needVault } from "./interrupt.js";

const POLL_MS = 12_000;
const MAX_LABEL = 40;
const te = new TextEncoder(), td = new TextDecoder();

let started = false;
let relay = null;
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
const fresh = () => M.canRead({ ownAt: S.liveAt.value || null, now: now() });

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

async function addConv(session, contact, { peerAt = null } = {}) {
  const id = hex(session.convId);
  const c = new M.Conversation(session, null, { persist: persistFor(id), requireLive: true, live: { peerAt } });
  convs.set(id, c);
  list.contacts.push({ ...contact, id });
  await c.seal().then(persistFor(id));
  await saveList();
  return c;
}

/* ---------------- posting: through an outbox, so nothing is lost to a dropped connection ---------------- */

async function post(items) {
  const recs = items.map((x) => ({ id: `o:${rid()}`, at: now(), box: x.box, wire: x.wire, tag: x.retractTag || null }));
  for (const r of recs) await R.store.putMsg(r);
  await flush();
}
async function flush() {
  const out = (await R.store.listMsg()).filter((r) => r.id.startsWith("o:")).sort((a, b) => a.at - b.at);
  for (const r of out) {
    try { await relay.put(r.box, r.wire, r.tag); await R.store.delMsg(r.id); }
    catch (e) {
      // a refusal that won't change on retry (a malformed or oversized object): drop it
      if (e?.status >= 400 && e?.status < 500 && e?.status !== 429) await R.store.delMsg(r.id);
      else break; // offline or busy: try again on the next poll
    }
  }
}

/* ---------------- stamps: one live check, the exact blinded values ---------------- */

/** A stamper for the step-up `proof` of ONE live check (used once, up to the server's limit). */
function stampWith(proof) {
  let used = false;
  const many = async (commits) => {
    if (used) throw Object.assign(new Error("That live check was already used. Try again."), { code: "stamp_used" });
    used = true;
    const drafts = commits.map((c) => M.blindStamp(keyset, c));
    const sigs = await R.api.stamp({ kid: keyset.issuing.id, blinded: drafts.map((d) => d.blinded) }, proof);
    return drafts.map((d, i) => M.finalizeStamp(keyset, d.draft, sigs[i]));
  };
  return Object.assign(async (c) => (await many([c]))[0], { many });
}
/** Run fn inside one live check that also produces stamps. fn gets { seed, stamper }. */
function live(purpose, label, fn) {
  needVault();
  return withStepUp("stamp", [], purpose, label, ({ seed, proof }) => fn({ seed, stamper: stampWith(proof) }));
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
      created: ct.createdAt, safetyVerified: !!ct.safetyVerified, duressAlert: !!ct.duressAlert, duressAt: ct.duressAt || 0,
      peerAt: c?.peerLiveAt ?? null, timer: c?.timer ?? 0,
      waiting: pendingBy.get(ct.id) || 0, unread: unreadIn,
      last: last ? { at: last.at, dir: last.dir, text: last.kind === "text" ? td.decode(last.body) : "Voice note or photo" } : null,
      lastAt: last?.at || ct.lastAt || ct.createdAt,
    };
  }).sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0));
  const invites = list.invites.filter((i) => !i.closed).map((i) => ({ id: i.id, code: i.code, expires: i.expires, label: i.label, created: i.createdAt, waiting: requestsFor(i.id) }));
  S.msg.value = {
    ready: true, error: null, contacts, invites,
    requests: [...requests.values()].map((r) => ({ id: r.id, invite: r.invite, label: list.invites.find((i) => i.id === r.invite)?.label || "", at: r.at })),
    newCount: contacts.reduce((n, c) => n + c.waiting + c.unread, 0) + requests.size,
  };
  if (openThread) showThread(openThread);
}
const pendingCount = new Map(); // conversation id → ciphertexts waiting to be read
const requests = new Map();     // request id → { id, invite, at }
const requestsFor = (inviteId) => [...requests.values()].filter((r) => r.invite === inviteId).length;

/** The open conversation's messages, only while its holder's check is fresh. */
function showThread(id) {
  const c = convs.get(id);
  const ct = contactOf(id);
  if (!c || !ct) { S.thread.value = null; return; }
  if (!fresh()) { S.thread.value = { id, locked: true, waiting: pendingCount.get(id) || 0 }; return; }
  const msgs = c.messages(now()).map((m) => ({
    id: m.id, dir: m.dir, kind: m.kind, at: m.at, expiresAt: m.expiresAt, live: m.dir === "out" ? true : m.live === true, duress: !!m.duress,
    text: m.kind === "text" ? td.decode(m.body) : null,
  }));
  S.thread.value = { id, locked: false, messages: msgs, notices: ct.notices || [] };
}

/** Re-render when the holder's check lapses, so content disappears on time. */
function scheduleLapse() {
  clearTimeout(lapseTimer);
  const until = (S.liveAt.value || 0) + M.LIVE_WINDOW_MS - now();
  if (until > 0) lapseTimer = setTimeout(() => publish(), until + 50);
}

/* ---------------- start, stop, poll ---------------- */

/** After unlock, when the server offers messaging. */
export async function start() {
  if (started || !S.messagingOn.value || !R.msgKey) return;
  started = true;
  try {
    const k = await R.api.msgKeys();
    keyset = M.importStampKeys(k.stamp.keys, { passKeys: (k.passKeyIds || []).map((id) => ({ id })) });
    relay = R.api.relay();
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
  relay?.close(); relay = null;
  for (const r of reviews.values()) r.shown?._accept && wipe(r.shown._accept.rk0);
  reviews.clear(); convs.clear(); pendingCount.clear(); requests.clear();
  list = null; keyset = null; openThread = null;
  batch(() => { S.msg.value = null; S.thread.value = null; });
}

async function countWaiting() {
  pendingCount.clear(); requests.clear();
  for (const r of await R.store.listMsg()) {
    if (r.id.startsWith("p:")) pendingCount.set(r.conv, (pendingCount.get(r.conv) || 0) + 1);
    if (r.id.startsWith("r:")) requests.set(r.id, { id: r.id, invite: r.invite, at: r.at });
  }
}

export function poll() {
  clearTimeout(timer);
  if (!started) return Promise.resolve();
  polling ||= (async () => {
    try {
      if (!document.hidden && !S.offline.value) {
        await flush();
        await fetchAll();
        await expireInvites();
        if (fresh()) await readWaiting();
      }
    } catch { /* offline or busy: next time */ }
    finally {
      polling = null;
      if (started) { publish(); timer = setTimeout(poll, POLL_MS); }
    }
  })();
  return polling;
}

async function fetchAll() {
  const t = now();
  const want = new Map(); // box → { conv } | { invite }
  for (const ct of list.contacts) {
    const c = convs.get(ct.id);
    if (!c || c.status === "erased" || c.status === "closed") continue;
    for (const b of c.session.inboxes(t)) want.set(b, { conv: ct.id });
  }
  for (const inv of list.invites) if (!inv.closed && inv.expires > t) want.set(inv.state.replyBox, { invite: inv.id });
  const boxes = [...want.keys()];
  for (let i = 0; i < boxes.length; i += 64) {
    const { got } = await relay.take(boxes.slice(i, i + 64));
    for (const [box, wires] of Object.entries(got)) {
      const to = want.get(box);
      for (const wire of wires) {
        // Stored before anything else, as ciphertext: the relay no longer has it.
        if (to.conv) { await R.store.putMsg({ id: `p:${rid()}`, conv: to.conv, wire, at: now() }); pendingCount.set(to.conv, (pendingCount.get(to.conv) || 0) + 1); }
        else { const id = `r:${rid()}`; await R.store.putMsg({ id, invite: to.invite, wire, at: now() }); requests.set(id, { id, invite: to.invite, at: now() }); }
      }
    }
  }
}

/** Open what's waiting. Only with a fresh check: the holder is proven live right now. */
async function readWaiting() {
  if (!fresh()) return;
  const waiting = (await R.store.listMsg()).filter((r) => r.id.startsWith("p:")).sort((a, b) => a.at - b.at);
  let changed = false;
  for (const r of waiting) {
    const c = convs.get(r.conv);
    const ct = contactOf(r.conv);
    if (c && ct && c.status !== "erased") {
      try {
        const m = await c.receive(r.wire, { stampKeys: keyset, now: now() });
        if (m.refused) note(ct, "A message arrived without a live check. It was discarded unread.");
        else if (m.duress && ct.duressAlert) { ct.duressAt = now(); note(ct, "They may be under duress: their last message was sent from a duress unlock."); }
        if (m.kind === "close") note(ct, "They ended this conversation.");
        if (m.kind === "delete" && m.deleted) note(ct, `They deleted ${m.deleted === 1 ? "a message" : `${m.deleted} messages`} for both of you.`);
        if (m.kind === "accept" && !m.refused) note(ct, "They approved you with a live check. You're connected.");
        if (!m.refused) ct.lastAt = Math.max(ct.lastAt || 0, m.at || 0);
        changed = true;
      } catch (e) {
        if (e?.code === "persist_failed") break; // try again later; nothing was applied
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

const report = (e) => { if (!cancelled(e)) toast(friendly(e), "error"); return null; };
const cleanLabel = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, MAX_LABEL);

/** Read: one live check, then everything waiting opens and stays readable for the window. */
export async function verifyToRead() {
  try {
    await withKeys("read", "Read your messages", async () => {});
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
  if (retract) await relay.retract(box, retract).catch(() => {});
  publish();
}

/** Someone's code, typed or scanned: fetch and check their invite. No check needed: nothing is sent. */
export async function openCode(code) {
  needVault();
  try {
    const parsed = M.parseInviteCode(code);
    const box = M.inviteBoxOf(parsed.secret);
    const { got } = await relay.take([box], { keep: true });
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
    let made = null;
    await live("connect", "Ask to connect", async ({ seed, stamper }) => {
      made = await M.requestContact(seed, found._opened, { intro: String(intro || "").slice(0, 280), stamper, requireLive: true, now: now() });
    });
    const salt = made.persona.salt;
    M.wipePersona(made.persona);
    await addConv(made.session, { label: cleanLabel(label) || "New contact", role: "b", personaSalt: salt, createdAt: now(), reqBox: made.box, retract: made.retract, peerId: found.id });
    await post([{ box: made.box, wire: made.wire, retractTag: made.retractTag }]);
    publish();
    return true;
  } catch (e) { return report(e); }
}

/** Withdraw a request before it's read. true: it never arrived. */
export async function withdrawRequest(id) {
  const ct = contactOf(id);
  if (!ct?.retract) return false;
  const removed = await relay.retract(ct.reqBox, ct.retract).catch(() => false);
  if (removed) await forgetLocal(id);
  else toast("They've already seen your request. Delete the conversation instead.", "warn");
  publish();
  return removed;
}

/** See who's asking: one live check (the request opens only with this invite's persona keys). */
export async function reviewRequest(reqId) {
  const r = requests.get(reqId);
  const rec = await R.store.getMsg(reqId);
  const inv = list.invites.find((i) => i.id === r?.invite);
  if (!r || !rec || !inv) return null;
  try {
    let shown = null, persona = null;
    await withKeys("review", "See who's asking", async ({ seed }) => {
      const p = M.personaFromSalt(seed, inv.state.personaSalt);
      try { shown = await M.readRequest(inv.state, p, rec.wire, { stampKeys: keyset, requireLive: true, now: now() }); }
      finally { persona = { pub: p.pub, id: p.id }; M.wipePersona(p); }
    });
    // The request's own live stamp proves them live: when it was made, never later than it arrived.
    const peerAt = M.peerLiveAt({ live: shown.live, sentAt: shown.at, receivedAt: rec.at });
    reviews.set(reqId, { shown, invite: inv, persona, at: now(), peerAt });
    return { id: reqId, from: shown.from, intro: shown.intro, live: shown.live === true, safetyCode: shown.safetyCode, at: shown.at, label: inv.label };
  } catch (e) {
    if (["not_live", "bad_signature", "malformed", "not_for_us", "replay_or_old", "invite_used", "invite_expired"].includes(e?.code)) {
      // Never shown: a request that isn't live, isn't for this invite, or was already handled.
      requests.delete(reqId); await R.store.delMsg(reqId); publish();
      toast(e.code === "not_live" ? "That request wasn't made with a live check, so it was discarded unread." : "That request couldn't be opened. It was discarded.", "warn");
      return null;
    }
    return report(e);
  }
}

/** Approve: one live check; the acceptance carries its stamp. */
export async function approveRequest(reqId, { label }) {
  const rv = reviews.get(reqId);
  if (!rv) return null;
  try {
    let sent = null, session = null;
    await live("approve", `Approve ${cleanLabel(label) || "this person"}`, async ({ stamper }) => {
      session = M.acceptRequest(rv.invite.state, rv.persona, rv.shown, { now: now() });
      const c = new M.Conversation(session, null, { requireLive: true });
      sent = await c.accept({ stamper, now: now() });
    });
    reviews.delete(reqId);
    requests.delete(reqId); await R.store.delMsg(reqId);
    if (rv.invite.state.closed) list.invites = list.invites.filter((i) => i !== rv.invite);
    await addConv(session, { label: cleanLabel(label) || "New contact", role: "a", personaSalt: rv.invite.state.personaSalt, createdAt: now(), lastAt: now(), peerId: rv.shown.from }, { peerAt: rv.peerAt });
    await post([sent]);
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
      r = await c.send(body, { stamper, duress: !!S.decoy.value, now: now() });
    });
    ct.lastAt = now(); ct.lastRead = now();
    await saveList();
    await post([r]);
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
    if (r.unsend) await relay.retract(r.unsend.box, r.unsend.retract).catch(() => false);
    await post([r.send]);
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
    await post([r]);
    publish();
    return true;
  } catch (e) { return report(e); }
}

/**
 * Delete a conversation. For me: nothing is sent, no check needed beyond the unlock.
 * For both: one live check stamps every delete and the end together.
 */
export async function deleteConversation(id, { forBoth = false } = {}) {
  const c = convs.get(id);
  if (!c) { await forgetLocal(id); publish(); return true; }
  try {
    let r = null;
    if (forBoth && c.status === "connected") await live("delete", "Delete for both of you", async ({ stamper }) => { r = await c.forget({ forBoth: true, stamper, now: now() }); });
    else r = await c.forget({ now: now() });
    for (const u of r.unsend) await relay.retract(u.box, u.retract).catch(() => false);
    if (r.send.length) await post(r.send);
    await forgetLocal(id);
    publish();
    return true;
  } catch (e) { return report(e); }
}

async function forgetLocal(id) {
  convs.delete(id);
  list.contacts = list.contacts.filter((c) => c.id !== id);
  for (const r of (await R.store.listMsg()).filter((x) => x.id.startsWith("p:") && x.conv === id)) await R.store.delMsg(r.id);
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
  if ("safetyVerified" in patch) ct.safetyVerified = !!patch.safetyVerified;
  if ("duressAlert" in patch) ct.duressAlert = !!patch.duressAlert;
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
  return M.liveState({ ownAt: S.liveAt.value || null, peerAt: c?.peerLiveAt ?? null, now: now() });
}

/** Network-wide: how many messages a live human approved today. */
export async function humanToday() {
  try { const days = await R.api.msgStats(); return days?.[0]?.stamps ?? 0; } catch { return null; }
}

export const LIVE_WINDOW_MS = M.LIVE_WINDOW_MS;
export const TIMERS = [[0, "Off"], [3600_000, "1 hour"], [86_400_000, "1 day"], [7 * 86_400_000, "1 week"]];
