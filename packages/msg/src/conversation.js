// A conversation as the app uses it: the ratchet (Session) plus the history on
// this phone (MessageStore), with every kind of delete in one place.
//
//   send(text)                 → post { box, wire, retractTag }
//   receive(wire)              → what to show (deletes and timers from the contact are applied here)
//   delete(id)                 → gone from this phone
//   delete(id, { forBoth })    → gone from this phone; returns an unsend to try at the relay
//                                and a delete message for the contact's phone
//   setTimer(ms)               → disappearing messages for both of you (0 = off)
//   forget()                   → the whole conversation and its keys, from this phone
//   forget({ forBoth: true })  → also deletes your messages from the contact's phone, then ends it
//   pending() / posted(ids)    → what still has to reach the relay, and marking it done
//   seal() / Conversation.open → save and load (ratchet + history + outbox together, a NEW key every save)
//
// The outbox (PC-28): everything a conversation hands back to post is ALSO kept, inside the same
// sealed save as the ratchet step that made it, until the app says it reached the relay. So a
// crash between "saved" and "posted" can't lose a message or leave a gap in the ratchet.
//
// What you can delete from the contact's phone is what YOU sent. What they sent
// stays theirs; you can always delete your own copy of it.
//
// Every operation runs one at a time, in order, so a send or receive that is
// still running when forget() is called finishes first and is then forgotten
// with everything else; anything called after forget() is refused.

import { MsgError, utf8, random, concat, u32, readU32, label, encodeJSON, decodeJSON, aeadSeal, aeadOpen, equal, guard, toPlain, fromPlain } from "./util.js";
import { MessageStore } from "./history.js";
import { Session, deleteBody, MAX_DELETE } from "./session.js";
import { messageCommitment } from "./stamp.js";
import { peerLiveAt } from "./live.js";

const SHOWN = new Set(["text", "file-key", "media"]); // kept and shown; every other kind is protocol
/** Stamps one live check may approve (the gateway and the issuer enforce it). */
export const STAMPS_PER_CHECK = 2;
/** Unposted objects one conversation keeps (offline for a long time): past this, sending waits. */
export const MAX_OUTBOX = 200;

export class Conversation {
  /**
   * @param session  a Session
   * @param store    its MessageStore (a new, empty one if omitted)
   * @param opts.persist async ({ blob, key }) => void: called with a fresh save after every change,
   *   before anything is handed back to post. Store the blob, and put the key in the phone's secure
   *   storage in place of the previous one. If it throws, the operation fails with persist_failed
   *   and nothing is handed back.
   * @param opts.requireLive the human-to-human rule (live.js): every message out must carry a live
   *   stamp (a stamper is required), and anything in without a valid one is discarded unread.
   * @param opts.live  { peerAt } restored from a save (Conversation.open does this)
   * @param opts.outbox what hadn't reached the relay at the last save (Conversation.open does this),
   *   or, for a new conversation, what started it (the request, or the accept): [{ id, box, wire, retractTag, kind, at }]
   */
  constructor(session, store = null, { persist = null, requireLive = false, live = null, outbox = [] } = {}) {
    this.session = session;
    this.store = store ?? new MessageStore(session.convId);
    this.persist = persist;
    this.requireLive = !!requireLive;
    this.dead = session.status === "erased";
    this.queue = Promise.resolve();
    // When the contact was last proven live (live.js peerLiveAt): sealed with the conversation.
    this.live = { peerAt: Number.isFinite(live?.peerAt) ? live.peerAt : null };
    this.outbox = Array.isArray(outbox) ? outbox.filter((o) => o && typeof o.id === "string" && o.wire instanceof Uint8Array) : [];
  }

  /** What still has to reach the relay, oldest first: [{ id, box, wire, retractTag, kind, at }]. */
  pending() { return this.dead ? [] : this.outbox.map((o) => ({ ...o })); }

  /** These reached the relay (or the relay refused them for good): drop them from the outbox and save. */
  posted(ids, { now = Date.now() } = {}) {
    return this.#serial(async () => {
      const gone = new Set(ids);
      const before = this.outbox.length;
      this.outbox = this.outbox.filter((o) => !gone.has(o.id));
      return this.outbox.length === before ? 0 : this.#saved(before - this.outbox.length, now);
    });
  }

  #keep(p, kind, now) {
    this.outbox.push({ id: p.id || `x${now}-${this.outbox.length}`, box: p.box, wire: p.wire, retractTag: p.retractTag || null, kind, at: now });
    return p;
  }
  #roomToSend() {
    if (this.outbox.length >= MAX_OUTBOX) throw new MsgError("outbox_full", "Too much is waiting to go out. Connect to the internet and try again.");
  }

  get status() { return this.session.status; }
  get timer() { return this.session.timer; }
  /** When the contact was last proven live on this phone, or null. Feed it to liveState(). */
  get peerLiveAt() { return this.live.peerAt; }

  /**
   * Stamp several messages with ONE live check, when the stamper offers it
   * (stamper.many(commitments) → stamps, in order; servers sign at most 2 per check): one action the holder approves once,
   * such as deleting a whole conversation for both, is one check, not one per message.
   * Returns [{ kind, body, nonce, stamper }] to encrypt in order.
   */
  async #plan(items, stamper, now) {
    const nonces = items.map(() => random(16));
    if (!stamper) return items.map((it, i) => ({ ...it, nonce: nonces[i], stamper: null }));
    if (typeof stamper.many !== "function") return items.map((it, i) => ({ ...it, nonce: nonces[i], stamper }));
    const me = this.session.s.me.fp, convId = this.session.convId;
    // what Session.encrypt will commit to for these (protocol messages: no disappearing time, no timer change)
    const commits = items.map((it, i) => messageCommitment({ convId, senderFp: me, nonce: nonces[i], kind: it.kind, body: typeof it.body === "string" ? utf8(it.body) : it.body, at: now, x: 0, ta: 0 }));
    const stamps = await stamper.many(commits, { at: now });
    if (!Array.isArray(stamps) || stamps.length !== items.length || (this.requireLive && stamps.some((x) => !x))) {
      throw new MsgError("stamp_required", "The live check didn't complete, so nothing was sent");
    }
    return items.map((it, i) => ({ ...it, nonce: nonces[i], stamper: async (c) => (equal(c, commits[i]) ? stamps[i] : null) }));
  }

  #serial(fn) {
    const run = this.queue.then(() => {
      if (this.dead) throw new MsgError("erased", "This conversation was deleted");
      return fn();
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async #saved(result, now) {
    if (this.persist) {
      try { await this.persist(await this.#seal(now)); }
      catch (e) { throw new MsgError("persist_failed", `Could not save the conversation: ${e?.message || e}`); }
    }
    return result;
  }

  /** Send text. Returns { box, wire, retractTag, id }: post wire to box with the tag. */
  send(text, opts = {}) { return this.#sendShown("text", text, utf8(text), opts); }

  /**
   * Send a voice note, photo or clip (body from encodeMedia in media.js). Kept like a text, so
   * delete for both, unsend and disappearing messages cover it too. Pass a stamper so it
   * arrives stamped.
   */
  sendMedia(body, opts = {}) {
    if (!(body instanceof Uint8Array)) throw new MsgError("bad_media", "Media body must be bytes from encodeMedia");
    return this.#sendShown("media", body, body, opts);
  }

  #sendShown(kind, content, stored, { now = Date.now(), stamper = null, duress = false, ttlMs } = {}) {
    return this.#serial(async () => {
      this.#roomToSend();
      const r = await this.session.encrypt(kind, content, { now, stamper, duress, ttlMs, requireLive: this.requireLive });
      this.store.add({
        id: r.id, dir: "out", kind, body: stored, at: now, expiresAt: r.ttlMs ? now + r.ttlMs : null,
        stamped: !!stamper, duress, pos: r.pos, box: r.box, retract: r.retract,
      }, now);
      return this.#saved(this.#keep(post(r), kind, now), now);
    });
  }

  /** One protocol message out: encrypted, kept in the outbox, saved, then handed back. */
  async #sendProtocol(kind, body, { now, stamper, nonce }) {
    this.#roomToSend();
    const r = await this.session.encrypt(kind, body, { now, ttlMs: 0, stamper, nonce, requireLive: this.requireLive });
    return this.#keep(post(r), kind, now);
  }

  /**
   * Open something from this conversation's inbox. Returns the session's result plus:
   *   dropped: true when a message arrived after its sender had deleted it (nothing is shown)
   *   deleted / refused: for a delete from the contact, how many messages were erased here, and
   *     how many it named that were yours (refused: a contact can't delete what you sent)
   * Disappearing messages count down from when they arrive (the shorter of the sender's timer and yours).
   */
  receive(wire, { now = Date.now(), stampKeys = null, receivedAt = now, holdUnknownKey = false } = {}) {
    return this.#serial(async () => {
      // receivedAt: when the wire came off the relay (the app may read it later)
      // holdUnknownKey: a stamp under a key not in stampKeys throws unknown_stamp_key, nothing moved (MSG-07)
      const m = await this.session.decrypt(wire, { now, stampKeys, requireLive: this.requireLive, receivedAt, holdUnknownKey });
      let out = m;
      if (m.refused) return this.#saved(m, now); // not approved live: nothing kept, nothing applied
      const pAt = peerLiveAt({ live: m.live, sentAt: m.at, receivedAt });
      if (pAt !== null && !(this.live.peerAt >= pAt)) this.live.peerAt = pAt;
      if (SHOWN.has(m.kind)) {
        const added = this.store.add({
          id: m.id, dir: "in", kind: m.kind, body: m.body, at: m.at, expiresAt: m.ttlMs ? now + m.ttlMs : null,
          live: m.live, stamped: m.stamped, duress: m.duress,
        }, now);
        out = { ...m, dropped: !added };
      } else if (m.kind === "delete") {
        out = { ...m, ...this.store.applyRemoteDelete(m.ids, now) };
      }
      return this.#saved(out, now);
    });
  }

  /** What's on screen. Expired messages are already gone. */
  messages(now = Date.now()) { return this.dead ? [] : this.store.list(now); }

  /**
   * Delete one message.
   *   forBoth false: from this phone only. Returns { deleted }.
   *   forBoth true:  only for messages you sent (including ones that already disappeared here in
   *     the last 14 days). Returns { deleted, unsend, send }:
   *     unsend { box, retract } → relay.retract(box, retract): true means it was never delivered
   *     send   { box, wire, retractTag } → post it: the contact's phone erases the message, or, if it
   *            hasn't arrived, destroys the key that would have opened it
   * If the conversation has ended, delete for both fails and nothing is deleted, so you can
   * choose to delete it for yourself instead (or unsend it: see forget).
   */
  delete(id, { forBoth = false, now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => {
      if (!forBoth) return this.#saved({ deleted: !!this.store.delete(id, now) }, now);
      const entry = this.store.outgoing(now).find((m) => m.id === id);
      if (!entry) {
        if (this.store.get(id, now)) throw new MsgError("not_yours", "Only messages you sent can be deleted for both of you");
        throw new MsgError("not_found", "That message isn't here");
      }
      const c = await this.#sendProtocol("delete", deleteBody([entry]), { now, stamper });
      const gone = this.store.delete(id, now);
      // not posted yet: it never leaves this phone at all
      this.outbox = this.outbox.filter((o) => o.id !== id);
      return this.#saved({ deleted: true, unsend: unsendOf(gone), send: c }, now);
    });
  }

  /**
   * The approver's first message: "accept". Under the human-to-human rule it carries the
   * approver's live stamp, so the requester knows a live human accepted. Returns what to post.
   */
  accept({ now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => this.#saved(await this.#sendProtocol("accept", "", { now, stamper }), now));
  }

  /**
   * "I'm here": a stamped receipt with no content, sent when the holder opens the conversation
   * with a live check. It makes the human-to-human state mutual for READING too: without it,
   * someone who only reads is live on their own phone but invisible to the contact until they
   * send something. The contact's phone counts it like any live message (peerLiveAt) and shows
   * nothing else. Returns what to post.
   */
  here({ now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => this.#saved(await this.#sendProtocol("receipt", '{"here":1}', { now, stamper }), now));
  }

  /** Turn disappearing messages on (ms) or off (0) for both of you. Returns what to post. */
  setTimer(ms, { now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => this.#saved(await this.#sendProtocol("timer", String(ms), { now, stamper }), now));
  }

  /** What forget() will take: { stamps, steps } for this conversation now (steps: live checks, at perCheck stamps each). */
  forgetPlan({ forBoth = false, notify = forBoth, now = Date.now(), perCheck = STAMPS_PER_CHECK } = {}) {
    if (this.session.status !== "connected") return { stamps: 0, steps: forBoth ? 1 : 0 };
    const recallable = forBoth ? this.store.outgoing(now).filter((m) => m.pos).length : 0;
    const stamps = Math.ceil(recallable / MAX_DELETE) + (notify ? 1 : 0);
    return { stamps, steps: Math.max(1, Math.ceil(stamps / perCheck)) };
  }

  /**
   * Delete the whole conversation from this phone: every message, and the keys.
   *   forBoth: send deletes for every message you sent that can still be recalled, then end the
   *            conversation, so the contact's phone erases your messages too.
   *   notify:  just tell the contact the conversation ended (default: only with forBoth).
   *   perCheck: stamps one live check may approve (default 2, as servers allow; a stamper with
   *            .many is asked once per step).
   *
   * Nothing is erased until everything it has to send is stamped and encrypted (PC-28): if the
   * check, the server or a save fails, the conversation is left as it was (anything already
   * encrypted stays in the outbox, sealed, to post) and the error says so.
   *
   * One step or several. With more to send than one check can stamp (over 500 recallable messages
   * for 2 stamps a check), each call sends the next deletes, removes those messages from this
   * phone, and returns { done: false, left } (stamped messages still to send): ask for another
   * check and call again. The last step ends the conversation and erases it.
   *
   * Returns { done, send: [...], unsend: [...], pending: [...] (last step only), left }: post
   * `pending` then `send`, and try `unsend` at the relay.
   * unsend covers every message of yours this step took off this phone, whether or not it could be
   * recalled, and even if the conversation had already ended. After the last step the app deletes
   * the stored conversation and its key, and the persona's salt from the contact list, which
   * forgets this persona for good.
   */
  forget({ forBoth = false, notify = forBoth, now = Date.now(), stamper = null, perCheck } = {}) {
    return this.#serial(async () => {
      const connected = this.session.status === "connected";
      // Under the human-to-human rule, telling the contact anything needs a live check; check that
      // first, so a missing stamper refuses before anything is erased.
      if (connected && (forBoth || notify) && this.requireLive && typeof stamper !== "function") throw new MsgError("stamp_required", "Deleting for both of you needs a live check");
      const max = perCheck ?? (typeof stamper?.many === "function" ? (stamper.perCheck ?? STAMPS_PER_CHECK) : Infinity);
      if (!(max >= 1)) throw new MsgError("bad_request", "perCheck must be at least 1");
      const mine = forBoth ? this.store.outgoing(now) : [];
      const items = [];
      if (connected) {
        const recallable = mine.filter((m) => m.pos);
        for (let i = 0; i < recallable.length; i += MAX_DELETE) {
          const chunk = recallable.slice(i, i + MAX_DELETE);
          items.push({ kind: "delete", body: deleteBody(chunk), ids: chunk.map((m) => m.id) });
        }
        if (notify) items.push({ kind: "close", body: "" });
      }
      const last = items.length <= max;
      const now_ = last ? items : items.slice(0, max);
      // Every stamp first, in one check: a check that fails or is refused changes nothing.
      const planned = now_.length ? await this.#plan(now_, stamper, now) : [];
      const send = [];
      try {
        for (const it of planned) send.push(await this.#sendProtocol(it.kind, it.body, { now, stamper: it.stamper, nonce: it.nonce }));
      } catch (e) {
        // Nothing erased. What was encrypted is in the outbox; save it so the ratchet and the
        // outbox agree, and hand it back with the error.
        try { await this.#saved(null, now); } catch {}
        throw Object.assign(e, { partial: { send } });
      }
      if (!last) {
        // Step done: these messages are deleted for both (or will be once posted). Take them off
        // this phone so the next step doesn't name them again.
        const ids = new Set(now_.flatMap((it) => it.ids || []));
        const unsend = [];
        for (const m of mine) if (ids.has(m.id)) { const u = unsendOf(this.store.delete(m.id, now)); if (u) unsend.push(u); }
        const left = items.length - now_.length;
        return this.#saved({ done: false, send, unsend, left }, now);
      }
      const unsend = [];
      for (const m of mine) { const u = unsendOf(m); if (u) unsend.push(u); }
      // pending: what hadn't reached the relay before this (earlier steps' deletes, and, when it's
      // only for you, what you'd already sent). Post it before `send`; the saved outbox goes with
      // the conversation. Your unposted words, when it's for both, simply never leave.
      const pending = this.outbox.filter((o) => !send.some((x) => x.id === o.id) && !(forBoth && SHOWN.has(o.kind)))
        .map(({ id, box, wire, retractTag }) => ({ id, box, wire, retractTag }));
      this.dead = true; // anything queued after this is refused
      this.outbox = [];
      this.store.deleteAll();
      await this.session.erase();
      return { done: true, send, unsend, pending, left: 0 };
    });
  }

  /**
   * Lock: forget everything this object holds in memory (message bodies and every ratchet
   * key), leaving the saved copy as it is. Anything queued finishes first; nothing runs after.
   */
  unload() {
    const run = this.queue.then(async () => { this.store.deleteAll(); this.outbox = []; await this.session.unload(); });
    this.dead = true;
    this.queue = run.catch(() => {});
    return run;
  }

  /**
   * Save the ratchet and the history together, under a NEW random key. Store
   * `blob`; put `key` in the phone's secure storage in place of the previous key.
   * Older blobs, and everything deleted since they were made (messages, and the
   * ratchet's keys for messages deleted before they arrived), can't be opened once
   * the old key is gone. One blob, so a crash can't save one half without the other.
   */
  seal(now = Date.now()) { return this.#serial(() => this.#seal(now)); }

  async #seal(now) {
    const st = this.session.toJSON();
    const version = this.session.version;
    const head = concat(this.session.convId, u32(Math.floor(version / 2 ** 32)), u32(version >>> 0));
    const key = random(32), nonce = random(12);
    const ct = await aeadSeal(key, nonce, encodeJSON({ v: 1, session: st, history: toPlain(this.store.toState(now)), live: { peerAt: this.live.peerAt }, outbox: toPlain(this.outbox) }), concat(label("conversation"), head));
    return { blob: concat(head, nonce, ct), key };
  }

  /** Load a saved conversation. convId: which conversation it must be. */
  static async open(key, blob, { convId, persist = null, requireLive = false } = {}) {
    return guard(async () => {
      if (!(convId instanceof Uint8Array) || convId.length !== 16) throw new MsgError("bad_request", "Say which conversation this is (convId)");
      if (!(blob instanceof Uint8Array) || blob.length < 24 + 12 + 16) throw new MsgError("malformed", "Not a saved conversation");
      const head = blob.subarray(0, 24);
      if (!equal(head.subarray(0, 16), convId)) throw new MsgError("wrong_conversation", "This belongs to another conversation");
      const o = decodeJSON(await aeadOpen(key, blob.subarray(24, 36), blob.subarray(36), concat(label("conversation"), head), "decrypt_failed"));
      if (o?.v !== 1 || !o.session || !o.history) throw new MsgError("malformed", "Bad saved conversation");
      const session = Session.fromJSON(o.session);
      const version = readU32(head, 16) * 2 ** 32 + readU32(head, 20);
      if (session.version !== version || !equal(session.convId, convId)) throw new MsgError("malformed", "Saved conversation is inconsistent");
      const outbox = Array.isArray(o.outbox) ? fromPlain(o.outbox) : [];
      return new Conversation(session, MessageStore.fromState(convId.slice(), fromPlain(o.history)), { persist, requireLive, live: o.live, outbox });
    });
  }
}

const post = (r) => ({ box: r.box, wire: r.wire, retractTag: r.retractTag, id: r.id });
// A copy: the store overwrites its own records when it deletes them.
const unsendOf = (m) => (m && m.box && m.retract ? { box: m.box, retract: m.retract.slice() } : null);
