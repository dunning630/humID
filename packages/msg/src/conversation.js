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
//   seal() / Conversation.open → save and load (ratchet + history together, a NEW key every save)
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
   */
  constructor(session, store = null, { persist = null, requireLive = false, live = null } = {}) {
    this.session = session;
    this.store = store ?? new MessageStore(session.convId);
    this.persist = persist;
    this.requireLive = !!requireLive;
    this.dead = session.status === "erased";
    this.queue = Promise.resolve();
    // When the contact was last proven live (live.js peerLiveAt): sealed with the conversation.
    this.live = { peerAt: Number.isFinite(live?.peerAt) ? live.peerAt : null };
  }

  get status() { return this.session.status; }
  get timer() { return this.session.timer; }
  /** When the contact was last proven live on this phone, or null. Feed it to liveState(). */
  get peerLiveAt() { return this.live.peerAt; }

  /**
   * Stamp several messages with ONE live check, when the stamper offers it
   * (stamper.many(commitments) → stamps, in order): one action the holder approves once,
   * such as deleting a whole conversation for both, is one check, not one per message.
   * Returns [{ kind, body, nonce, stamper }] to encrypt in order.
   */
  async #plan(items, stamper) {
    const nonces = items.map(() => random(16));
    if (!stamper) return items.map((it, i) => ({ ...it, nonce: nonces[i], stamper: null }));
    if (typeof stamper.many !== "function") return items.map((it, i) => ({ ...it, nonce: nonces[i], stamper }));
    const me = this.session.s.me.fp, convId = this.session.convId;
    const commits = items.map((it, i) => messageCommitment({ convId, senderFp: me, nonce: nonces[i], kind: it.kind, body: typeof it.body === "string" ? utf8(it.body) : it.body }));
    const stamps = await stamper.many(commits);
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
      const r = await this.session.encrypt(kind, content, { now, stamper, duress, ttlMs, requireLive: this.requireLive });
      this.store.add({
        id: r.id, dir: "out", kind, body: stored, at: now, expiresAt: r.ttlMs ? now + r.ttlMs : null,
        stamped: !!stamper, duress, pos: r.pos, box: r.box, retract: r.retract,
      }, now);
      return this.#saved(post(r), now);
    });
  }

  /**
   * Open something from this conversation's inbox. Returns the session's result plus:
   *   dropped: true when a message arrived after its sender had deleted it (nothing is shown)
   *   deleted / refused: for a delete from the contact, how many messages were erased here, and
   *     how many it named that were yours (refused: a contact can't delete what you sent)
   * Disappearing messages count down from when they arrive (the shorter of the sender's timer and yours).
   */
  receive(wire, { now = Date.now(), stampKeys = null } = {}) {
    return this.#serial(async () => {
      const m = await this.session.decrypt(wire, { now, stampKeys, requireLive: this.requireLive });
      let out = m;
      if (m.refused) return this.#saved(m, now); // not approved live: nothing kept, nothing applied
      const pAt = peerLiveAt({ live: m.live, sentAt: m.at, receivedAt: now });
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
      const c = await this.session.encrypt("delete", deleteBody([entry]), { now, ttlMs: 0, stamper, requireLive: this.requireLive });
      const gone = this.store.delete(id, now);
      return this.#saved({ deleted: true, unsend: unsendOf(gone), send: post(c) }, now);
    });
  }

  /**
   * The approver's first message: "accept". Under the human-to-human rule it carries the
   * approver's live stamp, so the requester knows a live human accepted. Returns what to post.
   */
  accept({ now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => this.#saved(post(await this.session.encrypt("accept", "", { now, ttlMs: 0, stamper, requireLive: this.requireLive })), now));
  }

  /** Turn disappearing messages on (ms) or off (0) for both of you. Returns what to post. */
  setTimer(ms, { now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => this.#saved(post(await this.session.encrypt("timer", String(ms), { now, ttlMs: 0, stamper, requireLive: this.requireLive })), now));
  }

  /**
   * Delete the whole conversation from this phone: every message, and the keys.
   *   forBoth: send deletes for every message you sent that can still be recalled, then end the
   *            conversation, so the contact's phone erases your messages too. The unsend tokens
   *            come back even if the conversation had already ended.
   *   notify:  just tell the contact the conversation ended (default: only with forBoth).
   * Returns { send: [...], unsend: [...] } to post and try at the relay. Afterwards the app
   * deletes the stored conversation and its key, and the persona's salt from the contact list,
   * which forgets this persona for good.
   */
  forget({ forBoth = false, notify = forBoth, now = Date.now(), stamper = null } = {}) {
    return this.#serial(async () => {
      const sends = this.session.status === "connected" && (forBoth || notify);
      // Under the human-to-human rule, telling the contact anything needs a live check; check that
      // first, so a missing stamper refuses before anything is erased.
      if (sends && this.requireLive && typeof stamper !== "function") throw new MsgError("stamp_required", "Deleting for both of you needs a live check");
      this.dead = true; // anything queued after this is refused
      const send = [], unsend = [];
      try {
        const mine = forBoth ? this.store.outgoing(now) : [];
        for (const m of mine) { const u = unsendOf(m); if (u) unsend.push(u); }
        if (this.session.status === "connected") {
          const recallable = mine.filter((m) => m.pos);
          const items = [];
          for (let i = 0; i < recallable.length; i += MAX_DELETE) items.push({ kind: "delete", body: deleteBody(recallable.slice(i, i + MAX_DELETE)) });
          if (notify) items.push({ kind: "close", body: "" });
          if (items.length) {
            for (const it of await this.#plan(items, stamper)) {
              send.push(post(await this.session.encrypt(it.kind, it.body, { now, ttlMs: 0, nonce: it.nonce, stamper: it.stamper, requireLive: this.requireLive })));
            }
          }
        }
      } finally {
        this.store.deleteAll();
        await this.session.erase();
      }
      return { send, unsend };
    });
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
    const ct = await aeadSeal(key, nonce, encodeJSON({ v: 1, session: st, history: toPlain(this.store.toState(now)), live: { peerAt: this.live.peerAt } }), concat(label("conversation"), head));
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
      return new Conversation(session, MessageStore.fromState(convId.slice(), fromPlain(o.history)), { persist, requireLive, live: o.live });
    });
  }
}

const post = (r) => ({ box: r.box, wire: r.wire, retractTag: r.retractTag, id: r.id });
// A copy: the store overwrites its own records when it deletes them.
const unsendOf = (m) => (m && m.box && m.retract ? { box: m.box, retract: m.retract.slice() } : null);
