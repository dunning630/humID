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
//
// What you can delete from the contact's phone is what YOU sent. What they sent
// stays theirs; you can always delete your own copy of it.

import { MsgError, utf8 } from "./util.js";
import { MessageStore } from "./history.js";
import { deleteBody, MAX_DELETE } from "./session.js";

const SHOWN = new Set(["text", "file-key"]);

export class Conversation {
  constructor(session, store = null) {
    this.session = session;
    this.store = store ?? new MessageStore(session.convId);
  }

  get status() { return this.session.status; }
  get timer() { return this.session.timer; }

  /** Send text. Returns { box, wire, retractTag, id }: post wire to box with the tag. */
  async send(text, { now = Date.now(), stamper = null, duress = false, ttlMs } = {}) {
    const r = await this.session.encrypt("text", text, { now, stamper, duress, ttlMs });
    this.store.add({
      id: r.id, dir: "out", kind: "text", body: utf8(text), at: now, expiresAt: r.ttlMs ? now + r.ttlMs : null,
      stamped: !!stamper, duress, pos: r.pos, box: r.box, retract: r.retract,
    }, now);
    return post(r);
  }

  /**
   * Open something from this conversation's inbox. Returns the session's result plus:
   *   dropped: true when a message arrived after its sender had deleted it (nothing is shown)
   *   deleted / refused: for a delete from the contact, how many messages were erased here, and
   *     how many it named that were yours (refused: a contact can't delete what you sent)
   * Disappearing messages count down from when they arrive.
   */
  async receive(wire, { now = Date.now(), stampKeys = null } = {}) {
    const m = await this.session.decrypt(wire, { now, stampKeys });
    if (SHOWN.has(m.kind)) {
      const added = this.store.add({
        id: m.id, dir: "in", kind: m.kind, body: m.body, at: m.at, expiresAt: m.ttlMs ? now + m.ttlMs : null,
        live: m.live, stamped: m.stamped, duress: m.duress,
      }, now);
      return { ...m, dropped: !added };
    }
    if (m.kind === "delete") return { ...m, ...this.store.applyRemoteDelete(m.ids, now) };
    return m;
  }

  /** What's on screen. Expired messages are already gone. */
  messages(now = Date.now()) { return this.store.list(now); }

  /**
   * Delete one message.
   *   forBoth false: from this phone only. Returns { deleted }.
   *   forBoth true:  only for messages you sent. Returns { deleted, unsend, send }:
   *     unsend { box, retract } → relay.retract(box, retract): true means it was never delivered
   *     send   { box, wire, retractTag } → post it: the contact's phone erases the message, or, if it
   *            hasn't arrived, destroys the key that would have opened it
   * If the conversation has ended, delete for both fails and nothing is deleted, so you can
   * choose to delete it for yourself instead.
   */
  async delete(id, { forBoth = false, now = Date.now() } = {}) {
    if (!forBoth) return { deleted: !!this.store.delete(id, now) };
    const entry = this.store.outgoing(now).find((m) => m.id === id);
    if (!entry) {
      if (this.store.get(id, now)) throw new MsgError("not_yours", "Only messages you sent can be deleted for both of you");
      throw new MsgError("not_found", "That message isn't here");
    }
    const c = await this.session.encrypt("delete", deleteBody([entry]), { now, ttlMs: 0 });
    const gone = this.store.delete(id, now);
    return { deleted: true, unsend: unsendOf(gone), send: post(c) };
  }

  /** Turn disappearing messages on (ms) or off (0) for both of you. Returns what to post. */
  async setTimer(ms, { now = Date.now() } = {}) {
    return post(await this.session.encrypt("timer", String(ms), { now, ttlMs: 0 }));
  }

  /**
   * Delete the whole conversation from this phone: every message, and the keys.
   *   forBoth: first send deletes for every message you sent that's still here, then end the
   *            conversation, so the contact's phone erases your messages too.
   *   notify:  just tell the contact the conversation ended (default: only with forBoth).
   * Returns { send: [...], unsend: [...] } to post and try at the relay. Afterwards the
   * app deletes the stored conversation, its history, both of their keys, and the persona's
   * salt from the contact list, which forgets this persona for good.
   */
  async forget({ forBoth = false, notify = forBoth, now = Date.now() } = {}) {
    const send = [], unsend = [];
    const live = this.session.status === "connected";
    if (live && forBoth) {
      const mine = this.store.outgoing(now).filter((m) => m.pos);
      for (let i = 0; i < mine.length; i += MAX_DELETE) {
        const chunk = mine.slice(i, i + MAX_DELETE);
        send.push(post(await this.session.encrypt("delete", deleteBody(chunk), { now, ttlMs: 0 })));
      }
      for (const m of mine) { const u = unsendOf(m); if (u) unsend.push(u); }
    }
    if (live && notify) send.push(post(await this.session.encrypt("close", "", { now, ttlMs: 0 })));
    this.store.deleteAll();
    await this.session.erase();
    return { send, unsend };
  }

  /** Save both parts. Returns { session: blob (seal it under the conversation's state key), history: { blob, key } }. */
  async seal(stateKey, now = Date.now()) {
    return { session: await this.session.seal(stateKey), history: await this.store.seal(now) };
  }
}

const post = (r) => ({ box: r.box, wire: r.wire, retractTag: r.retractTag, id: r.id });
// A copy: the store overwrites its own records when it deletes them.
const unsendOf = (m) => (m && m.box && m.retract ? { box: m.box, retract: m.retract.slice() } : null);
