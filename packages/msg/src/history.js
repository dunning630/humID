// The message history on a phone, and what "delete" means for it.
//
// Deleting a file on a phone's flash storage doesn't reliably erase its bytes:
// the storage chip moves data around and old copies can survive. So HumID
// deletes by destroying keys (crypto-erasure):
//
//   - The whole history is sealed (AES-256-GCM) under a NEW random key every
//     time it's saved. The app keeps only the current key, in the phone's secure
//     storage (Keychain / Keystore), overwriting the previous one.
//   - A deleted message is simply absent from the next save. Every older saved
//     copy that still contained it is sealed under a key that no longer exists
//     anywhere, so it can't be opened, whatever survives on the flash chip.
//   - The same rotation means an old copy can't be put back (no rollback).
//
// Tombstones: when the contact deletes a message before it arrives, its id is
// remembered (without content) for 14 days, so a late copy is dropped instead of
// appearing. Disappearing messages are removed as soon as their time is up:
// they never appear in a list, and the next save leaves them out. One of YOUR
// disappearing messages leaves a contentless record (its id, ratchet position
// and unsend token) for 14 days, so if it was never delivered you can still
// unsend it or delete it from the contact's phone.

import { MsgError, random, concat, label, encodeJSON, decodeJSON, aeadSeal, aeadOpen, wipe, equal, toPlain, fromPlain, fromUtf8, guard } from "./util.js";

export const TOMBSTONE_TTL_MS = 14 * 24 * 3600_000; // the relay's retention: a late copy can't arrive after this
export const MAX_TOMBSTONES = 5000; // a contact flooding deletes can't grow this without bound; oldest go first
const DIRS = ["in", "out"];

export class MessageStore {
  /** @param convId the conversation's id (session.convId), bound into every save */
  constructor(convId, state = null) {
    if (!(convId instanceof Uint8Array) || convId.length !== 16) throw new MsgError("bad_request", "convId must be 16 bytes");
    this.convId = convId;
    this.s = state ?? { v: 1, msgs: [], tomb: [] };
    this.tombIds = new Set(this.s.tomb.map((t) => t.id));
  }

  /**
   * Add a message. Returns false (and stores nothing) if it is already here, or
   * if it was deleted before it arrived.
   * entry: { id, dir: "in"|"out", kind, body (bytes), at, expiresAt?, live?, stamped?, duress?,
   *          and for "out": pos, box, retract (kept so it can be unsent or deleted for both) }
   */
  add(entry, now = Date.now()) {
    if (!entry || typeof entry.id !== "string" || !DIRS.includes(entry.dir) || !(entry.body instanceof Uint8Array)) {
      throw new MsgError("bad_request", "Not a message entry");
    }
    this.#purge(now);
    if (this.tombIds.has(entry.id)) return false;
    if (this.s.msgs.some((m) => m.id === entry.id)) return false;
    if (entry.expiresAt != null && entry.expiresAt <= now) return false;
    this.s.msgs.push({
      id: entry.id, dir: entry.dir, kind: entry.kind, body: entry.body.slice(), at: entry.at, stored: now,
      expiresAt: entry.expiresAt ?? null, live: entry.live ?? null, stamped: !!entry.stamped, duress: !!entry.duress,
      pos: entry.pos ?? null, box: entry.box ?? null, retract: entry.retract ? entry.retract.slice() : null,
    });
    return true;
  }

  /** Messages to show, oldest first. Expired ones are removed first and never returned. */
  list(now = Date.now()) {
    this.#purge(now);
    return this.s.msgs.filter((m) => !m.ghost).sort((a, b) => a.at - b.at || a.stored - b.stored).map(view);
  }

  get(id, now = Date.now()) {
    this.#purge(now);
    const m = this.s.msgs.find((x) => x.id === id && !x.ghost);
    return m ? view(m) : null;
  }

  /**
   * My own messages that can still be deleted for both or unsent: those still
   * here, and those that disappeared from here in the last 14 days. Internal
   * records, including unsend tokens.
   */
  outgoing(now = Date.now()) {
    this.#purge(now);
    return this.s.msgs.filter((m) => m.dir === "out");
  }

  /**
   * Delete one message from this device. Its bytes are overwritten now and it is
   * left out of the next save. Returns the removed record (with what's needed to
   * delete it for both or unsend it), or null if it wasn't here.
   */
  delete(id, now = Date.now()) {
    const i = this.s.msgs.findIndex((m) => m.id === id);
    if (i < 0) return null;
    const [m] = this.s.msgs.splice(i, 1);
    const out = { ...m, body: null, retract: m.retract ? m.retract.slice() : null, pos: m.pos ? { ...m.pos } : null };
    wipe(m.body, m.retract);
    this.#tombstone(id, now);
    return out;
  }

  /**
   * The contact asked to delete messages THEY sent. Only incoming messages are
   * touched: a contact can never delete what you sent. Ids not here yet become
   * tombstones, so a copy that arrives late is dropped.
   */
  applyRemoteDelete(ids, now = Date.now()) {
    let deleted = 0, refused = 0;
    for (const id of ids) {
      const m = this.s.msgs.find((x) => x.id === id);
      if (m && m.dir !== "in") { refused++; continue; }
      if (!m && this.tombIds.has(id)) continue;
      if (m) { this.delete(id, now); deleted++; }
      else this.#tombstone(id, now);
    }
    return { deleted, refused };
  }

  /** Delete everything: every message, every tombstone. */
  deleteAll() {
    for (const m of this.s.msgs) wipe(m.body, m.retract);
    this.s = { v: 1, msgs: [], tomb: [] };
    this.tombIds = new Set();
  }

  /** Messages shown (records kept only to recall your disappeared messages don't count). */
  get size() { return this.s.msgs.filter((m) => !m.ghost).length; }

  /**
   * Seal for storage under a NEW random key. Store `blob`; put `key` in the
   * phone's secure storage in place of the previous key, then forget the old
   * blob. Older blobs become unreadable once the old key is gone.
   */
  async seal(now = Date.now()) {
    this.#purge(now);
    const key = random(32);
    const nonce = random(12);
    const ct = await aeadSeal(key, nonce, encodeJSON(toPlain(this.s)), concat(label("history"), this.convId));
    return { blob: concat(this.convId, nonce, ct), key };
  }

  static async open(key, blob, { convId } = {}) {
    return guard(async () => {
      if (!(convId instanceof Uint8Array) || convId.length !== 16) throw new MsgError("bad_request", "Say which conversation this history belongs to (convId)");
      if (!(blob instanceof Uint8Array) || blob.length < 16 + 12 + 16) throw new MsgError("malformed", "Not a sealed history");
      if (!equal(blob.subarray(0, 16), convId)) throw new MsgError("wrong_conversation", "This history belongs to another conversation");
      const pt = await aeadOpen(key, blob.subarray(16, 28), blob.subarray(28), concat(label("history"), convId), "decrypt_failed");
      return MessageStore.fromState(convId.slice(), fromPlain(decodeJSON(pt)));
    });
  }

  /** Plain state (for Conversation.seal), and back. */
  toState(now = Date.now()) { this.#purge(now); return this.s; }
  static fromState(convId, state) {
    if (state?.v !== 1 || !Array.isArray(state.msgs) || !Array.isArray(state.tomb)) throw new MsgError("malformed", "Bad history");
    return new MessageStore(convId, state);
  }

  #tombstone(id, now) {
    if (this.tombIds.has(id)) return;
    this.s.tomb.push({ id, at: now });
    this.tombIds.add(id);
    while (this.s.tomb.length > MAX_TOMBSTONES) this.tombIds.delete(this.s.tomb.shift().id);
  }

  #purge(now) {
    const keep = [];
    for (const m of this.s.msgs) {
      if (m.ghost) {
        if (now < m.ghost) keep.push(m); else wipe(m.retract);
      } else if (m.expiresAt != null && m.expiresAt <= now) {
        wipe(m.body);
        // Yours: keep how to recall it (no content) until the relay would have dropped it.
        if (m.dir === "out" && m.pos && now < m.stored + TOMBSTONE_TTL_MS) {
          keep.push({ id: m.id, dir: "out", kind: m.kind, body: new Uint8Array(0), at: m.at, stored: m.stored, expiresAt: null,
            ghost: m.stored + TOMBSTONE_TTL_MS, pos: m.pos, box: m.box, retract: m.retract });
        } else wipe(m.retract);
      } else keep.push(m);
    }
    if (keep.length !== this.s.msgs.length || keep.some((m, i) => m !== this.s.msgs[i])) this.s.msgs = keep;
    const fresh = this.s.tomb.filter((t) => now - t.at < TOMBSTONE_TTL_MS);
    if (fresh.length !== this.s.tomb.length) { this.s.tomb = fresh; this.tombIds = new Set(fresh.map((t) => t.id)); }
  }
}

function view(m) {
  const v = { id: m.id, dir: m.dir, kind: m.kind, body: m.body.slice(), at: m.at, expiresAt: m.expiresAt, live: m.live, stamped: m.stamped, duress: m.duress };
  if (m.kind === "text") v.text = fromUtf8(m.body);
  return v;
}
