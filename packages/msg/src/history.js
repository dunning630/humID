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
// they never appear in a list, and the next save leaves them out.

import { MsgError, random, concat, label, encodeJSON, decodeJSON, aeadSeal, aeadOpen, wipe, equal, toPlain, fromPlain, fromUtf8, guard } from "./util.js";

export const TOMBSTONE_TTL_MS = 14 * 24 * 3600_000; // the relay's retention: a late copy can't arrive after this
const DIRS = ["in", "out"];

export class MessageStore {
  /** @param convId the conversation's id (session.convId), bound into every save */
  constructor(convId, state = null) {
    if (!(convId instanceof Uint8Array) || convId.length !== 16) throw new MsgError("bad_request", "convId must be 16 bytes");
    this.convId = convId;
    this.s = state ?? { v: 1, msgs: [], tomb: [] };
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
    if (this.s.tomb.some((t) => t.id === entry.id)) return false;
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
    return [...this.s.msgs].sort((a, b) => a.at - b.at || a.stored - b.stored).map(view);
  }

  get(id, now = Date.now()) {
    this.#purge(now);
    const m = this.s.msgs.find((x) => x.id === id);
    return m ? view(m) : null;
  }

  /** My own messages still here (for "delete conversation for both"). Internal records, including unsend tokens. */
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
    const out = { ...m, body: null, retract: m.retract ? m.retract.slice() : null };
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
      if (m) { this.delete(id, now); deleted++; }
      else this.#tombstone(id, now);
    }
    return { deleted, refused };
  }

  /** Delete everything: every message, every tombstone. */
  deleteAll() {
    for (const m of this.s.msgs) wipe(m.body, m.retract);
    this.s = { v: 1, msgs: [], tomb: [] };
  }

  get size() { return this.s.msgs.length; }

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
      const state = fromPlain(decodeJSON(pt));
      if (state?.v !== 1 || !Array.isArray(state.msgs) || !Array.isArray(state.tomb)) throw new MsgError("malformed", "Bad history");
      return new MessageStore(convId.slice(), state);
    });
  }

  #tombstone(id, now) {
    if (!this.s.tomb.some((t) => t.id === id)) this.s.tomb.push({ id, at: now });
  }

  #purge(now) {
    const keep = [];
    for (const m of this.s.msgs) {
      if (m.expiresAt != null && m.expiresAt <= now) wipe(m.body, m.retract);
      else keep.push(m);
    }
    if (keep.length !== this.s.msgs.length) this.s.msgs = keep;
    this.s.tomb = this.s.tomb.filter((t) => now - t.at < TOMBSTONE_TTL_MS);
  }
}

function view(m) {
  const v = { id: m.id, dir: m.dir, kind: m.kind, body: m.body.slice(), at: m.at, expiresAt: m.expiresAt, live: m.live, stamped: m.stamped, duress: m.duress };
  if (m.kind === "text") v.text = fromUtf8(m.body);
  return v;
}
