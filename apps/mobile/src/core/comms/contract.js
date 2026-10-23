// HumID Comms — the contract for secure human-to-human communication (3.0 boundary).
//
// What the vault proves today: a document was sealed during a live check on an enrolled
// device and opens only after another. Comms extends the same proof to a message between two people:
// sealed on the sender's phone to the recipient's HumID keys, opened only after the
// recipient's live check, and every send and open on both ledgers. No server reads it,
// no password exists, no phone number or name is needed: a HumID is a set of keys.
//
// This file is the whole contract. Nothing in the app imports an implementation
// directly: screens and the kernel talk to `comms`, and a transport (the HumID server's
// relay, a local link, a future mesh) plugs in behind it. That is how 3.0 grows into
// communication without a forklift: the vault doesn't change, the contract doesn't
// change, only transports and message kinds are added.
//
// Design rules every transport must keep (they mirror the vault's):
//   1. Sealed on the phone, to the recipient's ML-KEM-1024 + X25519 keys (@humid/crypto
//      suite PQ1), signed by the sender's ML-DSA-87 key. The relay sees sizes and times.
//   2. One live check seals (the liveness key signs the ciphertext hash, like a document);
//      one live check opens. A message is never decrypted silently, not even to preview.
//   3. Split keys apply: the message key's second half is released by keyshare inside the
//      recipient's check, so a copied phone opens nothing.
//   4. Every send, open and delete is a ledger event on both sides, verified on the phone.
//   5. The recipient is a HumID, found through a match code (like adding a device), never
//      a phone number, email or name. The relay stores no address book.
//   6. A duress session sends and opens nothing real; a Heartbeat erase erases messages too.
//   7. Arbitrary payloads: a message is a sealed envelope like any document (text, a file,
//      a voice note, a key). Formats not yet invented fit without a new contract.
//
// 4.0: person-to-person messaging is built on @humid/msg instead (core/messaging.js,
// docs/MESSAGING.md), with per-contact personas, a ratchet and live stamps; this 3.0 contract
// stays as the boundary for other transports.
// Status: contract and in-memory stub only. No transport ships in 3.0.0; the screens
// show nothing until one is registered (`comms.transport`).

/** A message as the app sees it. The body is a sealed envelope (codec format v1). */
export const MESSAGE_KINDS = Object.freeze({
  text: "text/plain",
  file: "application/octet-stream",
  voice: "audio/*",
  key: "application/x-humid-key",   // e.g. a recovery piece, a device link
});

/**
 * A transport delivers sealed envelopes. It never sees a key or a plaintext.
 * @typedef {object} Transport
 * @property {string} id                       "relay" | "local" | …
 * @property {() => Promise<Peer[]>} peers      who this HumID can reach (by HumID id and a sealed label)
 * @property {(code: string) => Promise<Peer>} findPeer   a match code someone showed you → their public keys
 * @property {(env: Uint8Array, to: Peer, share: Uint8Array|null, proof) => Promise<{ id, at }>} send
 * @property {(since?: string) => Promise<Sealed[]>} inbox   sealed messages for this HumID
 * @property {(id: string, proof) => Promise<{ envelope: Uint8Array, share: Uint8Array|null }>} fetch  under a step-up
 * @property {(id: string, proof) => Promise<void>} remove
 */

/**
 * @typedef {object} Peer      { account, kemPk, xPk, dsaPk, label? }   (label: sealed under the index key)
 * @typedef {object} Sealed    { id, from, size, at, kind }             (never a name or content)
 */

const listeners = new Set();
let transport = null;

export const comms = {
  /** The transport in use, or null (3.0.0: null). Setting one makes the Messages surface appear. */
  get transport() { return transport; },
  set transport(t) { transport = t; for (const l of listeners) l(t); },
  get available() { return !!transport; },
  onChange(l) { listeners.add(l); return () => listeners.delete(l); },
  /** The proof a message carries, so a recipient can check who sealed it and that a live person did. */
  proofFields: Object.freeze(["signer", "interrupt", "live", "ciphertextHash"]),
};
