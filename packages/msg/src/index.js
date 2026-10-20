// @humid/msg — HumID 4.0 (provisional): person-to-person messaging between
// HumID holders. Each side knows the other only by a per-contact persona ID;
// every contact is approved with a live check; messages are end-to-end
// encrypted with a hybrid post-quantum double ratchet and can carry a live
// stamp that proves a live human sent them without saying which one.
// See docs/MESSAGING.md.

export { VERSION, MsgError } from "./util.js";
export { backend, useBackend, checkBackend, resetBackend, SIZES, isValidKemPk } from "./backend.js";
export {
  newPersona, personaFromSalt, personaId, personaFingerprint, safetyCode, publicOf, wipePersona,
  encodePub, decodePub, dualSign, dualVerify, PERSONA_ID_CHARS, SAFETY_CHARS,
} from "./persona.js";
export {
  createInvite, openInvite, requestContact, readRequest, acceptRequest, declineRequest, closeInvite, cancelInvite,
  formatInviteCode, parseInviteCode, inviteBoxOf, DEFAULT_INVITE_TTL, MAX_INVITE_TTL, INVITE_SECRET_BYTES, INVITE_PIN_BYTES,
} from "./invite.js";
export {
  Session, openSession, conversationKeys, MAX_SKIP, KINDS, SKIPPED_TTL_MS,
  MIN_TTL_MS, MAX_TTL_MS, MAX_DELETE, deleteBody, parseDelete, isTtl,
} from "./session.js";
export { MessageStore, TOMBSTONE_TTL_MS } from "./history.js";
export { Conversation } from "./conversation.js";
export {
  importStampKeys, blindStamp, finalizeStamp, verifyStamp, makeStamper, messageCommitment, requestCommitment,
} from "./stamp.js";
export { BUCKETS, isWireSize, isBox, boxFor, pollDays, WIRE_VERSION, newRetract, retractTag } from "./wire.js";
export { memoryRelay, rateKey, RELAY_DEFAULTS } from "./relay.js";
