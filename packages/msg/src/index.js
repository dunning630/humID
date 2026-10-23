// @humid/msg — HumID 4.0 (provisional): person-to-person messaging between
// HumID holders. Each side knows the other only by a per-contact persona ID;
// every contact is approved with a live check; messages are end-to-end
// encrypted with a hybrid post-quantum double ratchet and can carry a live
// stamp that proves a live human sent them without saying which one.
// See docs/MESSAGING.md.

export { VERSION, MsgError, toPlain, fromPlain } from "./util.js";
export { backend, useBackend, checkBackend, resetBackend, SIZES, isValidKemPk } from "./backend.js";
export {
  newPersona, personaFromSalt, personaId, personaFingerprint, safetyCode, publicOf, wipePersona,
  encodePub, decodePub, dualSign, dualVerify, PERSONA_ID_CHARS, SAFETY_CHARS,
} from "./persona.js";
export {
  createInvite, openInvite, requestContact, readRequest, acceptRequest, approveRequest, declineRequest, closeInvite, cancelInvite,
  formatInviteCode, parseInviteCode, inviteBoxOf, inviteQrPayload, parseInviteQr, DEFAULT_INVITE_TTL, MAX_INVITE_TTL, INVITE_SECRET_BYTES, INVITE_PIN_BYTES,
} from "./invite.js";
export {
  Session, openSession, conversationKeys, MAX_SKIP, KINDS, SKIPPED_TTL_MS, STAMP_MAX_AGE_MS, MAX_STAMPS_SEEN,
  MIN_TTL_MS, MAX_TTL_MS, MAX_DELETE, deleteBody, parseDelete, isTtl,
} from "./session.js";
export { MessageStore, TOMBSTONE_TTL_MS, MAX_TOMBSTONES } from "./history.js";
// The human-to-human rule: nobody interacts without a live check (live.js).
export { liveState, peerLiveAt, canRead, LIVE_WINDOW_MS, MIN_LIVE_WINDOW_MS, MAX_LIVE_WINDOW_MS, LIVE_SKEW_MS } from "./live.js";
export { Conversation } from "./conversation.js";
export {
  importStampKeys, blindStamp, finalizeStamp, verifyStamp, makeStamper, messageCommitment, requestCommitment,
  stampKeyFor, knowsStampKey, STAMP_SKEW_MS, MAX_ARCHIVED_STAMP_KEYS,
} from "./stamp.js";
export { BUCKETS, isWireSize, isBox, boxFor, pollDays, daysSince, NEAR_MIDNIGHT_MS, BACKFILL_DAYS, WIRE_VERSION, newRetract, retractTag } from "./wire.js";
export { memoryRelay, rateKey, RELAY_DEFAULTS } from "./relay.js";
// Proving it's you (docs/MESSAGING.md, "Proving it's you"): answer live instead
// of being matched. Nothing below looks at, records or compares a voice or face.
export {
  makeChallenge, sendChallenge, readChallenge, replyToChallenge, replyId, checkReply, spokenCode,
  CHALLENGE_TTL, MAX_CHALLENGE_TTL, CLOCK_SKEW, PURPOSES, ANSWERS, QUESTIONS, SPOKEN_CODE_CHARS,
} from "./challenge.js";
export {
  encodeMedia, decodeMedia, makeMediaCredential, verifyMediaCredential, mediaHash, mediaCommitment,
  MEDIA_KINDS, MEDIA_VERSION, MAX_IN_MESSAGE,
} from "./media.js";
export {
  lockerKey, sealEvidence, openEvidence, makeRelease, verifyRelease, releaseCommitment,
  EVIDENCE_VERSION, MAX_EVIDENCE, MAX_RELEASE_DAYS,
} from "./evidence.js";
