// What a relay service needs from @humid/msg, without the rest of the module (no ratchet, no
// post-quantum code): the wire sizes, mailbox ids, unsend tags and the default caps.
export { isBox, isWireSize, retractTag, MAX_WIRE, TAG_RE, RETRACT_BYTES, BUCKETS } from "./wire.js";
export { RELAY_DEFAULTS, rateKey } from "./relay.js";
