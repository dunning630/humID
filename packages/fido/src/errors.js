// Errors a security key can return, in words a person can act on (CTAP 2.1 §8.2).

export class FidoError extends Error {
  /** code: a short stable name ("pin_invalid", "no_credentials", "lost", …). */
  constructor(code, message, { status, retries, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "FidoError";
    this.code = code;
    if (status !== undefined) this.status = status;
    if (retries !== undefined) this.retries = retries;
  }
}

const STATUS = {
  0x01: ["invalid_command", "The key didn't understand the request."],
  0x02: ["invalid_parameter", "The key refused a value in the request."],
  0x03: ["invalid_length", "The key refused the request's length."],
  0x11: ["cbor_type", "The key refused the request's format."],
  0x12: ["invalid_cbor", "The key refused the request's format."],
  0x14: ["missing_parameter", "The key said something was missing from the request."],
  0x16: ["unsupported_extension", "This key can't do what HumID needs (hmac-secret)."],
  0x19: ["credential_excluded", "This key is already one of your security keys."],
  0x21: ["processing", "The key is still busy."],
  0x26: ["unsupported_algorithm", "This key can't make the kind of key HumID uses."],
  0x27: ["operation_denied", "The key said no."],
  0x28: ["key_store_full", "This key is full. Remove a passkey you don't use from it, then try again."],
  0x2b: ["unsupported_option", "This key can't do what HumID needs."],
  0x2c: ["invalid_option", "The key refused an option."],
  0x2d: ["cancelled", "Cancelled on the key."],
  0x2e: ["no_credentials", "This key isn't one of the security keys added to HumID."],
  0x2f: ["user_action_timeout", "The key waited too long."],
  0x30: ["not_allowed", "The key refused that right now. Take it away and try again."],
  0x31: ["pin_invalid", "Wrong PIN."],
  0x32: ["pin_blocked", "This key's PIN is blocked after too many wrong tries. It can only be reset, which erases it, so it can't be a recovery proof any more."],
  0x33: ["pin_auth_invalid", "The key didn't accept HumID's PIN check. Take it away and try again."],
  0x34: ["pin_auth_blocked", "Three wrong PINs in a row. Take the key away, wait a moment, and try again."],
  0x35: ["pin_not_set", "This key has no PIN yet."],
  0x36: ["pin_required", "This key needs its PIN."],
  0x37: ["pin_policy", "The key won't accept that PIN. It needs to be longer."],
  0x39: ["too_large", "The request was too large for this key."],
  0x3a: ["action_timeout", "The key waited too long."],
  0x3b: ["up_required", "Touch the key, or hold it to the phone again."],
  0x3c: ["uv_blocked", "This key's fingerprint check is blocked. Use its PIN."],
  0x3f: ["uv_invalid", "The key didn't recognise the fingerprint."],
  0x40: ["unauthorized_permission", "The key refused HumID's permission request. Take it away and try again."],
};

export function statusError(status) {
  const [code, message] = STATUS[status] || ["ctap", `The key answered with error ${status}.`];
  return new FidoError(code, message, { status });
}
