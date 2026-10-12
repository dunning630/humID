// @humid/api — what the app calls. Every method runs over HTP/1; anything
// that touches keys takes a callback, so the biometric prompt stays in the app
// (and in the app's control) and this module never holds a private key.

import { HtpClient, HtpError } from "@humid/htp/client";
import { registerMessage, loginMessage, b64u, unb64u, utf8 } from "@humid/htp";
import { verifyLedger } from "@humid/audit";

export { HtpError, verifyLedger };

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

export class HumidApi {
  constructor({ baseUrl = "", pinnedKid = null, fetch } = {}) {
    this.htp = new HtpClient({ baseUrl, pinnedKid, ...(fetch ? { fetch } : {}) });
    this.session = null;
    this.onSignedOut = null;
    this.htp.onSessionLost = () => { this.session = null; this.onSignedOut?.("expired"); };
  }

  /** Server identity, for display ("Connected to … · 7A3F-91C2-…") and pinning. */
  async server() {
    const s = await this.htp.serverKeys();
    return { kid: s.kid, fingerprint: s.fingerprint };
  }

  get signedIn() { return !!this.session && this.htp.connected; }

  async #call(method, path, opts) {
    const res = await this.htp.call(method, path, opts);
    if (!res.ok) {
      const e = res.json() || {};
      if (res.status === 401 && e.error === "sign_in_required") { this.session = null; this.onSignedOut?.("required"); }
      throw new ApiError(res.status, e.error || "error", e.message || `Request failed (${res.status})`);
    }
    return res;
  }

  /**
   * Enrol a new identity. `sign(message)` is called once, inside the enrolment
   * interrupt, and must return the ML-DSA-87 signature.
   */
  async register({ pub, commit, device, sign }) {
    await this.htp.connect();
    const sig = await sign(registerMessage(this.htp.transcript, pub, commit));
    const res = await this.#call("POST", "/auth/register", {
      body: { kemPk: b64u(pub.kemPk), dsaPk: b64u(pub.dsaPk), xPk: b64u(pub.xPk), commit, sig: b64u(sig), device },
    });
    this.session = res.json();
    return this.session;
  }

  /** Sign in. `sign(message)` runs the biometric interrupt and returns { sig, interrupt }. */
  async login({ id, device, sign }) {
    await this.htp.connect();
    const { challenge } = (await this.#call("POST", "/auth/challenge", { body: { id } })).json();
    const { sig, interrupt } = await sign(loginMessage(this.htp.transcript, id, unb64u(challenge)));
    const res = await this.#call("POST", "/auth/login", { body: { id, sig: b64u(sig), interrupt, device } });
    this.session = res.json();
    return this.session;
  }

  async logout() {
    if (!this.htp.connected) return;
    try { await this.htp.call("POST", "/auth/logout"); } catch {}
    this.htp.close();
    this.session = null;
  }

  me() { return this.#call("GET", "/identity/me").then((r) => r.json()); }

  list() { return this.#call("GET", "/vault/objects").then((r) => r.json()); }

  /** Upload an envelope sealed on this device, plus its encrypted index entry. */
  upload(envelope, indexBlob) {
    return this.#call("POST", "/vault/objects", { body: envelope, headers: { "content-type": "application/vnd.humid.envelope", "x-humid-index": b64u(indexBlob) } }).then((r) => r.json());
  }

  rename(id, indexBlob) {
    return this.#call("PATCH", `/vault/objects/${id}`, { headers: { "x-humid-index": b64u(indexBlob) } }).then((r) => r.json());
  }

  /** Fetch ciphertext. stepUp({ message }) must run a fresh biometric check and return { sig, interrupt }. */
  async download(id, stepUp) {
    const res = await this.#call("GET", `/vault/objects/${id}`, { stepUp });
    return res.body;
  }

  remove(id, stepUp) { return this.#call("DELETE", `/vault/objects/${id}`, { stepUp }).then((r) => r.json()); }

  /** Read and VERIFY the access ledger. Returns the verification result with parsed entries. */
  async ledger({ limit = 200, trustedKeyFp } = {}) {
    const page = (await this.#call("GET", `/ledger/events?limit=${limit}`)).json();
    return { ...verifyLedger(page, { expectedOwner: this.session?.id, trustedKeyFp }), count: page.entries.length };
  }

  /** Close the identity and erase the vault on the server. Needs a step-up. */
  async closeIdentity(stepUp) {
    const r = (await this.#call("DELETE", "/identity/me", { stepUp })).json();
    this.htp.close();
    this.session = null;
    return r;
  }
}

export const decodeB64u = unb64u;
export const encodeUtf8 = utf8;
