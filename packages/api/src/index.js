// @humid/api — what the app calls. Every method runs over HTP/1; anything
// that touches keys takes a callback, so the biometric prompt stays in the app
// (and in the app's control) and this module never holds a private key.

import { HtpClient, HtpError } from "@humid/htp/client";
import { registerMessage, deviceMessage, loginMessage, identityId, b64u, unb64u, utf8 } from "@humid/htp";
import { verifyLedger } from "@humid/audit";
import { keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL } from "@humid/recovery";

export { HtpError, verifyLedger };

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

const ENVELOPE_TYPE = "application/vnd.humid.envelope";

/** The request each step-up approves, by API method name. */
const STEP_UP = {
  download: (id) => ["GET", `/vault/objects/${id}`],
  remove: (id) => ["DELETE", `/vault/objects/${id}`],
  removeDevice: (id) => ["DELETE", `/identity/devices/${id}`],
  closeIdentity: () => ["DELETE", "/identity/me"],
  approveLink: (code) => ["POST", `/recovery/links/${codeOf(code)}/approve`],
  setCard: () => ["PUT", "/recovery/card"],
  removeCard: () => ["DELETE", "/recovery/card"],
  setContacts: () => ["PUT", "/recovery/contacts"],
  removeContacts: () => ["DELETE", "/recovery/contacts"],
  help: (code) => ["POST", `/recovery/help/${codeOf(code)}`],
  cancelAlert: (ref) => ["POST", `/recovery/alerts/${ref}/cancel`],
};

/**
 * A code a person typed commits to public keys. Recompute it from the keys the
 * server returned: a server that swapped in its own keys is caught here.
 */
function checkCode(code, label, ...keys) {
  if (keyCode(label, ...keys) !== parseCode(code)) {
    throw new ApiError(409, "code_mismatch", "The server returned different keys for this code. Nothing was shared. Don't continue, and report this.");
  }
}
const codeOf = (input) => {
  const c = parseCode(input);
  if (!c) throw new ApiError(400, "bad_code", "That code isn't valid. It has 12 letters and numbers.");
  return c;
};

export class HumidApi {
  constructor({ baseUrl = "", pinnedKid = null, fetch } = {}) {
    this.htp = new HtpClient({ baseUrl, pinnedKid, ...(fetch ? { fetch } : {}) });
    this.session = null;
    this.onSignedOut = null;
    this.htp.onSessionLost = () => { this.session = null; this.onSignedOut?.("expired"); };
  }

  /**
   * Reserve the request slot for a step-up BEFORE the biometric check, so the
   * device's liveness key can sign exactly that request during the check:
   *   const t = await api.ticket("download", id);   // t.live: bytes to sign in hardware
   *   …biometric check signs t.live…
   *   await api.download(id, { ticket: t, sign: (message) => ({ sig, interrupt, live }) });
   */
  ticket(name, ...args) {
    const route = STEP_UP[name];
    if (!route) throw new Error(`No step-up for ${name}`);
    const [method, path] = route(...args);
    return this.htp.ticket(method, path);
  }

  /** Server identity, for display ("Connected to … · 7A3F-91C2-…") and pinning, plus its policy hint. */
  async server() {
    const s = await this.htp.serverKeys();
    return { kid: s.kid, fingerprint: s.fingerprint, policy: s.policy };
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
  #json(method, path, opts) { return this.#call(method, path, opts).then((r) => r.json()); }

  /* ---------------- accounts & devices ---------------- */

  /**
   * Create an account and enrol this device, in a fresh session.
   * `sign({ register, device, th })` runs inside ONE biometric interrupt and returns
   * { registerSig, sigAccount, sigDevice, live?, gateMethod?, assurance? }: the account
   * key signs both messages, the device key signs `device`, and the device's hardware
   * liveness key (made and attested for `th`) signs `device` too.
   * @param pub     account public keys { kemPk, dsaPk, xPk }
   * @param device  { dsaPk, platform, gateMethod, assurance }
   */
  async register({ pub, commit, device, sign }) {
    await this.htp.connect();
    const th = this.htp.transcript;
    const sigs = await sign({ register: registerMessage(th, pub, commit), device: deviceMessage(th, identityId(pub.dsaPk), device.dsaPk), th });
    this.session = await this.#json("POST", "/auth/register", {
      body: {
        kemPk: b64u(pub.kemPk), dsaPk: b64u(pub.dsaPk), xPk: b64u(pub.xPk), commit, sig: b64u(sigs.registerSig),
        device: deviceBody(device, sigs),
      },
    });
    return this.session;
  }

  /**
   * Join an existing account (after a device link or a recovery), in a fresh session.
   * `sign(message, th)` returns { sigAccount, sigDevice, live?, gateMethod?, assurance? } over the same message.
   */
  async enrollDevice({ account, device, via, recoveryId, sign }) {
    await this.htp.connect();
    const sigs = await sign(deviceMessage(this.htp.transcript, account, device.dsaPk), this.htp.transcript);
    this.session = await this.#json("POST", "/auth/device", { body: { account, via, recoveryId, device: deviceBody(device, sigs) } });
    return this.session;
  }

  /**
   * Sign in. `sign(message)` runs the biometric interrupt and returns
   * { sig (device key), interrupt, live? (liveness key, same message) }.
   */
  async login({ id, device, sign }) {
    await this.htp.connect();
    const { challenge } = await this.#json("POST", "/auth/challenge", { body: { id, device } });
    const { sig, interrupt, live } = await sign(loginMessage(this.htp.transcript, `${id}/${device}`, unb64u(challenge)));
    this.session = await this.#json("POST", "/auth/login", { body: { id, device, sig: b64u(sig), interrupt, ...(live ? { live: b64u(live) } : {}) } });
    return this.session;
  }

  async logout() {
    if (!this.htp.connected) return;
    try { await this.htp.call("POST", "/auth/logout"); } catch {}
    this.htp.close();
    this.session = null;
  }

  me() { return this.#json("GET", "/identity/me"); }
  removeDevice(id, stepUp) { return this.#json("DELETE", `/identity/devices/${id}`, { stepUp }); }

  /** Close the identity and erase the vault on the server. Needs a step-up. */
  async closeIdentity(stepUp) {
    const r = await this.#json("DELETE", "/identity/me", { stepUp });
    this.htp.close();
    this.session = null;
    return r;
  }

  /* ---------------- vault ---------------- */

  list() { return this.#json("GET", "/vault/objects"); }

  /** Upload an envelope sealed on this device, plus its encrypted index entry. */
  upload(envelope, indexBlob) {
    return this.#json("POST", "/vault/objects", { body: envelope, headers: { "content-type": ENVELOPE_TYPE, "x-humid-index": b64u(indexBlob) } });
  }

  rename(id, indexBlob) { return this.#json("PATCH", `/vault/objects/${id}`, { headers: { "x-humid-index": b64u(indexBlob) } }); }

  /** Fetch ciphertext. stepUp({ message }) must run a fresh biometric check and return { sig, interrupt }. */
  async download(id, stepUp) { return (await this.#call("GET", `/vault/objects/${id}`, { stepUp })).body; }

  remove(id, stepUp) { return this.#json("DELETE", `/vault/objects/${id}`, { stepUp }); }

  /** Read and VERIFY the access ledger. Returns the verification result with parsed entries. */
  async ledger({ limit = 200, trustedKeyFp } = {}) {
    const page = await this.#json("GET", `/ledger/events?limit=${limit}`);
    return { ...verifyLedger(page, { expectedOwner: this.session?.id, trustedKeyFp }), count: page.entries.length };
  }

  /* ---------------- device links ---------------- */

  /** New device: publish link keys, get the code to show. No sign-in needed. */
  startLink({ kemPk, xPk, platform }) { return this.#json("POST", "/recovery/links", { body: { kemPk: b64u(kemPk), xPk: b64u(xPk), platform } }); }
  /** New device: poll. { status: waiting | approved | expired, account?, envelope? } */
  async linkResult(code) {
    const r = await this.#json("GET", `/recovery/links/${code}/result`);
    return { ...r, envelope: r.envelope ? unb64u(r.envelope) : undefined };
  }
  /** Signed-in device: look up the keys behind a code someone typed. */
  async getLink(input) {
    const code = codeOf(input);
    const r = await this.#json("GET", `/recovery/links/${code}`);
    const out = { ...r, kemPk: unb64u(r.kemPk), xPk: unb64u(r.xPk) };
    checkCode(code, LINK_LABEL, out.kemPk, out.xPk);
    return out;
  }
  /** Signed-in device: hand over the account seed, sealed to the new device's link keys. */
  approveLink(code, envelope, stepUp) {
    return this.#json("POST", `/recovery/links/${codeOf(code)}/approve`, { body: envelope, headers: { "content-type": ENVELOPE_TYPE }, stepUp });
  }

  /* ---------------- recovery card ---------------- */

  card() { return this.#json("GET", "/recovery/card"); }
  setCard({ tag, blob }, stepUp) { return this.#json("PUT", "/recovery/card", { body: { tag, blob: b64u(blob) }, stepUp }); }
  removeCard(stepUp) { return this.#json("DELETE", "/recovery/card", { stepUp }); }

  /* ---------------- recovery contacts ---------------- */

  /** "Be a recovery contact": publish this account's public keys under a short code. */
  offerContact({ kemPk, xPk, dsaPk }) { return this.#json("POST", "/recovery/offers", { body: { kemPk: b64u(kemPk), xPk: b64u(xPk), dsaPk: b64u(dsaPk) } }); }
  async getOffer(input) {
    const code = codeOf(input);
    const r = await this.#json("GET", `/recovery/offers/${code}`);
    const out = { ...r, kemPk: unb64u(r.kemPk), xPk: unb64u(r.xPk), dsaPk: unb64u(r.dsaPk) };
    checkCode(code, OFFER_LABEL, out.kemPk, out.xPk, out.dsaPk);
    if (identityId(out.dsaPk) !== out.account) throw new ApiError(409, "code_mismatch", "The server's answer doesn't match this contact. Nothing was shared.");
    return out;
  }
  async contacts() {
    const r = await this.#json("GET", "/recovery/contacts");
    return { ...r, guardians: (r.guardians || []).map((g) => ({ ...g, label: g.label ? unb64u(g.label) : null })) };
  }
  /** guardians: [{ contact, offer (code), envelope (bytes), label (bytes) }] */
  setContacts({ threshold, guardians }, stepUp) {
    return this.#json("PUT", "/recovery/contacts", {
      body: { threshold, guardians: guardians.map((g) => ({ contact: g.contact, offer: g.offer, envelope: b64u(g.envelope), label: g.label ? b64u(g.label) : undefined })) },
      stepUp,
    });
  }
  removeContacts(stepUp) { return this.#json("DELETE", "/recovery/contacts", { stepUp }); }
  /** Shares this account holds for other people: [{ owner, envelope, createdAt }] */
  async protecting() {
    const r = await this.#json("GET", "/recovery/protecting");
    return r.shares.map((s) => ({ ...s, envelope: unb64u(s.envelope) }));
  }

  /* ---------------- recovering ---------------- */

  /** New device. body: { method: "card", tag, platform } | { method: "contacts", kemPk, xPk, platform } */
  startRecovery(body) {
    const b = body.method === "contacts" ? { ...body, kemPk: b64u(body.kemPk), xPk: b64u(body.xPk) } : body;
    return this.#json("POST", "/recovery/requests", { body: b });
  }
  /** New device: poll. When released: { status: "released", blob } (card) or { shares: [envelope] } (contacts). */
  async recoveryStatus(id) {
    const r = await this.#json("GET", `/recovery/requests/${id}`);
    return { ...r, blob: r.blob ? unb64u(r.blob) : undefined, shares: r.shares ? r.shares.map(unb64u) : undefined };
  }
  /** A contact looks up the recovery code someone sent them. */
  async getHelp(input) {
    const code = codeOf(input);
    const r = await this.#json("GET", `/recovery/help/${code}`);
    const out = { ...r, kemPk: unb64u(r.kemPk), xPk: unb64u(r.xPk) };
    checkCode(code, REQUEST_LABEL, out.kemPk, out.xPk);
    return out;
  }
  /** A contact releases their share, re-sealed to the requesting device. */
  help(code, { owner, envelope }, stepUp) { return this.#json("POST", `/recovery/help/${codeOf(code)}`, { body: { owner, envelope: b64u(envelope) }, stepUp }); }

  /** Recoveries in progress for this account (shown on every signed-in device). */
  alerts() { return this.#json("GET", "/recovery/alerts").then((r) => r.alerts); }
  cancelAlert(ref, stepUp) { return this.#json("POST", `/recovery/alerts/${ref}/cancel`, { stepUp }); }
}

function deviceBody(device, sigs) {
  return {
    dsaPk: b64u(device.dsaPk), sigAccount: b64u(sigs.sigAccount), sigDevice: b64u(sigs.sigDevice),
    platform: device.platform, gateMethod: sigs.gateMethod ?? device.gateMethod, assurance: sigs.assurance ?? device.assurance,
    ...(sigs.live ? { live: liveBody(sigs.live) } : {}),
  };
}

/** live: { pub, sig, attestation?: { kind: "android-key", chain: [DER] } | { kind: "apple-app-attest", object } } (bytes) */
function liveBody(l) {
  const a = l.attestation;
  return {
    pub: b64u(l.pub), sig: b64u(l.sig),
    ...(a ? { attestation: a.kind === "android-key" ? { kind: a.kind, chain: a.chain.map((c) => b64u(c)) } : { kind: a.kind, object: b64u(a.object) } } : {}),
  };
}

export const decodeB64u = unb64u;
export const encodeUtf8 = utf8;
