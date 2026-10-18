// @humid/api — what the app calls. Every method runs over HTP/1; anything
// that touches keys takes a callback, so the biometric prompt stays in the app
// (and in the app's control) and this module never holds a private key.

import { HtpClient, HtpError } from "@humid/htp/client";
import { registerMessage, deviceMessage, loginMessage, identityId, b64u, unb64u, utf8 } from "@humid/htp";
import { verifyLedger, verifyCheckpoint } from "@humid/audit";
import { keyCode, parseCode, LINK_LABEL, OFFER_LABEL, REQUEST_LABEL } from "@humid/recovery";
import { importKeySet, blind, finalize, parseAccessCode, PassError } from "@humid/pass";

export { HtpError, verifyLedger, verifyCheckpoint };

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
  setAnchor: () => ["PUT", "/recovery/anchor"],
  removeAnchor: () => ["DELETE", "/recovery/anchor"],
  setSettings: () => ["PUT", "/recovery/settings"],
  stationVerify: (code) => ["POST", `/recovery/station/requests/${codeOf(code)}/verify`],
  clearDuress: () => ["POST", "/auth/duress/clear"],
  approveAdmin: (code) => ["POST", `/admin/requests/${codeOf(code)}/approve`],
  armCheckin: () => ["POST", "/checkin/arm"],
  checkIn: () => ["POST", "/checkin/check"],
  disarmCheckin: () => ["POST", "/checkin/disarm"],
};

/** Chip data for the wire: { dg1, sod, dg15? } bytes → base64url. */
const chipBody = (c) => ({ dg1: b64u(c.dg1), sod: b64u(c.sod), ...(c.dg15 ? { dg15: b64u(c.dg15) } : {}) });
const PRESENCE_PAD = "x".repeat(96);

/**
 * A code a person typed commits to public keys. Recompute it from the keys the
 * server returned: a server that swapped in its own keys is caught here.
 */
function checkCode(code, label, ...keys) {
  if (!code || keyCode(label, ...keys) !== parseCode(code)) {
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
      // details: the server's whole answer, for errors that say more (e.g. which documents)
      throw Object.assign(new ApiError(res.status, e.error || "error", e.message || `Request failed (${res.status})`), { details: e });
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
  async register({ pub, commit, device, sign, card, soleBiometric, pass }) {
    await this.htp.connect();
    const th = this.htp.transcript;
    const sigs = await sign({ register: registerMessage(th, pub, commit), device: deviceMessage(th, identityId(pub.dsaPk), device.dsaPk), th });
    this.session = await this.#json("POST", "/auth/register", {
      body: {
        kemPk: b64u(pub.kemPk), dsaPk: b64u(pub.dsaPk), xPk: b64u(pub.xPk), commit, sig: b64u(sigs.registerSig),
        device: deviceBody(device, sigs),
        // optional recovery card { tag, blob }, stored under this same live check
        ...(card ? { card: { tag: card.tag, blob: b64u(card.blob) } } : {}),
        ...(soleBiometric ? { soleBiometric: true } : {}),
        // an access pass (docs/ANONYMITY.md) when the server requires one
        ...(pass ? { pass } : {}),
      },
    });
    return this.session;
  }

  /* ---------------- anonymous payment ---------------- */

  /**
   * Swap an access code for an access pass, signed blind (RFC 9474).
   * Runs in a throwaway session of its own that never signs in, so nothing about it
   * travels to the registration that later spends the pass.
   *   saveDraft(draft)  called before the code is sent: persist it. If the app dies
   *                     before the answer arrives, call again with { draft } and the
   *                     same code: the server answers the same request again.
   * Returns the pass, already checked against the server's published key.
   */
  async getPass(code, { saveDraft = async () => {}, draft = null } = {}) {
    const parsed = parseAccessCode(code);
    if (!parsed) throw new ApiError(400, "code_invalid", "That access code isn't valid. Check it and try again.");
    const anon = new HtpClient({ baseUrl: this.htp.base, pinnedKid: this.htp.pinnedKid, fetch: this.htp.fetch, timeoutMs: this.htp.timeoutMs });
    const call = async (method, path, body) => {
      const res = await anon.call(method, path, body ? { body } : undefined);
      const j = res.json() || {};
      if (!res.ok) throw new ApiError(res.status, j.error || "error", j.message || `Request failed (${res.status})`);
      return j;
    };
    try {
      let set;
      try { set = importKeySet((await call("GET", "/pass/keys")).keys); }
      catch (e) { if (e instanceof PassError) throw new ApiError(502, e.code, e.message); throw e; }
      const key = draft ? set.keys.find((k) => k.id === draft.kid) : set.issuing;
      if (!key) throw new ApiError(409, "key_changed", "The vault's pass key changed before your pass was finished. Contact support with your access code.");
      let blinded;
      if (draft) blinded = draft.blinded;
      else {
        const b = blind(key);
        draft = b.draft;
        blinded = draft.blinded;
        await saveDraft(draft);
      }
      const out = await call("POST", "/pass/issue", { code: parsed, kid: key.id, blinded });
      try { return finalize(key, draft, unb64u(out.blindSig)); }
      catch (e) { if (e instanceof PassError) throw new ApiError(502, e.code, e.message); throw e; }
    } finally { anon.close(); }
  }

  /**
   * Join an existing account (after a device link or a recovery), in a fresh session.
   * `sign(message, th)` returns { sigAccount, sigDevice, live?, gateMethod?, assurance? } over the same message.
   */
  async enrollDevice({ account, device, via, recoveryId, sign, soleBiometric }) {
    await this.htp.connect();
    const sigs = await sign(deviceMessage(this.htp.transcript, account, device.dsaPk), this.htp.transcript);
    this.session = await this.#json("POST", "/auth/device", { body: { account, via, recoveryId, device: deviceBody(device, sigs), ...(soleBiometric ? { soleBiometric: true } : {}) } });
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

  /* ---------------- duress ---------------- */

  /**
   * Sent after EVERY unlock. duress = true only when the person used their duress
   * gesture. The request is the same size and shape either way.
   */
  presence(duress = false) { return this.#json("POST", "/auth/presence", { body: { d: duress ? 1 : 0, pad: PRESENCE_PAD } }); }
  /** { lockdown, since, lastDuressAt, clearableAt } — a decoy session always sees { lockdown: false }. */
  duressStatus() { return this.#json("GET", "/auth/duress"); }
  clearDuress(stepUp) { return this.#json("POST", "/auth/duress/clear", { stepUp }); }
  removeDevice(id, stepUp) { return this.#json("DELETE", `/identity/devices/${id}`, { stepUp }); }

  /** Close the identity and erase the vault on the server. Needs a step-up. */
  async closeIdentity(stepUp) {
    const r = await this.#json("DELETE", "/identity/me", { stepUp });
    this.htp.close();
    this.session = null;
    return r;
  }

  /* ---------------- Check-in (docs/CHECKIN.md) ---------------- */

  /**
   * Where Check-in stands: { state: "off" | "armed" | "locked" | "erased", deadline?, erasesAt?,
   * windowMs?, maxWindowMs?, graceMs?, armedAt?, erasedAt? }. Times are milliseconds since the epoch.
   * locked: a check-in was missed and the vault opens nothing until the next one; at erasesAt it's erased.
   */
  checkin() { return this.#json("GET", "/checkin"); }
  /**
   * Arm Check-in, or change its settings (which also starts a new window). Needs a step-up.
   * keep: ids of the documents marked for the decoy view, which an erase leaves in place.
   * A 409 unsplit_items error lists, in error.details.items, documents that must be re-sealed first.
   */
  armCheckin({ windowMs, maxWindowMs, graceMs, keep = [] }, stepUp) {
    return this.#json("POST", "/checkin/arm", { body: { windowMs, maxWindowMs, graceMs, keep }, stepUp });
  }
  /** Check in: the next deadline, from now. nextWindowMs: a longer one (e.g. for the night), up to the armed maximum. Needs a step-up. */
  checkIn({ nextWindowMs } = {}, stepUp) { return this.#json("POST", "/checkin/check", { body: nextWindowMs ? { nextWindowMs } : {}, stepUp }); }
  /** Turn Check-in off. Needs a step-up. */
  disarmCheckin(stepUp) { return this.#json("POST", "/checkin/disarm", { body: {}, stepUp }); }

  /* ---------------- vault ---------------- */

  list() { return this.#json("GET", "/vault/objects"); }

  /** Upload an envelope sealed on this device, plus its encrypted index entry. */
  /** Upload a sealed envelope. `share`: a split document's key (32 bytes), stored by the keyshare service, never the vault. */
  upload(envelope, indexBlob, share) {
    return this.#json("POST", "/vault/objects", { body: envelope, headers: { "content-type": ENVELOPE_TYPE, "x-humid-index": b64u(indexBlob), ...(share ? { "x-humid-share": b64u(share) } : {}) } });
  }

  rename(id, indexBlob) { return this.#json("PATCH", `/vault/objects/${id}`, { headers: { "x-humid-index": b64u(indexBlob) } }); }

  /** Fetch ciphertext. stepUp({ message }) must run a fresh biometric check and return { sig, interrupt }. */
  async download(id, stepUp) { return (await this.#call("GET", `/vault/objects/${id}`, { stepUp })).body; }

  /** Envelope plus, for a split document, its key, released under the same step-up. share is null for older documents. */
  async downloadWithShare(id, stepUp) {
    const r = await this.#call("GET", `/vault/objects/${id}`, { stepUp });
    const h = r.headers?.["x-humid-share"];
    return { envelope: r.body, share: h ? unb64u(String(h)) : null };
  }

  remove(id, stepUp) { return this.#json("DELETE", `/vault/objects/${id}`, { stepUp }); }

  /**
   * Check this account's place in the public transparency log: the latest ledger
   * entry is in the published tree, and the tree extends `previous` ({ size, root }),
   * the checkpoint this device verified last time. Returns verifyCheckpoint's result.
   */
  async continuity({ previous, trustedKeyFp } = {}) {
    const inc = await this.#json("GET", "/ledger/tlog/inclusion");
    let consistency = null;
    if (previous?.size > 0 && previous.size <= inc.checkpoint.size) {
      consistency = (await this.#json("GET", `/ledger/tlog/consistency?from=${previous.size}&to=${inc.checkpoint.size}`)).proof;
    }
    const r = verifyCheckpoint(inc, { trustedKeyFp, previous, consistency, inclusion: { owner: inc.owner, seq: inc.seq, hash: inc.hash, index: inc.index, proof: inc.proof } });
    if (r.ok && this.session?.id && inc.owner !== this.session.id) return { ok: false, reason: "The log answered for someone else" };
    return { ...r, seq: inc.seq };
  }

  /** Read and VERIFY the access ledger. Returns the verification result with parsed entries. */
  async ledger({ limit = 200, trustedKeyFp } = {}) {
    const page = await this.#json("GET", `/ledger/events?limit=${limit}`);
    return { ...verifyLedger(page, { expectedOwner: this.session?.id, trustedKeyFp }), count: page.entries.length };
  }

  /* ---------------- device links ---------------- */

  /** New device: publish link keys, get the code to show. No sign-in needed. */
  /**
   * New device: ask to join. The code shown must commit to this device's own keys:
   * recomputed here, so a server that swapped in its keys is caught before anything is shown.
   */
  async startLink({ kemPk, xPk, platform }) {
    const r = await this.#json("POST", "/recovery/links", { body: { kemPk: b64u(kemPk), xPk: b64u(xPk), platform } });
    checkCode(r.code, LINK_LABEL, kemPk, xPk);
    return r;
  }
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
  async offerContact({ kemPk, xPk, dsaPk }) {
    const r = await this.#json("POST", "/recovery/offers", { body: { kemPk: b64u(kemPk), xPk: b64u(xPk), dsaPk: b64u(dsaPk) } });
    checkCode(r.code, OFFER_LABEL, kemPk, xPk, dsaPk);
    return r;
  }
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
  setContacts({ threshold, guardians, scheme }, stepUp) {
    return this.#json("PUT", "/recovery/contacts", {
      body: { threshold, scheme, guardians: guardians.map((g) => ({ contact: g.contact, offer: g.offer, envelope: b64u(g.envelope), label: g.label ? b64u(g.label) : undefined })) },
      stepUp,
    });
  }
  removeContacts(stepUp) { return this.#json("DELETE", "/recovery/contacts", { stepUp }); }
  /** Shares this account holds for other people: [{ owner, envelope, createdAt }] */
  async protecting() {
    const r = await this.#json("GET", "/recovery/protecting");
    return r.shares.map((s) => ({ ...s, envelope: unb64u(s.envelope) }));
  }

  /* ---------------- identity anchor, settings, witness alerts ---------------- */

  /** { available, exists, document?, country?, createdAt? } */
  anchor() { return this.#json("GET", "/recovery/anchor"); }
  /** Bind a passport or ID chip ({ dg1, sod, dg15? }) and store the anchor part under it. */
  setAnchor({ chip, part }, stepUp) { return this.#json("PUT", "/recovery/anchor", { body: { chip: chipBody(chip), part: b64u(part) }, stepUp }); }
  removeAnchor(stepUp) { return this.#json("DELETE", "/recovery/anchor", { stepUp }); }
  settings() { return this.#json("GET", "/recovery/settings"); }
  setSettings(settings, stepUp) { return this.#json("PUT", "/recovery/settings", { body: settings, stepUp }); }
  /** Recoveries and duress signals of the people this account protects: [{ kind, owner, … }] */
  protectingAlerts() { return this.#json("GET", "/recovery/protecting/alerts").then((r) => r.alerts); }

  /* ---------------- server administration (docs/ADMIN.md) ---------------- */

  /** For an administrator of this server: { health, alerts, updates, version, at }. Throws not_admin otherwise. */
  adminSummary() { return this.#json("GET", "/admin/summary"); }
  /** What a code from the server's admin console asks for: { code, kind: "enrol" | "action", title, lines, digest, check, expiresAt }. */
  adminRequest(code) { return this.#json("GET", `/admin/requests/${codeOf(code)}`); }
  /** Approve exactly that request (its digest), with a live check. */
  approveAdmin(code, digest, stepUp) { return this.#json("POST", `/admin/requests/${codeOf(code)}/approve`, { body: { digest }, stepUp }); }

  /* ---------------- verification stations ---------------- */

  station() { return this.#json("GET", "/recovery/station"); }
  stationRequest(code) { return this.#json("GET", `/recovery/station/requests/${codeOf(code)}`); }
  /** checks: { document, face, present } — what the operator confirmed in person. */
  /** A fresh challenge for the chip in front of the station (bytes). */
  async stationChallenge(code) { return unb64u((await this.#json("POST", `/recovery/station/requests/${codeOf(code)}/challenge`)).nonce); }
  stationVerify(code, { chip, checks, signature, hash }, stepUp) {
    const body = { chip: chipBody(chip), checks, ...(signature ? { signature: b64u(signature) } : {}), ...(hash ? { hash } : {}) };
    return this.#json("POST", `/recovery/station/requests/${codeOf(code)}/verify`, { body, stepUp });
  }

  /* ---------------- recovering ---------------- */

  /**
   * New device. body:
   *   { method: "quorum", kemPk, xPk, platform, tag? }   two proofs (witnesses, ID chip, seal card)
   *   { method: "card", tag, platform }                   a v1 card on its own
   *   { method: "contacts", kemPk, xPk, platform }        v1 contacts on their own
   */
  async startRecovery(body) {
    const b = body.kemPk ? { ...body, kemPk: b64u(body.kemPk), xPk: b64u(body.xPk) } : body;
    const r = await this.#json("POST", "/recovery/requests", { body: b });
    if (body.kemPk) checkCode(r.code, REQUEST_LABEL, body.kemPk, body.xPk);
    return r;
  }
  /** Two proofs: add the seal card. */
  recoveryAddCard(id, tag) { return this.#json("POST", `/recovery/requests/${id}/card`, { body: { tag } }); }
  /** Two proofs: a fresh challenge for the ID chip to sign (Active Authentication). Returns bytes. */
  async recoveryChallenge(id) { return unb64u((await this.#json("POST", `/recovery/requests/${id}/challenge`)).nonce); }
  /** Two proofs: the ID chip's data and its answer to the challenge. */
  recoveryAddAnchor(id, { chip, signature, hash }) {
    return this.#json("POST", `/recovery/requests/${id}/anchor`, { body: { chip: chipBody(chip), signature: b64u(signature), ...(hash ? { hash } : {}) } });
  }
  /**
   * New device: poll. When released: { status: "released", blob?, shares?, anchorPart? }:
   * the card blob, the contacts' or witnesses' shares, the anchor part — whichever this request earned.
   */
  async recoveryStatus(id) {
    const r = await this.#json("GET", `/recovery/requests/${id}`);
    return { ...r, blob: r.blob ? unb64u(r.blob) : undefined, shares: r.shares ? r.shares.map(unb64u) : undefined, anchorPart: r.anchorPart ? unb64u(r.anchorPart) : undefined };
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
