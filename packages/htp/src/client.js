// HTP/1 client. Runs in the app (browser, WKWebView, Android WebView) and in
// Node for tests. Transport is plain HTTPS POSTs, so it works through any
// proxy or CDN, which see only opaque frames.

import { clientHello, clientFinish, keyId, fingerprint } from "./handshake.js";
import { sealFrame, openFrame, parseHeader, DIR, MEDIA_TYPE } from "./frame.js";
import { stepUpMessage } from "./proofs.js";
import { unb64u, toHex, equal, wipe, utf8, fromUtf8 } from "./primitives.js";

export class HtpError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.code = code;
    this.status = status;
  }
}

export class HtpClient {
  /**
   * @param baseUrl   e.g. "https://vault.humidsecure.ai" or "" for same origin
   * @param pinnedKid hex server key id; when set, any other server is refused
   * @param fetch     injectable for tests
   */
  constructor({ baseUrl = "", pinnedKid = null, fetch = globalThis.fetch.bind(globalThis) } = {}) {
    this.base = baseUrl.replace(/\/$/, "");
    this.pinnedKid = pinnedKid ? pinnedKid.toLowerCase() : null;
    this.fetch = fetch;
    this.server = null;
    this.session = null;
    this.seq = 0;
    this.onSessionLost = null;
  }

  /** Fetch and authenticate the server's public keys. */
  async serverKeys() {
    if (this.server) return this.server;
    const res = await this.fetch(`${this.base}/htp/v1/keys`, { headers: { accept: "application/json" }, cache: "no-store" });
    if (!res.ok) throw new HtpError("server_unreachable", `Server keys unavailable (${res.status})`);
    const j = await res.json();
    const keys = { kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) };
    const kid = toHex(keyId(keys.kemPk, keys.xPk, keys.dsaPk));
    if (kid !== String(j.kid).toLowerCase()) throw new HtpError("server_keys_invalid", "Server key bundle is inconsistent.");
    if (this.pinnedKid && kid !== this.pinnedKid) {
      throw new HtpError("server_identity_changed", "This server's identity does not match the one this app trusts. Refusing to connect.");
    }
    this.server = { ...keys, kid, fingerprint: fingerprint(keyId(keys.kemPk, keys.xPk, keys.dsaPk)) };
    return this.server;
  }

  /** Run the handshake. Called automatically by call(). */
  async connect() {
    const server = await this.serverKeys();
    const { wire, state } = clientHello(server);
    const res = await this.fetch(`${this.base}/htp/v1/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(wire),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      this.server = null; // re-fetch keys next time
      if (/unknown server key id/.test(e.message || "")) {
        throw new HtpError("server_identity_changed", "This server's identity does not match the one this app trusts. Refusing to connect.", res.status);
      }
      throw new HtpError(e.error || "handshake_failed", e.message || `Handshake failed (${res.status})`, res.status);
    }
    this.close();
    this.session = clientFinish(state, await res.json());
    this.seq = 0;
    return this.session;
  }

  get connected() { return !!this.session && this.session.expiresAt > Date.now(); }
  get transcript() { return this.session?.th; }

  /**
   * Make one encrypted call.
   * @param opts.body     Uint8Array | object (sent as JSON) | undefined
   * @param opts.stepUp   async ({ message }) => { sig: Uint8Array, interrupt } — biometric step-up
   */
  async call(method, path, { body, headers = {}, stepUp } = {}) {
    if (!this.connected) await this.connect();
    let bytes = body;
    const h = { ...headers };
    if (body && !(body instanceof Uint8Array)) { bytes = utf8(JSON.stringify(body)); h["content-type"] = "application/json"; }
    const s = this.session;
    const seq = ++this.seq;
    const meta = { m: method.toUpperCase(), p: path, h };
    if (stepUp) {
      const at = Date.now();
      const message = stepUpMessage(s.th, seq, meta.m, path, bytes, at);
      const { sig, interrupt } = await stepUp({ message });
      meta.proof = { at, sig: b64(sig), interrupt };
    }
    const frame = await sealFrame(s.c2s, DIR.request, s.sid, seq, meta, bytes);
    const res = await this.fetch(`${this.base}/htp/v1/call`, {
      method: "POST",
      headers: { "content-type": MEDIA_TYPE },
      body: frame,
    });
    if (res.headers.get("content-type")?.startsWith("application/json")) {
      // Unencrypted error: the gateway could not open the frame (expired session etc.).
      const e = await res.json().catch(() => ({}));
      if (e.error === "session_unknown" || e.error === "session_expired") {
        this.close();
        this.onSessionLost?.(e.error);
      }
      throw new HtpError(e.error || "transport_error", e.message || `Call failed (${res.status})`, res.status);
    }
    const parsed = parseHeader(new Uint8Array(await res.arrayBuffer()));
    if (parsed.dir !== DIR.response || parsed.seq !== seq || !equal(parsed.sid, s.sid)) {
      throw new HtpError("response_mismatch", "Response does not belong to this request.");
    }
    const { meta: rmeta, body: rbody } = await openFrame(s.s2c, parsed);
    return new HtpResponse(rmeta.s, rmeta.h || {}, rbody);
  }

  /** Forget the session keys (does not tell the server; see api logout). */
  close() {
    if (this.session) wipe(this.session.c2s, this.session.s2c);
    this.session = null;
  }
}

export class HtpResponse {
  constructor(status, headers, body) {
    this.status = status;
    this.headers = headers;
    this.body = body;
  }
  get ok() { return this.status >= 200 && this.status < 300; }
  json() { return this.body.length ? JSON.parse(fromUtf8(this.body)) : null; }
}

const b64 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
