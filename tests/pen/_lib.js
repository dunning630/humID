// Shared helpers for the penetration regression pack. Everything runs against the
// in-process stack (tests/e2e/stack.js); nothing here reaches a dev server.
import { clientHello, clientFinish, sealFrame, DIR, MEDIA_TYPE, unb64u } from "@humid/htp";
import { HumidApi } from "@humid/api";
import { makeHolder } from "../e2e/holder.js";

/** Anything a refusal body must never contain: paths, Node internals, stack frames, hosts. */
export const LEAK_RE = /(\/home\/|\/humid\/|node:internal|\bat async\b|\bat Object\b|\.js:\d+|Error:|\bstack\b|ECONNREFUSED|127\.0\.0\.1:\d|localhost:\d)/i;

export function assertNoLeak(assert, text) {
  assert.ok(!LEAK_RE.test(text), `refusal must not leak internals: ${text.slice(0, 200)}`);
}

/** A raw HTP session built by hand, so tests control every byte of every frame. */
export async function rawSession(baseUrl) {
  const j = await (await fetch(`${baseUrl}/htp/v1/keys`)).json();
  const server = { kemPk: unb64u(j.kem), xPk: unb64u(j.x25519), dsaPk: unb64u(j.dsa) };
  const { wire, state } = clientHello(server);
  const res = await fetch(`${baseUrl}/htp/v1/hello`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(wire) });
  if (!res.ok) throw new Error(`hello refused: ${res.status} ${await res.text()}`);
  return clientFinish(state, await res.json());
}

/** Seal one request frame for a raw session. */
export const frame = (s, seq, meta = { m: "GET", p: "/identity/me", h: {} }, body, ts) => sealFrame(s.c2s, DIR.request, s.sid, seq, meta, body, ts);

/** POST a frame (or any bytes) to /htp/v1/call and describe the answer. `cipher` is true for an encrypted reply. */
export async function send(baseUrl, bytes, contentType = MEDIA_TYPE) {
  const res = await fetch(`${baseUrl}/htp/v1/call`, { method: "POST", headers: { "content-type": contentType }, body: bytes });
  const ct = res.headers.get("content-type") || "";
  if (ct.startsWith("application/json")) {
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, cipher: false, text, json, error: json?.error };
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  return { status: res.status, cipher: true, bytes: buf, text: `<${ct} ${buf.length}B>`, error: null };
}

/** POST raw text to /htp/v1/hello. */
export async function hello(baseUrl, body, contentType = "application/json") {
  const res = await fetch(`${baseUrl}/htp/v1/hello`, { method: "POST", headers: { "content-type": contentType }, body });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, text, json, error: json?.error };
}

/** Flip one bit of a frame copy. */
export function flip(bytes, pos) { const f = Uint8Array.from(bytes); f[pos] ^= 0x01; return f; }

/** Register a holder on the stack and return { api, holder }. */
export async function registered(stack, label, { kind = "android" } = {}) {
  const holder = makeHolder(label, { kind });
  const api = new HumidApi({ baseUrl: stack.baseUrl, pinnedKid: stack.gateway.htp.kid });
  await api.register({ pub: holder.pub, commit: holder.commit, device: holder.device, sign: holder.registerSign });
  return { api, holder };
}
