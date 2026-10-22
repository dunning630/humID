// CTAP 2 over NFC (CTAP 2.1 §11.3), on any ISO 7816-4 APDU transport: the app's
// NFC plugin on a phone, PC/SC on a computer, a simulator in tests. A transport is
// { transceive(apdu: Uint8Array) → Promise<Uint8Array> } returning data ‖ SW1 SW2.
import { FidoError } from "./errors.js";

export const FIDO_AID = Uint8Array.of(0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01);

const MAX_SHORT = 255;
const MAX_RESPONSE = 64 * 1024;   // nothing HumID asks a key for comes near this
const MAX_CHAINED = 300;          // 61xx rounds
const BUSY_POLL_MS = 100;         // NFCCTAP_GETRESPONSE interval while the key works
const BUSY_LIMIT_MS = 30_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const lost = (e) => new FidoError("lost", e?.message || "Lost contact with the key.", { cause: e });

async function send(t, apdu) {
  let r;
  try { r = await t.transceive(apdu); } catch (e) { throw lost(e); }
  if (!(r instanceof Uint8Array) || r.length < 2) throw new FidoError("bad_response", "The key gave an answer HumID can't read.");
  return { data: r.subarray(0, r.length - 2), sw: (r[r.length - 2] << 8) | r[r.length - 1] };
}

/**
 * One command, with ISO command chaining for data over 255 bytes (CLA bit 0x10 on every
 * block but the last) and 61xx response chaining (GET RESPONSE). Returns { data, sw }.
 */
export async function command(t, cla, ins, p1, p2, data = new Uint8Array(0)) {
  let off = 0;
  for (;;) {
    const chunk = data.subarray(off, off + MAX_SHORT);
    const last = off + chunk.length >= data.length;
    const apdu = chunk.length
      ? concat([Uint8Array.of(last ? cla : cla | 0x10, ins, p1, p2, chunk.length), chunk, last ? Uint8Array.of(0x00) : new Uint8Array(0)])
      : Uint8Array.of(cla, ins, p1, p2, 0x00);
    const r = await send(t, apdu);
    if (last) return collect(t, r);
    if (r.sw !== 0x9000) throw swError(r.sw);
    off += chunk.length;
  }
}

async function collect(t, first) {
  let { data, sw } = first;
  const parts = [data];
  let total = data.length;
  for (let i = 0; (sw >> 8) === 0x61; i++) {
    if (i >= MAX_CHAINED) throw new FidoError("bad_response", "The key's answer never ended.");
    const r = await send(t, Uint8Array.of(0x00, 0xc0, 0x00, 0x00, sw & 0xff));
    parts.push(r.data); total += r.data.length; sw = r.sw;
    if (total > MAX_RESPONSE) throw new FidoError("bad_response", "The key's answer is too long.");
  }
  return { data: parts.length === 1 ? data : concat(parts), sw };
}

function swError(sw) {
  if (sw === 0x6a82) return new FidoError("not_fido", "That isn't a FIDO2 security key.");
  if (sw === 0x6d00 || sw === 0x6e00) return new FidoError("not_fido2", "This key doesn't speak FIDO2 over NFC.");
  if (sw === 0x6700) return new FidoError("bad_length", "The key refused the message's length.");
  if (sw === 0x6985 || sw === 0x6986) return new FidoError("not_allowed", "The key refused that command.");
  return new FidoError("sw", `The key answered ${sw.toString(16).padStart(4, "0")}.`);
}

/** SELECT the FIDO applet. Returns the version string ("FIDO_2_0" or "U2F_V2"). */
export async function selectFido(t) {
  const r = await command(t, 0x00, 0xa4, 0x04, 0x00, FIDO_AID);
  if (r.sw !== 0x9000) throw swError(r.sw);
  return new TextDecoder().decode(r.data);
}

/**
 * One CTAP2 request: NFCCTAP_MSG with P1 = 0x80 (the key may answer 9100 while it works;
 * then NFCCTAP_GETRESPONSE until it's done). Returns the CTAP response: status ‖ CBOR.
 */
export async function ctapMessage(t, cmd, cborBytes = new Uint8Array(0)) {
  let r = await command(t, 0x80, 0x10, 0x80, 0x00, concat([Uint8Array.of(cmd), cborBytes]));
  const started = Date.now();
  while (r.sw === 0x9100) {
    if (Date.now() - started > BUSY_LIMIT_MS) throw new FidoError("timeout", "The key took too long to answer.");
    await sleep(BUSY_POLL_MS);
    r = await command(t, 0x80, 0x11, 0x00, 0x00);
  }
  if (r.sw !== 0x9000) throw swError(r.sw);
  if (!r.data.length) throw new FidoError("bad_response", "The key sent an empty answer.");
  return r.data;
}
