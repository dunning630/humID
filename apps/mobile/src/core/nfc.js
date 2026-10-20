// The chip reader transport in the app: tauri-plugin-humid-nfc (humid-nfc@1)
// moves APDUs; @humid/emrtd does ICAO 9303. iPhone and Android use the
// phone's NFC; Windows and Mac use a USB contactless reader (PC/SC).
import { fromB64, toB64, toHex } from "@humid/codec";
import { SERVER_URL } from "./config.js";

/* global __HUMID_ALLOW_DEMO__ */
// The development-build flag is tested inline (see core/config.js DEMO_BUILD): release builds fold
// it to false and the simulated chip below, with its /dev/chip endpoints, is dropped.

const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";
const invoke = (cmd, args) => globalThis.__TAURI_INTERNALS__.invoke(`plugin:humid-nfc|${cmd}`, args);
const msg = (e) => (typeof e === "string" ? e : e?.message || String(e));

// Development builds in a browser: a simulated chip on the local dev server, for the
// demo passport holder named here (Security → ID chip, or Prove it's me).
let demoHolder = "Demo Person";
export const setDemoHolder = (name) => { demoHolder = name || "Demo Person"; };
export const demoChipHint = async (name) => ((typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) ? (await fetch(`${SERVER_URL}/dev/chip/hint?name=${encodeURIComponent(name)}`, { method: "POST" })).json() : null);

/** { available, kind: "phone" | "reader" | "demo" | "none", reason? } */
export async function probeNfc() {
  if (!inTauri() && (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) return { available: true, kind: "demo" };
  if (!inTauri()) return { available: false, kind: "none", reason: "Reading ID chips needs the HumID app on your phone, or on Windows or a Mac with a USB card reader." };
  try { return await invoke("probe"); }
  catch (e) { return { available: false, kind: "none", reason: msg(e) }; }
}

/**
 * Wait for a document, then return a transport for @humid/emrtd:
 * { transceive(bytes), message(text), end({ message?, error? }) }.
 */
export async function openChip({ prompt, timeoutMs = 60_000 } = {}) {
  if (!inTauri() && (typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) {
    const s = await (await fetch(`${SERVER_URL}/dev/chip/begin?name=${encodeURIComponent(demoHolder)}`, { method: "POST" })).json();
    return {
      kind: "demo",
      transceive: async (apdu) => {
        const r = await (await fetch(`${SERVER_URL}/dev/chip/transceive?session=${s.session}&apdu=${toHex(apdu)}`, { method: "POST" })).json();
        return Uint8Array.from(r.response.match(/../g), (h) => parseInt(h, 16));
      },
      message: async () => {},
      end: async () => {},
    };
  }
  let s;
  try { s = await invoke("begin", { prompt, timeoutMs }); }
  catch (e) { const m = msg(e); throw Object.assign(new Error(/cancel/i.test(m) ? "Chip reading cancelled." : m), { code: /cancel/i.test(m) ? "cancelled" : "nfc" }); }
  return {
    kind: s.kind,
    async transceive(apdu) {
      try { return fromB64((await invoke("transceive", { session: s.session, apdu: toB64(apdu) })).response); }
      catch (e) { throw Object.assign(new Error(msg(e)), { code: "lost" }); }
    },
    message: (text) => invoke("message", { session: s.session, message: text }).catch(() => {}),
    end: ({ message, error } = {}) => invoke("end", { session: s.session, message, error }).catch(() => {}),
  };
}
