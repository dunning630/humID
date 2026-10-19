// Reading an ID chip (NFC on phones, a USB reader on desktops). The chip reader
// (@humid/emrtd and its elliptic-curve code) loads only when a chip is read.
import { toB64 } from "@humid/codec";
import * as S from "./state.js";
import { probeNfc, openChip } from "./nfc.js";
import { sleep } from "./runtime.js";
import { toast, friendly } from "./notify.js";

const CHIP_PROMPT = {
  phone: "Hold the top of your phone flat against the photo page of your passport, or against your ID card.",
  reader: "Place the passport's photo page, or the ID card, flat on the card reader.",
};

/**
 * Read a passport or ID card chip. access: { number, birth, expiry } (YYMMDD) or { can }.
 * nonce: a server challenge for the chip to sign (live proof). The access details live only
 * in this call; nothing read is stored on the device.
 * Returns { dg1, sod, dg15?, aaSignature?, access } or null if cancelled or failed (shown to the person).
 */
export async function readChip(access, { nonce, purpose = "anchor", photo = false } = {}) {
  const n = S.nfc.value || await probeNfc();
  S.nfc.value = n;
  if (!n.available) { toast(n.reason || "This device can't read ID chips.", "warn"); return null; }
  const show = (patch) => { S.chipRead.value = { ...(S.chipRead.value || {}), ...patch }; };
  show({ stage: "waiting", fraction: 0, message: CHIP_PROMPT[n.kind] || CHIP_PROMPT.phone, error: null, kind: n.kind, purpose });
  let chip = null;
  try {
    const { readDocument } = await import("@humid/emrtd");
    chip = await openChip({ prompt: CHIP_PROMPT[n.kind] });
    show({ stage: "reading", fraction: 0.05, message: "Keep holding still…" });
    let said = "";
    const r = await readDocument(chip, {
      access, nonce, photo,
      onProgress: ({ fraction, message }) => { show({ stage: "reading", fraction, message }); if (message !== said) { said = message; chip.message(message); } },
    });
    await chip.end({ message: "Done. You can move your document away." });
    show({ stage: "done", fraction: 1, message: "Read. You can move your document away." });
    await sleep(700);
    S.chipRead.value = null;
    return r;
  } catch (e) {
    const cancelledRead = e?.code === "cancelled";
    const message = cancelledRead ? "Cancelled." : friendly(e);
    await chip?.end({ error: message });
    if (cancelledRead) { S.chipRead.value = null; return null; }
    show({ stage: "error", message, error: e?.code || "error" });
    return null;
  }
}

export const dismissChipRead = () => { S.chipRead.value = null; };

/** Is there a chip reader here (phone NFC, or a USB reader on a desktop)? Cached in S.nfc. */
export async function chipReader({ fresh = false } = {}) {
  if (!S.nfc.value || fresh) S.nfc.value = await probeNfc();
  return S.nfc.value;
}

/**
 * Read a passport or ID card chip for the holder's own vault copy: the MRZ data, the
 * photo, and the signed hashes, checked against each other. Fills the record in place.
 * Fails closed: chip data is used only when the files match the chip's own hash list.
 * Returns true if read and integrity-checked, "unverified" if read but not verifiable
 * (record untouched except a chipFailed note), false if not read.
 */
export async function readChipInto(record, access, { portrait } = {}) {
  const r = await readChip(access, { purpose: "vault", photo: true });
  if (!r) return false;
  const { readDg1, readDg2, safeCheckIntegrity, chipIntegrityOk, applyChip, setImage } = await import("@humid/idscan");
  const b64 = (b) => toB64(b);
  let mrz = null;
  try { mrz = readDg1(r.dg1).mrz; } catch { /* shown as unread below */ }
  const integrity = safeCheckIntegrity(r.sod, { 1: r.dg1, ...(r.dg2 ? { 2: r.dg2 } : {}), ...(r.dg15 ? { 15: r.dg15 } : {}) });
  applyChip(record, r, { mrz, integrity, b64 });
  if (!chipIntegrityOk(integrity)) return "unverified";
  // A photo is decoded only from a chip whose files match its own signed list.
  if (r.dg2 && portrait) {
    try { setImage(record, "portrait", await portrait(readDg2(r.dg2))); }
    catch { toast("Read the chip, but its photo is in a format HumID can't show yet. It's kept with the record.", "warn"); }
  }
  return true;
}
