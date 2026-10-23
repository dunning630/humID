// The vault: list, seal, open, save, export, rename, pin, decoy, delete.
// The heavy readers (ID records, payment cards, Wallet passes) are loaded only when a
// document of that kind is sealed or opened, so the first paint carries none of them.
import { batch } from "@preact/signals";
import { toB64, fromB64, toHex, MEDIA_TYPE, EXTENSION } from "@humid/codec";
import { suite, random, splitWrap, splitUnwrap, isSplit } from "@humid/crypto";
import { saveBytes, readFile } from "@humid/io";
import { ApiError } from "@humid/api";
import { sealLiveMessage, b64u } from "@humid/htp";
import { classify, inferKind, kindFromType } from "./categories.js";
import * as S from "./state.js";
import { validStamp, REASONS } from "./place.js";
import { R, MAX_FILE, wipe, sleep, fromB64u, epoch, stale, localChallenge } from "./runtime.js";
import { toast, friendly, cancelled } from "./notify.js";
import { withKeys, withStepUp, showInterrupt, needVault } from "./interrupt.js";
import { keepOffline, markPicking } from "./session.js";
import { openChip } from "./nfc.js";
import { mark } from "./perf.js";
import { updateIdentity } from "./identity.js";

/* global __HUMID_ALLOW_DEMO__ */

/**
 * The split-keys policy hint arrives in plain JSON before any session exists, so a proxy
 * could strip it. Remember the first time a vault says it splits keys, in the identity
 * record, and refuse to seal unsplit from then on.
 */
async function splitKeysRatchet(id) {
  const hint = !!S.server.value?.policy?.splitKeys;
  if (hint && !id.splitKeysSeen) {
    try { await updateIdentity((cur) => { if (cur.splitKeysSeen) return null; cur.splitKeysSeen = true; }); } catch { /* remembered next time */ }
    return true;
  }
  if (!hint && id.splitKeysSeen) throw Object.assign(new Error("Your vault didn't offer split keys this time, so nothing was sealed. Try again on a connection you trust."), { code: "split_keys_missing" });
  return hint;
}

export const ID_TYPE = "application/vnd.humid.id+json";
export const CARD_TYPE = "application/vnd.humid.card+json";
export const PASS_TYPE = "application/vnd.apple.pkpass";
const idscan = () => import("@humid/idscan");
const cards = () => import("@humid/cards");
const walletPkg = () => import("@humid/wallet");

async function decodeIndex(raw) {
  try { return classify(await suite().openIndex(R.indexKey, fromB64u(raw))); }
  catch { return classify({ name: "Unreadable item", type: "" }); }
}

export async function refresh() {
  if (!R.indexKey) return;
  const ep = epoch();
  S.loading.value = true;
  try {
    const { items, usage } = S.offline.value ? { items: R.offline?.items || [], usage: R.offline?.usage || null } : await R.api.list();
    keepOffline({ items, usage });
    const decoded = await Promise.all(items.map(async (it) => {
      const meta = await decodeIndex(it.index);
      return { ...it, ...meta, id: it.id, size: meta.size ?? it.size, envelopeSize: it.size };
    }));
    // A decoy session shows only the documents marked for it, and their usage; only
    // their names are kept in memory (for Activity), never the others'.
    if (stale(ep)) return; // locked meanwhile: nothing from this session is shown
    const shown = S.decoy.value ? decoded.filter((i) => i.decoy) : decoded;
    for (const i of shown) R.knownNames.set(i.id, i.name);
    const u = S.decoy.value ? { ...usage, bytes: shown.reduce((n, i) => n + (i.envelopeSize || 0), 0), count: shown.length } : usage;
    batch(() => { S.items.value = shown; S.usage.value = u; });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 401)) toast(friendly(e), "error");
  } finally { S.loading.value = false; }
}

/* ---------------- adding ---------------- */

/** Seal a photo or a file. `tags`: what it's about (core/categories.js), chosen on the review screen. */
export async function addDocument({ file, name, tags = [], place = null }) {
  if (file.size > MAX_FILE) { toast(`${file.name} is over 50 MB. HumID seals files up to 50 MB.`, "warn"); return false; }
  const bytes = await readFile(file);
  const type = file.type || "application/octet-stream";
  return sealAndStore({ bytes, type, name: (name || file.name || "Document").trim().slice(0, 120), kind: kindFromType(type, file.name), tags, place });
}

/** Seal an identity document record (@humid/idscan): one sealed JSON with its photos, and a summary in the encrypted index. */
export async function addIdRecord(record, name, place = null, { tags = ["identity"] } = {}) {
  const { encodeRecord, summary } = await idscan();
  const bytes = encodeRecord(record);
  if (bytes.length > MAX_FILE) { toast("Those photos are too large to seal. Retake them and try again.", "warn"); return false; }
  return sealAndStore({ bytes, type: ID_TYPE, name: (name || "ID").trim().slice(0, 120), kind: "id", tags, extra: { idInfo: summary(record) }, place });
}

/** Seal a payment card record (@humid/cards). The encrypted index carries only network, last four, expiry and nickname. */
export async function addCardRecord(record, name, { tags = ["money"], place = null } = {}) {
  const { encodeCard, summary } = await cards();
  let bytes;
  try { bytes = encodeCard(record); } catch (e) { toast(e.message, "warn"); return false; }
  return sealAndStore({ bytes, type: CARD_TYPE, name: (name || "Card").trim().slice(0, 120), kind: "card", tags, extra: { cardInfo: summary(record) }, place });
}

/** Tap a contactless card (Android NFC, or a USB reader on a computer): number and expiry. No payment is made. */
export async function readCardTap() {
  let t;
  try {
    const { readContactless } = await cards();
    t = await openChip({ prompt: "Hold your card flat against the back of your phone." });
    const r = await readContactless(t);
    await t.end({ message: "Card read." });
    return r;
  } catch (e) {
    await t?.end({ error: "Couldn't read the card." });
    if (e?.code !== "cancelled") toast(e?.message || "Couldn't read the card. Try the camera, or type it.", "warn");
    return null;
  }
}

const CARD_OCR_PX = 1300;

/** Read a card from a photo with the on-device text reader. Best effort: the holder checks what was read. */
export async function readCardPhoto(canvas, { side = "front", pan = null } = {}) {
  try {
    const [{ textReader, grab }, { readCardText, readCardBack }] = await Promise.all([import("./scan.js"), cards()]);
    const ocr = await textReader();
    // A card's print is sharp at 1300 px across (digits 40 px tall); the reader's time grows with the picture's area (2.2.0).
    const small = canvas.width > CARD_OCR_PX ? grab(canvas, null, CARD_OCR_PX) : canvas;
    const text = await ocr.read(small, { front: side === "front" });
    return side === "front" ? readCardText(text) : readCardBack(text, { pan });
  } catch { return null; }
}

/* ---------------- Apple Wallet passes ---------------- */

/** Apple's roots, pinned (@humid/wallet). A development build also trusts test roots a browser check puts in globalThis.__humidExtraPassRoots. */
const passRoots = (APPLE_ROOTS) => ((typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true) && Array.isArray(globalThis.__humidExtraPassRoots)
  ? [...APPLE_ROOTS, ...globalThis.__humidExtraPassRoots.map((d, i) => ({ name: `Test root ${i + 1}`, der: fromB64(d) }))]
  : APPLE_ROOTS);

/** Check a .pkpass: its files, its issuer's signature, Apple's chain. → { ok, result, bytes } | { ok: false, reason } */
export async function checkPass(file) {
  try {
    if (file.size > 20 * 1024 * 1024) return { ok: false, reason: "That pass is too big." };
    const { readPkpass, APPLE_ROOTS, WalletError } = await walletPkg();
    const bytes = await readFile(file);
    try { return { ok: true, result: await readPkpass(bytes, { roots: passRoots(APPLE_ROOTS) }), bytes }; }
    catch (e) { return { ok: false, reason: e instanceof WalletError ? e.message : "That pass can't be read." }; }
  } catch { return { ok: false, reason: "That pass can't be read." }; }
}

/** Seal a checked pass: exactly the bytes that were checked, with its summary in the encrypted index. */
export async function addPass({ checked, name, tags = [], place = null }) {
  const { passIndex } = await walletPkg();
  const { result, bytes } = checked;
  return sealAndStore({ bytes: Uint8Array.from(bytes), type: PASS_TYPE, name: (name || result.pass.description || "Pass").trim().slice(0, 120), kind: "pass", tags, extra: { passInfo: passIndex(result.pass, result.issuer) }, place });
}

/* ---------------- sealing ---------------- */

/** Resolves after the screen has had a frame to draw (or 60 ms, if the page is hidden and none comes). */
const paint = () => new Promise((r) => {
  const t = setTimeout(r, 60);
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(() => { clearTimeout(t); setTimeout(r, 0); });
});

let sealWarm = false;
/**
 * Run the sealing arithmetic once on throwaway data, so the first real seal isn't also the
 * first time this phone's JavaScript engine meets it (ML-KEM, ML-DSA and SHA-3 start slow:
 * their first run costs several times a warm one). Called while a review is on screen. Only
 * random, made-up keys and a few bytes go through it: nothing of the person's, nothing kept,
 * nothing sent (2.2.0).
 */
export function warmSeal() {
  if (sealWarm || !S.identity.value) return;
  sealWarm = true;
  setTimeout(async () => {
    let Suite = null, k = null;
    try {
      Suite = suite(S.identity.value?.suite);
      k = Suite.deriveKeys(random(32));
      const p = await Suite.prepareSeal({ bytes: random(64), name: "warm", type: "application/octet-stream" }, { kemPk: k.kemPk, xPk: k.xPk });
      Suite.finishSeal(p, k, { identityCommit: "warm", interrupt: {} });
    } catch { /* only a warm-up */ }
    finally { if (k) Suite.wipeKeys(k); }
  }, 1200); // after the review has drawn
}

/**
 * Encrypt on this device, one live check signs it, upload. S.sealing shows the stages.
 * place: a location watch (core/place.js) when the person chose to stamp where it was sealed.
 */
async function sealAndStore({ bytes, type, name: finalName, kind, tags = [], extra = {}, place = null }) {
  const id = S.identity.value;
  if (S.offline.value) { toast(friendly({ code: "offline" }), "warn"); return false; }
  S.sealing.value = "seal";
  mark("seal-start");
  let share = null, prepared;
  try {
    // where it's being sealed: the wait for a first fix (three seconds at most) runs beside the
    // encryption below, not before it (2.2.0)
    const fix = place ? place.take(3000) : null;
    let stamp = null;
    // Encrypt first (public keys only), then one live check signs the ciphertext's hash
    // in hardware and releases the key that signs the envelope.
    const Suite = suite(id.suite);
    const size = bytes.length;
    await paint(); // the "Sealing" step is on screen before the arithmetic starts (hashing a photo holds the thread a while)
    let plainHash;
    // Split keys: the document is first encrypted under its own key, which goes to the
    // keyshare service and is forgotten here. The account keys alone then open nothing.
    // Split keys ratchet: once this HumID has seen a vault that splits keys, it never seals
    // unsplit again, whatever an (unauthenticated) policy hint says later.
    const splitKeys = await splitKeysRatchet(id);
    if (splitKeys) {
      plainHash = toHex(Suite.sha3_512(bytes)); // of the document itself; what's encrypted below is its wrapped form
      const w = await splitWrap({ bytes, name: finalName, type });
      wipe(bytes);
      bytes = w.file.bytes; share = w.share;
      prepared = await Suite.prepareSeal(w.file, { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) });
    } else {
      prepared = await Suite.prepareSeal({ bytes, name: finalName, type }, { kemPk: fromB64(id.pub.kemPk), xPk: fromB64(id.pub.xPk) });
      plainHash = prepared.plainHash; // the same SHA3-512 of the same bytes: not computed a second time
    }
    wipe(bytes); bytes = null;
    mark("seal-prepared");
    if (fix) {
      const got = await fix;
      if (got.stamp && validStamp(got.stamp)) stamp = got.stamp;
      else extra = { ...extra, placeNote: REASONS[got.reason] || REASONS.unavailable };
    }
    if (stamp) extra = { ...extra, place: stamp };
    mark("seal-place");
    const { envelope, index } = await withKeys("seal", `Seal ${finalName}`, async ({ keys, rec, live }) => {
      mark("seal-keys");
      const sealed = Suite.finishSeal(prepared, keys, { identityCommit: id.commit, interrupt: { ...rec, ...(live ? { live: b64u(live.sig) } : {}) } });
      const idx = await Suite.sealIndex(R.indexKey, { name: finalName, type, size, kind, ...(tags.length ? { tags } : {}), addedAt: new Date().toISOString(), plainHash, ...(share ? { split: true } : {}), ...extra });
      mark("seal-signed");
      return { envelope: sealed.envelope, index: idx };
    }, { challenge: sealLiveMessage(prepared.ciphertextHash) });
    S.sealing.value = "upload";
    await R.api.upload(envelope, index, share);
    mark("seal-uploaded");
    wipe(share); share = null;
    S.sealing.value = "done";
    await refresh();
    mark("seal-refreshed");
    await sleep(650);
    S.sealing.value = null;
    toast(`${finalName} sealed. Only your face or fingerprint can open it.`);
    return true;
  } catch (e) {
    wipe(bytes, share);
    S.sealing.value = null;
    if (!cancelled(e)) toast(friendly(e), "error");
    return false;
  }
}

/* ---------------- opening ---------------- */

/**
 * Download, verify, decrypt — all under one live check. GET /vault/objects/:id IS the
 * step-up request: the server releases the envelope (and, for a split document, its key)
 * only on the proof the liveness key signs during the check.
 */
async function fetchPlain(item, purpose, label) {
  return withStepUp("download", [item.id], purpose, label, async ({ keys, proof, Suite }) => {
    showInterrupt({ progress: 0.65, message: "Fetching the sealed copy from your vault…" });
    const { envelope, share } = await R.api.downloadWithShare(item.id, proof);
    showInterrupt({ progress: 0.85, message: share ? "Checking, then opening with both keys…" : "Checking it's untouched, then opening…" });
    // Only this account seals documents into its vault, so anything signed by another key
    // is a forgery from whoever served it (PC-03): refused before it's decrypted or shown.
    const out = await Suite.open(envelope, keys, { signer: keys.dsaPk });
    let result;
    if (!isSplit(out.meta)) { wipe(share); result = out; }
    else { try { result = await splitUnwrap(out.bytes, share); } finally { wipe(out.bytes, share); } }
    // The envelope must be the document this vault entry names, not another one the
    // holder once sealed (a deleted file, an older version): the index entry, sealed
    // under a key only the holder has, records the document's hash (PC-03 follow-up).
    if (item.plainHash && toHex(Suite.sha3_512(result.bytes)) !== item.plainHash) {
      wipe(result.bytes);
      throw new Error("The server sent a different document than the one in your vault. It wasn't opened.");
    }
    return result;
  });
}

export async function openItem(item) {
  const ep = epoch();
  try {
    needVault();
    const { bytes, meta } = await fetchPlain(item, "decrypt", `Open ${item.name}`);
    if (stale(ep)) { wipe(bytes); return; } // locked while the check ran: the document is wiped, not shown
    const type = meta.type || item.type || "application/octet-stream";
    let url = null, text = null, idRecord = null, cardRecord = null, pass = null, passError = null;
    if (type === ID_TYPE) {
      const { decodeRecord, recheckChip, readDg2 } = await idscan();
      try { idRecord = decodeRecord(bytes); } catch { text = new TextDecoder().decode(bytes); }
      // The chip photo shown is re-made from the chip's own DG2 every time, never
      // taken from the stored copy (precert APP-05): a JPEG 2000 photo can't be
      // compared byte for byte after conversion.
      if (idRecord?.raw?.chip?.dg2 && recheckChip(idRecord).ok) {
        try { const { portraitImage } = await import("./scan.js"); idRecord.images = idRecord.images || {}; idRecord.images.portrait = await portraitImage(readDg2(fromB64(idRecord.raw.chip.dg2))); }
        catch { if (idRecord.images) delete idRecord.images.portrait; }
      }
    } else if (type === CARD_TYPE) {
      const { decodeCard } = await cards();
      try { cardRecord = decodeCard(bytes); } catch { text = "This card record can't be read."; }
      wipe(bytes); // the card lives only in the viewer, masked until revealed
    } else if (type === PASS_TYPE) {
      // checked again on every open: what's shown is what the issuer signed
      const { readPkpass, APPLE_ROOTS, WalletError } = await walletPkg();
      const at = Date.parse(item.passInfo?.checkedAt || "");
      try { pass = await readPkpass(bytes, { roots: passRoots(APPLE_ROOTS), now: Number.isNaN(at) ? new Date() : new Date(Math.min(at, Date.now())) }); }
      catch (e) { passError = e instanceof WalletError ? e.message : "This pass can't be read."; }
    } else if (type.startsWith("text/") || type === "application/json") { text = new TextDecoder().decode(bytes); wipe(bytes); }
    else url = URL.createObjectURL(new Blob([bytes], { type }));
    batch(() => { S.viewer.value = { name: meta.name, type, url, text, idRecord, cardRecord, pass, passError, bytes: url || idRecord || pass || passError ? bytes : null, item, openedAt: Date.now() }; });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export function closeViewer() {
  const v = S.viewer.value;
  if (!v) return;
  if (v.url) URL.revokeObjectURL(v.url);
  wipe(v.bytes);
  S.viewer.value = null;
}

/**
 * Save an unsealed copy to this device. Always its own live check, even from an open
 * viewer, so "every open, save and delete needs a fresh check" is true, and the save is
 * in Activity like any other release.
 */
export async function saveCopy(item) {
  try {
    needVault();
    const { bytes, meta } = await fetchPlain(item, "export", `Save a copy of ${item.name}`);
    markPicking();
    try { await saveBytes(bytes, meta.name, meta.type); } finally { wipe(bytes); }
    toast("Saved a copy to this device. It isn't sealed: keep it safe.");
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

export async function exportSealed(item) {
  try {
    needVault();
    const env = await withStepUp("download", [item.id], "export", `Export sealed ${item.name}`, async ({ proof }) => R.api.download(item.id, proof));
    markPicking();
    await saveBytes(env, `${item.name}${EXTENSION}`, MEDIA_TYPE);
    toast("Exported. The copy stays sealed: only your HumID can open it.");
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); }
}

/* ---------------- changing the index entry ---------------- */

/** An item's index entry, to re-seal with a change. */
const indexEntry = (item, patch = {}) => ({
  name: item.name, type: item.type, size: item.size, kind: inferKind(item), addedAt: item.addedAt, plainHash: item.plainHash,
  ...(item.tags?.length ? { tags: item.tags } : {}),
  ...(item.decoy ? { decoy: true } : {}), ...(item.pinned ? { pinned: true } : {}), ...(item.idInfo ? { idInfo: item.idInfo } : {}),
  ...(item.split ? { split: true } : {}), ...(item.place ? { place: item.place } : {}),
  ...(item.cardInfo ? { cardInfo: item.cardInfo } : {}), ...(item.passInfo ? { passInfo: item.passInfo } : {}), ...patch,
});

/** Pin an item to the top. Sealed in the item's encrypted index entry, so it shows on every device. */
export async function setPinned(item, on) {
  const show = () => { S.items.value = S.items.value.map((i) => (i.id === item.id ? { ...i, pinned: on || undefined } : i)); };
  if (S.decoy.value) { show(); return; }
  try {
    needVault();
    const entry = indexEntry(item);
    if (on) entry.pinned = true; else delete entry.pinned;
    await R.api.rename(item.id, await suite().sealIndex(R.indexKey, entry));
    show();
    toast(on ? `${item.name} is pinned to the top.` : `${item.name} is unpinned.`);
  } catch (e) { toast(friendly(e), "error"); }
}

/** Show (or stop showing) a document in the decoy view. Stored inside the encrypted index. */
export async function setDecoy(item, on) { return setDecoys([{ item, on }]); }

/**
 * Which items a forced unlock shows. One live check covers every change (local, like
 * reading the duress setting): what a coercer will see is a safety setting, never changed
 * on the session alone.
 */
export async function setDecoys(changes) {
  const todo = changes.filter(({ item, on }) => !!item.decoy !== !!on);
  if (!todo.length) return true;
  try {
    needVault();
    const label = todo.length === 1 ? (todo[0].on ? `Show ${todo[0].item.name} in the decoy view` : `Hide ${todo[0].item.name} from the decoy view`) : `Change ${todo.length} decoy documents`;
    if (S.decoy.value) {
      // A decoy session looks the same (the same live check, the same words) and changes nothing.
      await withKeys("decoy", label, async () => null, { challenge: localChallenge("decoy") });
      const on = new Map(todo.map(({ item, on: v }) => [item.id, v]));
      S.items.value = S.items.value.map((i) => (on.has(i.id) ? { ...i, decoy: on.get(i.id) || undefined } : i));
      toast(decoyWords(todo));
      return true;
    }
    const blobs = await withKeys("decoy", label, async () => {
      const out = [];
      for (const { item, on } of todo) { const entry = indexEntry(item); if (on) entry.decoy = true; else delete entry.decoy; out.push([item.id, await suite().sealIndex(R.indexKey, entry)]); }
      return out;
    }, { challenge: localChallenge("decoy") });
    for (const [id, blob] of blobs) await R.api.rename(id, blob);
    await refresh();
    toast(decoyWords(todo));
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}
const decoyWords = (todo) => (todo.length === 1 ? (todo[0].on ? `${todo[0].item.name} will show in the decoy view.` : `${todo[0].item.name} is hidden from the decoy view.`) : "Decoy documents updated.");

/** Rename an item and set its tags (an array of tag ids; an empty one clears them). */
export async function renameItem(item, name, tags = item.tags || []) {
  try {
    needVault();
    const entry = indexEntry(item, { name: name.trim().slice(0, 120) || item.name });
    if (tags.length) entry.tags = tags; else delete entry.tags;
    await R.api.rename(item.id, await suite().sealIndex(R.indexKey, entry));
    await refresh();
    toast("Updated.");
    return true;
  } catch (e) { toast(friendly(e), "error"); return false; }
}

export async function deleteItem(item) {
  try {
    await withStepUp("remove", [item.id], "delete", `Delete ${item.name}`, async ({ proof }) => R.api.remove(item.id, proof));
    await refresh();
    toast(`${item.name} deleted from your vault.`);
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/** The item with this id, as the list shows it now (after a rename or refresh). */
export const itemById = (id) => S.items.value.find((i) => i.id === id) || null;
export { toB64 };
