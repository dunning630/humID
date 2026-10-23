// Recovery, from the owner's side: the recovery card, witnesses, the ID chip anchor,
// security keys (4.0, the flows themselves are in seckey.js);
// being someone's witness; alerts about recoveries of this account.
import { fromB64, toHex } from "@humid/codec";
import { suite } from "@humid/crypto";
import { readFile } from "@humid/io";
import {
  newCard, cardTag, sealCardPart, split, thresholdFor, encodeShare, decodeShare, MIN_CONTACTS, MAX_CONTACTS,
  quorumParts, anchorPartKey, sealAnchorPart,
} from "@humid/recovery";
import * as S from "./state.js";
import { SERVER_URL } from "./config.js";
import { R, KEY_TYPE, wipe } from "./runtime.js";
import { toast, friendly, cancelled, quietly } from "./notify.js";
import { withKeys, withStepUp, showInterrupt, needVault } from "./interrupt.js";
import { keepOffline } from "./session.js";
import { loadRecoveryMode, isHolderOnly, currentEpoch, mayMakePieces } from "./recmode.js";

/* global __HUMID_ALLOW_DEMO__ */

export async function loadRecovery() {
  if (S.offline.value) { S.recovery.value = R.offline?.recovery || null; S.recoveryMode.value = R.offline?.recoveryMode || S.recoveryMode.value; return; }
  const [card, contacts, anchor, settings, keyList] = await Promise.all([
    quietly(R.api.card()), quietly(R.api.contacts()), quietly(R.api.anchor()), quietly(R.api.settings()),
    R.api.keys().catch(() => null), // an older server has no security keys: shown as unavailable
    loadRecoveryMode(),
  ]);
  if (!card || !contacts) return;
  const names = [];
  for (const g of contacts.guardians || []) {
    let name = "A witness";
    try { if (g.label && R.indexKey) name = (await suite().openIndex(R.indexKey, g.label)).name; } catch {}
    names.push(name);
  }
  const keys = [];
  for (const k of keyList?.keys || []) {
    let name = "Security key";
    try { if (k.label && R.indexKey) name = (await suite().openIndex(R.indexKey, k.label)).name || name; } catch {}
    keys.push({ id: k.id, name, createdAt: k.createdAt });
  }
  // Two-proof recovery is ready when at least two different proofs are set up.
  const proofs = {
    witness: contacts.n > 0 && contacts.scheme === "quorum",
    anchor: !!anchor?.exists,
    card: card.exists && card.scheme === "quorum",
    key: keys.length > 0,
  };
  const legacy = (card.exists && card.scheme !== "quorum") || (contacts.n > 0 && contacts.scheme !== "quorum");
  S.recovery.value = {
    card, anchor: anchor || { available: false, exists: false }, settings: settings || {},
    contacts: { n: contacts.n, threshold: contacts.threshold, createdAt: contacts.createdAt, names, scheme: contacts.scheme },
    keys: { available: !!keyList, max: keyList?.max || 4, list: keys },
    proofs, ready: Object.values(proofs).filter(Boolean).length >= 2, legacy,
    holderOnly: isHolderOnly(),
  };
  keepOffline({ recovery: S.recovery.value, recoveryMode: S.recoveryMode.value });
  if (!S.decoy.value) {
    R.api.protectingAlerts().then((a) => { S.protecting.value = a; }).catch(() => {});
    R.api.station().then((st) => { S.station.value = st; }).catch(() => {});
  }
}

/**
 * The part of two-proof recovery this flow needs, made from the seed inside a live check, for
 * the account's current set of pieces (its epoch, from the signed recovery-mode statement).
 */
export const partOf = (seed, kind) => {
  // Never on the server's say-so (V74-01): only in a hardened mode this device has checked
  // against its account key and its own pin. Every flow that makes a piece comes through here.
  if (!mayMakePieces()) throw Object.assign(new Error("This HumID is set to open only on your own devices, or your vault server's record of that doesn't check out. No recovery piece was made."), { code: "holder_only" });
  const parts = quorumParts(seed, currentEpoch());
  const p = parts[kind];
  for (const k of Object.keys(parts)) if (k !== kind) wipe(parts[k].y);
  return p;
};

/* ---------------- the recovery card ---------------- */

/** Make (or replace) the recovery card. Returns the code to show ONCE; the caller forgets it. */
export async function makeNewCard() {
  const accountId = S.identity.value.server.id;
  let card;
  try {
    await withStepUp("setCard", [], "card", "Make a recovery card", async ({ seed, proof }) => {
      card = newCard();
      const part = partOf(seed, "card");
      try { await R.api.setCard({ tag: cardTag(card.secret), blob: await sealCardPart(card.secret, part, accountId), epoch: part.epoch }, proof); }
      finally { wipe(part.y); }
    });
    S.cardCode.value = card.code;
    loadRecovery();
    return card.code;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
  finally { wipe(card?.secret); }
}

export async function removeCard() {
  try {
    await withStepUp("removeCard", [], "card", "Remove your recovery card", async ({ proof }) => R.api.removeCard(proof));
    toast("Recovery card removed. It no longer counts on your vault server, but it still fits your other pieces: destroy it, or make new recovery pieces so it fits nothing new.");
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/* ---------------- witnesses ---------------- */

/** Look up a witness code someone showed you. The API checks it against their keys. */
export async function findContact(code) {
  try { needVault(); return await R.api.getOffer(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/**
 * Split the account seed among 2–5 witnesses; a majority rebuilds it.
 * contacts: [{ code, name, offer }] where offer came from findContact.
 * ownerName: how the witnesses know you, shown to them when you ask for help.
 */
export async function saveContacts(contacts, ownerName) {
  const id = S.identity.value;
  const n = contacts.length;
  if (n < MIN_CONTACTS || n > MAX_CONTACTS) { toast(`Choose ${MIN_CONTACTS} to ${MAX_CONTACTS} witnesses.`, "warn"); return false; }
  const t = thresholdFor(n);
  try {
    await withStepUp("setContacts", [], "contacts", "Save your witnesses", async ({ keys, seed, rec, proof, Suite }) => {
      showInterrupt({ progress: 0.6, message: `Splitting your witness part into ${n} pieces…` });
      const part = partOf(seed, "witness");
      const shares = split(part.y, n, t);
      wipe(part.y);
      const guardians = [];
      for (let i = 0; i < n; i++) {
        const c = contacts[i];
        const piece = encodeShare({ owner: id.server.id, label: ownerName, ...shares[i], t, n, epoch: part.epoch });
        const { envelope } = await Suite.seal({ bytes: piece, name: "HumID recovery piece", type: KEY_TYPE }, keys, { kemPk: c.offer.kemPk, xPk: c.offer.xPk }, { identityCommit: id.commit, interrupt: rec });
        guardians.push({ contact: c.offer.account, offer: c.code, envelope, label: await Suite.sealIndex(R.indexKey, { name: c.name.trim().slice(0, 40) || "Contact" }) });
        wipe(piece, shares[i].y);
      }
      await R.api.setContacts({ threshold: t, guardians, scheme: "quorum", epoch: part.epoch }, proof);
    });
    toast(`Saved. Any ${t} of your ${n} witnesses count as one proof.`);
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function removeContacts() {
  try {
    await withStepUp("removeContacts", [], "contacts", "Remove your witnesses", async ({ proof }) => R.api.removeContacts(proof));
    toast("Witnesses removed. Their pieces no longer count on your vault server, but still fit your other pieces: make new recovery pieces so they fit nothing new.");
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/* ---------------- being someone's witness ---------------- */

/** A code someone types to make you their witness. Public keys only. → { code, expiresAt } */
export async function offerToBeContact() {
  const p = S.identity.value.pub;
  try {
    needVault();
    return await R.api.offerContact({ kemPk: fromB64(p.kemPk), xPk: fromB64(p.xPk), dsaPk: fromB64(p.dsaPk) });
  } catch (e) { toast(friendly(e), "error"); return null; }
}

export async function findHelpRequest(code) {
  try { needVault(); return await R.api.getHelp(code); }
  catch (e) { toast(friendly(e), "error"); return null; }
}

/** Live check 1: open the pieces you hold to see whose they are. Only names leave the check. */
export async function whoDoIProtect() {
  try {
    needVault();
    return await withKeys("help", "See who you protect", async ({ keys, Suite }) => {
      const held = await R.api.protecting();
      const people = [];
      for (const h of held) {
        try {
          const { bytes } = await Suite.open(h.envelope, keys);
          const s = decodeShare(bytes);
          people.push({ owner: s.owner, label: s.label || "Someone", since: h.createdAt });
          wipe(bytes, s.y);
        } catch { /* skip a piece that doesn't open */ }
      }
      return people;
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/** Live check 2: release your piece for `owner`, re-sealed to the device that asked. */
export async function releasePiece(req, person) {
  const id = S.identity.value;
  try {
    return await withStepUp("help", [req.code], "help", `Help ${person.label} recover`, async ({ keys, rec, proof, Suite }) => {
      const held = (await R.api.protecting()).find((h) => h.owner === person.owner);
      if (!held) throw new Error("You no longer hold a piece for this person.");
      const { bytes } = await Suite.open(held.envelope, keys);
      const { envelope } = await Suite.seal({ bytes, name: "HumID recovery piece", type: KEY_TYPE }, keys, { kemPk: req.kemPk, xPk: req.xPk }, { identityCommit: id.commit, interrupt: rec });
      wipe(bytes);
      return R.api.help(req.code, { owner: person.owner, envelope }, proof);
    });
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return null; }
}

/* ---------------- alerts: recoveries of this account ---------------- */

export async function loadAlerts() {
  if (S.decoy.value) { S.alerts.value = []; return; } // a decoy session sees a calm account
  if (S.offline.value) return; // recoveries in progress are a live question: shown once back online
  const a = await R.api.alerts().catch(() => null);
  if (a) S.alerts.value = a;
  R.api.protectingAlerts().then((p) => { S.protecting.value = p; }).catch(() => {});
}

export async function cancelRecovery(alert) {
  try {
    await withStepUp("cancelAlert", [alert.ref], "cancel", "Cancel this recovery", async ({ proof }) => R.api.cancelAlert(alert.ref, proof));
    toast("Cancelled. That device gets nothing.");
    loadAlerts();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

/* ---------------- identity anchor: your passport or ID chip ---------------- */

const fromAny = (s) => {
  const t = String(s || "").trim();
  if (/^[0-9a-f]+$/i.test(t) && t.length % 2 === 0) return Uint8Array.from(t.match(/../g), (h) => parseInt(h, 16));
  return fromB64(t.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((t.length + 3) % 4));
};

/** Chip data from files: one JSON file { dg1, sod, dg15? } (base64 or hex), or the raw files a chip reader exports. */
export async function readChipFiles(files) {
  const list = [...(files || [])];
  if (!list.length) return null;
  try {
    if (list.length === 1 && /\.json$/i.test(list[0].name)) {
      const j = JSON.parse(new TextDecoder().decode(await readFile(list[0])));
      const get = (k) => j[k] ?? j[k.toUpperCase()] ?? j[`EF_${k.toUpperCase()}`];
      const chip = { dg1: fromAny(get("dg1")), sod: fromAny(get("sod")), ...(get("dg15") ? { dg15: fromAny(get("dg15")) } : {}) };
      if (!chip.dg1.length || !chip.sod.length) throw new Error();
      return chip;
    }
    const chip = {};
    for (const f of list) {
      const n = f.name.toUpperCase();
      const key = /DG15/.test(n) ? "dg15" : /DG1(?!\d)/.test(n) ? "dg1" : /SOD/.test(n) ? "sod" : null;
      if (key) chip[key] = await readFile(f);
    }
    if (!chip.dg1 || !chip.sod) throw new Error();
    return chip;
  } catch {
    toast("Those files aren't ID chip data. Choose the DG1 and SOD files (and DG15 if there is one), or one .json with them.", "warn");
    return null;
  }
}

/** Development builds only: a demo passport from the local dev server, with a chip that answers challenges. */
export async function demoPassport(name = "Demo Person") {
  if (!(typeof __HUMID_ALLOW_DEMO__ !== "undefined" && __HUMID_ALLOW_DEMO__ === true)) return null;
  try {
    const res = await fetch(`${SERVER_URL}/dev/passport?name=${encodeURIComponent(name)}`, { method: "POST" });
    if (!res.ok) throw new Error("This server has no demo passports.");
    const j = await res.json();
    return {
      dg1: fromAny(j.dg1), sod: fromAny(j.sod), dg15: j.dg15 ? fromAny(j.dg15) : undefined, demo: true, name,
      answer: async (nonce) => {
        const r = await fetch(`${SERVER_URL}/dev/passport/answer?name=${encodeURIComponent(name)}&nonce=${toHex(nonce)}`, { method: "POST" });
        return r.ok ? fromAny((await r.json()).signature) : null;
      },
    };
  } catch (e) { toast(friendly(e), "error"); return null; }
}

/**
 * Link your passport or ID to your HumID. The chip must be read live: `read(nonce)` reads it
 * and has it answer the server's fresh challenge, so copied chip files can't link someone's
 * identity (CREDS-02). The anchor part is sealed here, under a key from that chip's own
 * authentication key (DG15), before it leaves the phone. That ties it to this one chip
 * (CREDS-01). It does NOT keep it from the vault server, which sees DG15 when the chip is
 * checked: the anchor screen says so (V74-03). A chip with no authentication key can't hold it.
 */
export async function setAnchor(read) {
  try {
    const nonce = await R.api.anchorChallenge();
    const chip = await read(nonce);
    if (!chip) return false;
    if (!chip.dg15 || !chip.aaSignature) throw new Error("This ID's chip can't prove it's present, so it can't be one of your proofs. Use witnesses, a recovery card or a security key.");
    const r = await withStepUp("setAnchor", [], "anchor", "Link your HumID to your ID chip", async ({ seed, proof }) => {
      showInterrupt({ progress: 0.6, message: "Sealing your recovery piece to your ID chip…" });
      const part = partOf(seed, "anchor");
      const key = anchorPartKey(chip.dg15);
      try { return await R.api.setAnchor({ chip, sealedPart: await sealAnchorPart(key, part, S.identity.value.server.id), signature: chip.aaSignature, epoch: part.epoch }, proof); }
      finally { wipe(part.y, key); }
    });
    toast(`Linked to your ${r.document}'s chip${r.country ? ` (${r.country})` : ""}.`);
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}

export async function removeAnchor() {
  try {
    await withStepUp("removeAnchor", [], "anchor", "Unlink your ID chip", async ({ proof }) => R.api.removeAnchor(proof));
    toast("ID chip unlinked.");
    loadRecovery();
    return true;
  } catch (e) { if (!cancelled(e)) toast(friendly(e), "error"); return false; }
}
