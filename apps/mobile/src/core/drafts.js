// What survives a lock: the form the person was in the middle of.
//
// Every background locks the app (keys wiped, session ended). Until 3.0 that also threw
// away a half-typed form — three witness codes copied from a group chat, a card form, an
// ID photographed on both sides — and with the clipboard deliberately blocked, people hit
// it daily. Now the top flow's draft is kept in memory across the lock and offered back
// after the next unlock: "Pick up where you left off?"
//
// Limits, chosen on purpose:
//   - typed text for 10 minutes; a captured page (an ID side, a card photo) for 2 minutes,
//     then it's wiped from the draft while the text stays;
//   - in memory only, never on disk; gone when the app is closed, erased or reset;
//   - never kept from a decoy session, and never restored into one;
//   - a draft is restored only after a live check (it rides inside the unlocked session).
//
// A new recovery card is a draft too (APP-02), until its holder has typed part of it back: it
// is the only copy, and the server already stopped accepting the old card.
import { signal } from "@preact/signals";
import * as S from "./state.js";
import { wipe } from "./runtime.js";

const TEXT_MS = 10 * 60_000;
const IMAGE_MS = 2 * 60_000;
/** A new recovery card not yet checked (core/recovery.js): shown again after a real unlock. */
export const CARD_DRAFT = "recoveryCard";

/** The flow in progress: { kind, state, at } while unlocked; null otherwise. Screens write it as they go. */
export const current = signal(null);
/** A draft kept across the last lock, offered once after unlock: { kind, state, at, images } or null. */
export const kept = signal(null);
let imageTimer = null;

/**
 * Screens call this as their state changes. `images` lists the keys in `state` that hold
 * captured pages. An empty state clears only a draft of the same kind, so a sheet that opens
 * empty never throws away another flow's draft; and nothing replaces a new recovery card's
 * draft until that card is checked or given up.
 */
export function setDraft(kind, state, { images = [] } = {}) {
  if (state && current.value?.kind === CARD_DRAFT && kind !== CARD_DRAFT) return; // the card until it's checked
  if (state) current.value = { kind, state, at: Date.now(), images };
  else if (current.value?.kind === kind) current.value = null;
}
/**
 * A flow finished or was abandoned: forget its draft. A new recovery card's draft goes only
 * when asked for by kind, so finishing some other flow can't throw away the only copy.
 */
export function clearDraft(kind) {
  const k = current.value?.kind;
  if (kind ? k === kind : k !== CARD_DRAFT) current.value = null;
}

/** On lock: move the live draft to `kept`, start the image clock. */
export function keepDraft() {
  const d = current.value;
  current.value = null;
  clearTimeout(imageTimer);
  if (!d || S.decoy.value) { dropDrafts(); return; }
  kept.value = d;
  if (d.images.length) imageTimer = setTimeout(() => { kept.value = kept.value && stripImages(kept.value); }, IMAGE_MS);
}

function stripImages(d) {
  const state = { ...d.state };
  for (const k of d.images) { const v = state[k]; if (v?.bytes) wipe(v.bytes); delete state[k]; }
  return { ...d, state, images: [] };
}

/** After unlock: the draft to offer, if it's still fresh and this isn't a decoy session. */
export function takeDraft() {
  const d = kept.value;
  kept.value = null;
  clearTimeout(imageTimer);
  if (!d || S.decoy.value || Date.now() - d.at > TEXT_MS) { if (d) dropOne(d); return null; }
  return Date.now() - d.at > IMAGE_MS ? stripImages(d) : d;
}

function dropOne(d) { for (const k of d.images || []) { const v = d.state?.[k]; if (v?.bytes) wipe(v.bytes); } }
/** Forget everything: on erase, reset, a removed device, a lost key. */
export function dropDrafts() {
  clearTimeout(imageTimer);
  if (kept.value) dropOne(kept.value);
  if (current.value) dropOne(current.value);
  kept.value = null; current.value = null;
}
