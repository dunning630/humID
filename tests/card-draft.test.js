// A new recovery card until its holder has checked it (APP-02, APP-03): it rides the drafts
// system (apps/mobile/src/core/drafts.js), so it is kept in memory across a lock for ten
// minutes and shown again after a real unlock, but never in a decoy session, never after
// the time limit, and no other flow's draft can push it out.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as S from "../apps/mobile/src/core/state.js";
import { setDraft, clearDraft, keepDraft, takeDraft, dropDrafts, current, kept, CARD_DRAFT } from "../apps/mobile/src/core/drafts.js";
import { forgetNewCard, resumeNewCard } from "../apps/mobile/src/core/recovery.js";

const CODE = "HUMID-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";
const realNow = Date.now;
let now = 1_000_000;
beforeEach(() => { now = 1_000_000; Date.now = () => now; dropDrafts(); S.resetSession(); });
afterEach(() => { Date.now = realNow; });

/** What makeNewCard leaves behind once the server took the card. */
const made = () => { S.cardCode.value = CODE; setDraft(CARD_DRAFT, { code: CODE }); };

test("a new card survives a lock and comes back after a real unlock", () => {
  made();
  keepDraft(); S.resetSession(); // what lock() does
  assert.equal(S.cardCode.value, null, "the lock forgot the card on screen");
  now += 5 * 60_000;
  const d = takeDraft();
  assert.equal(d?.kind, CARD_DRAFT);
  assert.ok(resumeNewCard(d));
  assert.equal(S.cardCode.value, CODE);
  assert.equal(S.tab.value, "you");
});

test("never shown in a decoy session", () => {
  made();
  keepDraft(); S.resetSession();
  S.decoy.value = true;
  const d = takeDraft();
  assert.equal(d, null, "takeDraft refuses a decoy session");
  assert.equal(kept.value, null, "and the card is gone from memory");
  assert.equal(resumeNewCard({ kind: CARD_DRAFT, state: { code: CODE } }), false);
  assert.equal(S.cardCode.value, null);
});

test("a card made in a decoy session is not kept across its lock", () => {
  S.decoy.value = true;
  made();
  keepDraft();
  assert.equal(kept.value, null);
});

test("gone after ten minutes", () => {
  made();
  keepDraft(); S.resetSession();
  now += 10 * 60_000 + 1;
  assert.equal(takeDraft(), null);
});

test("no other flow's draft replaces or clears it until it's checked", () => {
  made();
  setDraft("witnesses", { rows: [1] });
  assert.equal(current.value.kind, CARD_DRAFT, "a sheet writing its draft doesn't push the card out");
  setDraft("seckey", null);
  clearDraft();
  assert.equal(current.value?.kind, CARD_DRAFT, "a sheet opening empty, or another flow finishing, leaves the card");
  forgetNewCard();
  assert.equal(current.value, null);
  assert.equal(S.cardCode.value, null);
  setDraft("witnesses", { rows: [1] });
  assert.equal(current.value.kind, "witnesses", "other drafts work as before once the card is done");
});

test("the wiring: makeNewCard writes the draft, unlock into a decoy drops drafts, the sheet asks before closing", () => {
  const src = (f) => readFileSync(new URL(`../apps/mobile/src/${f}`, import.meta.url), "utf8");
  const rec = src("core/recovery.js");
  const make = rec.slice(rec.indexOf("export async function makeNewCard"), rec.indexOf("export function forgetNewCard"));
  assert.match(make, /setDraft\(CARD_DRAFT, \{ code: card\.code \}\)/);
  const sess = src("core/session.js");
  assert.equal((sess.match(/if \(duress\) dropDrafts\(\)/g) || []).length, 2, "online and offline unlock both drop drafts in a decoy session");
  const you = src("screens/you/index.jsx");
  const sheet = you.slice(you.indexOf("function CardSheet"));
  assert.match(sheet, /Close without saving your new card\?/);
  assert.match(sheet, /if \(checked\.current\) forgetNewCard\(\); else setAsking\(true\)/, "every close goes through the question until the check passes");
  assert.doesNotMatch(sheet, /onClose=\{\(\) => \{ S\.cardCode\.value = null/);
});
