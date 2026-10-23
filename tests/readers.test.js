// Another app that can read the screen (APP-09, R15; apps/mobile/src/core/readers.js). An
// enabled Android accessibility service reads what the WebView shows; before a document, a
// card or messages appear, the holder is told which, by name, and decides.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as S from "../apps/mobile/src/core/state.js";
import { screenReadersOk, answerReaders } from "../apps/mobile/src/core/readers.js";
import { enabledAccessibilityServices } from "@humid/gate";

const TALKER = { id: "com.example/.Reader", label: "Screen Helper", canRead: true, canAct: true };
const list = (...s) => () => Promise.resolve(s);
const tick = () => new Promise((r) => setTimeout(r, 0));

test("no service that can read: nothing is asked", async () => {
  S.resetSession();
  assert.equal(await screenReadersOk("this document", { list: list() }), true);
  assert.equal(await screenReadersOk("this document", { list: list({ id: "x", label: "Switch", canRead: false }) }), true);
  assert.equal(S.readerWarning.value, null);
});

test("one that can read: the holder is asked, by name; 'Not now' shows nothing", async () => {
  S.resetSession();
  const p = screenReadersOk("this document", { list: list(TALKER) });
  await tick();
  assert.deepEqual(S.readerWarning.value, { what: "this document", services: [TALKER] });
  answerReaders(false);
  assert.equal(await p, false);
  assert.equal(S.readerWarning.value, null);
});

test("a yes holds for the session and that same set of services; a new service asks again", async () => {
  S.resetSession();
  const p = screenReadersOk("your messages", { list: list(TALKER) });
  await tick();
  answerReaders(true);
  assert.equal(await p, true);
  assert.equal(await screenReadersOk("this card", { list: list(TALKER) }), true, "not asked twice");
  const q = screenReadersOk("this card", { list: list(TALKER, { id: "b/.B", label: "Other", canRead: true }) });
  await tick();
  assert.equal(S.readerWarning.value?.services.length, 2, "a second service: asked again");
  answerReaders(false);
  assert.equal(await q, false);
});

test("a lock answers no, and the next session asks again", async () => {
  S.resetSession();
  const p = screenReadersOk("this document", { list: list(TALKER) });
  await tick();
  S.resetSession(); // what lock() does to every session signal
  assert.equal(await p, false);
  const again = screenReadersOk("this document", { list: list(TALKER) });
  await tick();
  assert.ok(S.readerWarning.value, "asked again after the lock");
  answerReaders(true);
  await again;
});

test("outside the Android app the gate lists none, and never throws", async () => {
  assert.deepEqual(await enabledAccessibilityServices(), []);
});

test("every way a secret is revealed asks first: a document or card, the recovery card, messages", () => {
  const core = new URL("../apps/mobile/src/core/", import.meta.url);
  const src = (f) => readFileSync(new URL(f, core), "utf8").replace(/\r\n/g, "\n"); // CRLF on a Windows checkout
  const before = (f, fn, call) => { const s = src(f), i = s.indexOf(fn); assert.ok(i >= 0, fn); const j = s.indexOf(call, i); assert.ok(j > i && j < s.indexOf("\n}\n", i), `${f}: ${fn} asks first`); };
  before("vault.js", "export async function openItem(", "screenReadersOk(");
  assert.ok(src("vault.js").indexOf("screenReadersOk(", src("vault.js").indexOf("export async function openItem(")) < src("vault.js").indexOf("fetchPlain(item", src("vault.js").indexOf("export async function openItem(")), "before the document is fetched");
  before("recovery.js", "export async function makeNewCard(", "screenReadersOk(");
  before("enroll.js", "export async function enroll(", "screenReadersOk(");
  before("messaging.js", "export async function verifyToRead(", "screenReadersOk(");
});
