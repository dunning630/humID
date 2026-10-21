// The document camera's machine (apps/mobile/src/core/capture.js, 3.0.3): what the person is told,
// moment by moment, from the camera's verdicts; the lock box; and what was read, said back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  begin, step, view, chipsOf, docBox, easeBox, summarize, day, diagnose, verdictOf, pace, isLive,
  TIPS, SAY_AFTER, SWITCH_AFTER, TIMING, CHIP_AGREE,
} from "../apps/mobile/src/core/capture.js";
import { parseMrz } from "@humid/idscan";

const run = (s, events, t0 = 0, dt = 100) => events.reduce((st, ev, i) => step(st, ev, t0 + i * dt), s);
const look = (v, extra = {}) => ({ t: "look", v: { present: true, aligned: true, steady: true, sharp: true, ready: true, key: null, ...v }, progress: 0, ...extra });
const NOTHING = { present: false, aligned: false, steady: true, sharp: true, ready: false, key: null };

test("starting → aim → hold → capture → check → done, with the words at each step", () => {
  let s = begin({ expect: null, now: 0 });
  assert.equal(view(s).headline, "Starting the camera");
  s = step(s, { t: "ready" }, 10);
  assert.equal(s.phase, "aim");
  assert.equal(view(s, { noun: "license" }).headline, "Place the license in the frame");
  s = step(s, look(NOTHING), 100);
  assert.equal(s.phase, "aim");
  s = step(s, { ...look({}), progress: 0.4 }, 200);
  assert.equal(s.phase, "hold");
  assert.equal(view(s).headline, "Hold still");
  assert.equal(view(s).progress, 0.4, "the ring fills as it holds");
  s = step(s, { t: "capture", how: "auto" }, 300);
  assert.equal(view(s).headline, "Captured");
  assert.equal(isLive(s), false, "looks don't move a photo being taken");
  assert.equal(step(s, look(NOTHING), 310), s);
  s = step(s, { t: "check", note: "Saving…" }, 400);
  assert.equal(view(s).headline, "Saving…");
  s = step(s, { t: "done", result: { title: "Got it", detail: "Read from the barcode.", fields: [{ label: "Name", value: "Jordan Alex Specimen" }] } }, 500);
  const v = view(s);
  assert.equal(v.headline, "Got it"); assert.equal(v.tone, "ok");
  assert.deepEqual(v.fields, [{ label: "Name", value: "Jordan Alex Specimen" }]);
  assert.ok(v.actions.includes("continue"));
  assert.match(v.live, /Name: Jordan Alex Specimen/, "a screen reader hears what was read");
});

test("a problem is said only once it has held; good news is said at once", () => {
  let s = run(begin(), [{ t: "ready" }]);
  const closer = look({ key: "closer", aligned: false, ready: false });
  s = step(s, closer, 100);
  assert.notEqual(s.phase, "adjust", "not at once");
  s = step(s, closer, 100 + SAY_AFTER.default);
  assert.equal(s.phase, "adjust");
  assert.equal(view(s).headline, "Move closer");
  assert.equal(view(s).tone, "warn");
  // fixed: cleared at the next look
  s = step(s, look({}), 600);
  assert.equal(s.phase, "hold");
  assert.equal(view(s).headline, "Hold still");
});

test("a flicker between two problems doesn't flicker on screen: a new one waits SWITCH_AFTER", () => {
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({ key: "closer", aligned: false }), 0);
  s = step(s, look({ key: "closer", aligned: false }), 400);
  assert.equal(view(s).headline, "Move closer");
  s = step(s, look({ key: "shift", aligned: false, detail: "Move it left." }), 450);
  assert.equal(view(s).headline, "Move closer", "the new one waits");
  s = step(s, look({ key: "shift", aligned: false, detail: "Move it left." }), 450 + SWITCH_AFTER - 10);
  assert.equal(view(s).headline, "Move closer");
  s = step(s, look({ key: "shift", aligned: false, detail: "Move it left." }), 450 + SWITCH_AFTER);
  assert.equal(view(s).headline, "Line it up");
  assert.equal(view(s).detail, "Move it left.", "with the direction from the verdict");
  s = step(s, look({ key: "shift", aligned: false, detail: "Move it up." }), 1100);
  assert.equal(view(s).detail, "Move it up.", "the direction follows the document while the same problem stands");
});

test("a blur is 'Focusing…' first, and only called blurry once it has lasted", () => {
  let s = run(begin(), [{ t: "ready" }]);
  const blur = look({ key: "blur", sharp: false, ready: false });
  s = step(s, blur, 0);
  assert.equal(view(s).headline, "Focusing…");
  s = step(s, blur, SAY_AFTER.blur - 10);
  assert.equal(view(s).headline, "Focusing…");
  s = step(s, blur, SAY_AFTER.blur);
  assert.equal(view(s).headline, "Not sharp yet");
});

test("the chips: what each says, and they change only when looks agree", () => {
  assert.deepEqual(chipsOf({ present: false }), { framed: "off", sharp: "off", steady: "off", light: "off" });
  assert.deepEqual(chipsOf({ present: true, aligned: false, key: "closer" }), { framed: "warn", sharp: "off", steady: "off", light: "ok" });
  assert.deepEqual(chipsOf({ present: true, aligned: true, sharp: false, steady: true }), { framed: "ok", sharp: "warn", steady: "ok", light: "ok" });
  assert.equal(chipsOf({ present: false, key: "dark" }).light, "warn");
  assert.equal(chipsOf({ present: true, key: "glare" }).light, "warn");
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({}), 100);
  assert.equal(s.chips.framed, "off", "one look isn't enough");
  for (let i = 1; i < CHIP_AGREE; i++) s = step(s, look({}), 100 + i * 100);
  assert.equal(s.chips.framed, "ok");
  s = step(s, look(NOTHING), 900);
  s = step(s, look({}), 1000);
  assert.equal(s.chips.framed, "ok", "a single odd look doesn't move it");
});

test("the code chip: off → seen → reading → read; then 'Barcode read ✓' and only the photo is left", () => {
  let s = run(begin({ expect: "barcode" }), [{ t: "ready" }]);
  const chip = () => view(s).chips.find((c) => c.k === "code");
  assert.equal(chip().label, "Barcode"); assert.equal(chip().state, "off");
  s = step(s, look({}, { codeSeen: true }), 100);
  s = step(s, look({}, { codeSeen: true }), 200);
  assert.equal(chip().state, "seen");
  assert.equal(view(s).headline, "Reading the barcode…", "with the barcode in view, it says it's reading");
  s = step(s, { t: "code", state: "reading" }, 250);
  assert.equal(chip().state, "busy");
  s = step(s, { t: "code", state: "read", fields: [{ label: "Name", value: "X" }] }, 300);
  assert.equal(chip().state, "ok");
  assert.equal(view(s).headline, "Barcode read ✓");
  assert.equal(view(s).detail, "Hold still for the photo.");
  s = step(s, look({ key: "closer", aligned: false }), 400);
  s = step(s, look({ key: "closer", aligned: false }), 800);
  assert.equal(view(s).headline, "Barcode read ✓", "what's left is said under it");
  assert.equal(view(s).detail, "Move closer for the photo.");
  const p = view(run(begin({ expect: "mrz" }), [{ t: "ready" }])).chips.find((c) => c.k === "code");
  assert.equal(p.label, "ID lines");
  assert.equal(view(run(begin({ expect: "card" }), [{ t: "ready" }])).chips.find((c) => c.k === "code"), undefined, "a card's number is read after the photo: no live chip");
});

test("fail: plain words and the two ways forward; retry is a fresh start", () => {
  let s = run(begin({ expect: "barcode" }), [{ t: "ready" }, { t: "capture" }, { t: "check" }]);
  s = step(s, { t: "fail", result: { title: "Couldn't read the barcode", detail: "Try again closer." } }, 900);
  const v = view(s);
  assert.equal(v.headline, "Couldn't read the barcode"); assert.equal(v.tone, "warn");
  assert.deepEqual(v.actions, ["retry", "keep"]);
  assert.deepEqual(view(step(s, { t: "fail", result: { title: "x", keep: false } }, 950)).actions, ["retry"]);
  s = step(s, { t: "retry" }, 1000);
  assert.equal(s.phase, "aim"); assert.equal(s.tries, 1); assert.equal(s.code.state, "off"); assert.equal(s.startedAt, 1000);
});

test("the budget: after a while the round button is pointed out, in words and with a pulse", () => {
  let s = run(begin(), [{ t: "ready" }]);
  assert.equal(view(s).offer, false);
  s = step(s, { t: "tick" }, TIMING.offerShutterAfter);
  assert.equal(view(s).offer, true);
  assert.match(view(s).detail, /round button/);
  assert.equal(view(s, { guided: false }).headline, "Point the camera at the document", "Photo has no frame to line up in");
  assert.equal(view(s, { guided: false }).chips[0].label, "Found");
});

test("Too dark offers the light only when the phone has one", () => {
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({ key: "dark", present: false, aligned: false }), 0);
  s = step(s, look({ key: "dark", present: false, aligned: false }), SAY_AFTER.dark);
  assert.equal(view(s).headline, "Too dark");
  assert.ok(view(s, { torch: true }).actions.includes("light"));
  assert.ok(!view(s, { torch: false }).actions.includes("light"));
});

test("the lock box: from four (or three) edges, never from a shape no document has; eased, a big jump snaps", () => {
  const e = (o) => ({ found: true, off: o });
  const m = { sides: 4, rot: 2, edges: { left: e(-0.2), right: e(-0.2), top: e(-0.2), bottom: e(-0.2) } };
  const b = docBox(m);
  for (const [k, want] of [["x", 0.2], ["y", 0.2], ["w", 0.6], ["h", 0.6]]) assert.ok(Math.abs(b[k] - want) < 1e-9, `${k} ${b[k]}`);
  assert.equal(b.rot, 2);
  const three = docBox({ sides: 3, edges: { left: e(-0.1), right: e(-0.3), top: e(-0.2), bottom: { found: false } } });
  assert.ok(Math.abs(three.h - 0.6) < 1e-9, "the missing side mirrors its opposite");
  assert.equal(docBox({ sides: 2, edges: m.edges }), null, "two sides aren't enough");
  assert.equal(docBox({ sides: 4, edges: { left: e(0), right: e(0), top: e(-0.4), bottom: e(-0.4) } }), null, "a width and height that don't agree");
  const eased = easeBox({ x: 0, y: 0, w: 1, h: 1, rot: 0 }, { x: 0.1, y: 0.1, w: 0.8, h: 0.8, rot: 4 }, 0.5);
  assert.ok(Math.abs(eased.w - 0.9) < 1e-9 && Math.abs(eased.rot - 2) < 1e-9);
  assert.deepEqual(easeBox({ x: 0, y: 0, w: 1, h: 1, rot: 0 }, { x: 0.4, y: 0.4, w: 0.5, h: 0.5, rot: 0 }), { x: 0.4, y: 0.4, w: 0.5, h: 0.5, rot: 0 });
  assert.equal(easeBox({ x: 0, y: 0, w: 1, h: 1, rot: 0 }, null), null);
});

const BARCODE = readFileSync(new URL("./fixtures/id/card-back.barcode.txt", import.meta.url), "utf8");

test("what a license's barcode gave, said back: name, date of birth, number, expiry, city", () => {
  const r = summarize("driver_license", { barcode: BARCODE }, "barcode");
  assert.equal(r.ok, true); assert.equal(r.what, "barcode"); assert.equal(r.title, "Got it");
  const f = Object.fromEntries(r.fields.map((x) => [x.label, x.value]));
  assert.equal(f.Name, "Jordan Alex Specimen");
  assert.equal(f.Number, "S12345678901");
  assert.match(f["Date of birth"], /^\d{1,2} [A-Z][a-z]{2} \d{4}$/);
  assert.ok(f.Expires && f.Address);
});

test("what a passport's lines gave; partial lines and nothing at all are said plainly", () => {
  const lines = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10";
  const mrz = parseMrz(lines, { now: new Date("2010-01-01") });
  const r = summarize("passport", { mrz, consensus: true }, "mrz");
  assert.equal(r.ok, true);
  const f = Object.fromEntries(r.fields.map((x) => [x.label, x.value]));
  assert.equal(f.Number, "L898902C3"); assert.equal(f["Date of birth"], "12 Aug 1974"); assert.equal(f.Nationality, "UTO");
  assert.match(r.detail, /checked twice/);
  const bad = summarize("passport", { mrz: { ...mrz, valid: false } }, "mrz");
  assert.equal(bad.ok, false); assert.equal(bad.title, "Read only part of it");
  assert.equal(summarize("passport", {}, "mrz").title, "Couldn't read the lines of <<<");
  assert.equal(summarize("driver_license", {}, "barcode").title, "Couldn't read the barcode");
  assert.equal(summarize("id_card", {}, "both").title, "Couldn't read the details");
  assert.equal(summarize("driver_license", { barcode: "https://example.com" }, "barcode").title, "That isn't an ID barcode");
  assert.equal(summarize("other", {}, null).ok, true, "a photo with nothing to read is fine");
});

test("day(): the same on every phone", () => {
  assert.equal(day("1974-08-12"), "12 Aug 1974");
  assert.equal(day("2029-01-05"), "5 Jan 2029");
  assert.equal(day(""), "");
});

test("the Photo camera's looks fit the same machine", () => {
  assert.equal(diagnose(null), null);
  assert.equal(diagnose({ found: false, dim: true }), "dark");
  assert.equal(diagnose({ found: true, fits: false }), "shape");
  assert.equal(diagnose({ found: true, fits: true, big: false }), "far");
  assert.equal(diagnose({ found: true, fits: true, big: true, light: false, mean: 230 }), "bright");
  const v = verdictOf({ found: true, ok: true, fits: true, big: true, light: true, steady: true, sharp: true });
  assert.deepEqual([v.present, v.aligned, v.ready, v.key], [true, true, true, null]);
  for (const k of ["shape", "far", "bright"]) assert.ok(TIPS[k].title);
});

test("pace: slow phones are given room, fast ones aren't slowed", () => {
  assert.equal(pace(0), 70);
  assert.equal(pace(50), 110);
  assert.equal(pace(1000), 260);
  assert.equal(pace(10, { min: 80 }), 80);
});

test("nothing the camera says names a picture or keeps one", () => {
  const src = readFileSync(new URL("../apps/mobile/src/core/capture.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /console\.|localStorage|fetch\(|ImageData|canvas/i);
});
