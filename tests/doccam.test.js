// The document camera's machine (apps/mobile/src/core/capture.js, 5.0): what the person is told,
// moment by moment, from the camera's own events (the native camera, or the web camera, both
// shaped by core/lookstate.js); and what was read, said back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { begin, step, view, chipsOf, summarize, day, isLive, TIPS, TIMING } from "../apps/mobile/src/core/capture.js";
import { parseMrz } from "@humid/idscan";

const run = (s, events, t0 = 0, dt = 100) => events.reduce((st, ev, i) => step(st, ev, t0 + i * dt), s);
/** A look as a camera sends it (core/lookstate.js): lined up and in focus unless told otherwise. */
const look = (o = {}) => ({ t: "look", look: { state: "sharp", key: null, aligned: true, quad: [[0, 0], [10, 0], [10, 6], [0, 6]], focus: "focused", steady: true, light: "ok", progress: 0, ...o } });
const NOTHING = { state: "searching", aligned: false, quad: null, focus: null };

test("starting → aim → hold → capture → check → done, with the words at each step", () => {
  let s = begin({ expect: null, now: 0 });
  assert.equal(view(s).headline, "Starting the camera");
  s = step(s, { t: "ready" }, 10);
  assert.equal(s.phase, "aim");
  assert.equal(view(s, { noun: "license" }).headline, "Place the license in the frame");
  s = step(s, look(NOTHING), 100);
  assert.equal(s.phase, "aim");
  s = step(s, look({ progress: 0.4 }), 200);
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

test("the camera's key is said as it comes (the camera already waited); cleared at once", () => {
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({ state: "aligning", aligned: false, key: "closer" }), 100);
  assert.equal(s.phase, "adjust");
  assert.equal(view(s).headline, "Move closer");
  assert.equal(view(s).tone, "warn");
  s = step(s, look({}), 200);
  assert.equal(s.phase, "hold");
  assert.equal(view(s).headline, "Hold still");
  // a key the app doesn't know is not shown (a newer camera, a bad event)
  s = step(s, look({ key: "explode" }), 300);
  assert.equal(s.phase, "hold");
});

test("'Focusing…' only while the camera says its autofocus is moving, never because a look is lined up", () => {
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({ focus: "scanning", state: "sharp" }), 100);
  assert.notEqual(view(s).headline, "Focusing…", "a short scan isn't said (the camera hasn't called it focusing)");
  s = step(s, look({ focus: "scanning", state: "focusing" }), 200);
  assert.equal(view(s).headline, "Focusing…");
  assert.equal(view(s).chips.find((c) => c.k === "sharp").state, "busy");
  s = step(s, look({ focus: "focused", state: "sharp" }), 300);
  assert.equal(view(s).headline, "Hold still");
  // a camera that can't say (the web camera: focus null) is never "Focusing…"
  s = step(s, look({ focus: null, state: "sharp" }), 400);
  assert.equal(view(s).headline, "Hold still");
  assert.equal(view(s).chips.find((c) => c.k === "sharp").state, "ok");
});

test("too close: 'Move back a little', and the Sharp chip says why", () => {
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({ key: "tooclose", focus: "failed" }), 100);
  assert.equal(view(s).headline, "Move back a little");
  assert.match(view(s).detail, /Too close for the camera to focus/);
  assert.equal(view(s).chips.find((c) => c.k === "sharp").state, "warn");
});

test("the chips follow each look (no second agreement rule)", () => {
  assert.deepEqual(chipsOf(null), { framed: "off", sharp: "off", steady: "off", light: "off" });
  assert.deepEqual(chipsOf({ state: "searching", quad: null }), { framed: "off", sharp: "off", steady: "off", light: "off" });
  assert.deepEqual(chipsOf({ state: "aligning", aligned: false, quad: [[0, 0]], key: "closer", light: "ok" }), { framed: "warn", sharp: "off", steady: "off", light: "ok" });
  assert.deepEqual(chipsOf({ state: "sharp", aligned: true, quad: [[0, 0]], focus: "focused", steady: true, light: "ok" }), { framed: "ok", sharp: "ok", steady: "ok", light: "ok" });
  assert.equal(chipsOf({ state: "sharp", aligned: true, steady: false, light: "ok" }).steady, "warn");
  assert.equal(chipsOf({ state: "searching", light: "dark" }).light, "warn");
  let s = run(begin(), [{ t: "ready" }]);
  s = step(s, look({}), 100);
  assert.equal(s.chips.framed, "ok", "one look is enough: the camera already held it");
});

test("the code chip: off → seen → reading → read; then 'Barcode read ✓' and only the photo is left", () => {
  let s = run(begin({ expect: "barcode" }), [{ t: "ready" }]);
  const chip = () => view(s).chips.find((c) => c.k === "code");
  assert.equal(chip().label, "Barcode"); assert.equal(chip().state, "off");
  s = step(s, { t: "code", state: "seen" }, 100);
  assert.equal(chip().state, "seen");
  s = step(s, look({}), 150);
  assert.equal(view(s).headline, "Reading the barcode…", "with the barcode in view, it says it's reading");
  s = step(s, { t: "code", state: "reading" }, 250);
  assert.equal(chip().state, "busy");
  s = step(s, { t: "code", state: "read", fields: [{ label: "Name", value: "X" }] }, 300);
  assert.equal(chip().state, "ok");
  assert.equal(view(s).headline, "Barcode read ✓");
  assert.equal(view(s).detail, "Hold still for the photo.");
  s = step(s, { t: "code", state: "reading" }, 350);
  assert.equal(chip().state, "ok", "once read, it stays read");
  s = step(s, look({ state: "aligning", aligned: false, key: "closer" }), 400);
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
  s = step(s, look({ state: "searching", aligned: false, quad: null, key: "dark", light: "dark" }), 0);
  assert.equal(view(s).headline, "Too dark");
  assert.ok(view(s, { torch: true }).actions.includes("light"));
  assert.ok(!view(s, { torch: false }).actions.includes("light"));
});

test("every key a camera may send has words", () => {
  for (const k of ["dark", "glare", "bright", "closer", "fill", "far", "back", "tooclose", "shift", "tilt", "flat", "hold", "shape", "showback", "showfront", "showpage"]) {
    assert.ok(TIPS[k]?.title && TIPS[k].detail, k);
  }
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

test("nothing the camera says names a picture or keeps one", () => {
  for (const f of ["capture.js", "lookstate.js", "doctpl.js"]) {
    const src = readFileSync(new URL(`../apps/mobile/src/core/${f}`, import.meta.url), "utf8");
    assert.doesNotMatch(src, /console\.|localStorage|fetch\(|ImageData|canvas/i, f);
  }
});
