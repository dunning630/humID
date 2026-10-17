// Kinds and tags (apps 2.0): every vault item has one kind (id · card · pass · photo ·
// file), sealed in its index entry; items sealed before 2.0 carry none and are
// classified from what else the entry holds. The 1.x categories live on as optional
// tags, suggested from the name; nothing defaults to Identity.
import { test } from "node:test";
import assert from "node:assert/strict";
import { KINDS, KIND_IDS, TAGS, TAG_IDS, kindFromType, inferKind, inferTags, classify, guessTag, suggestTags } from "../apps/mobile/src/core/categories.js";

test("five kinds, in the order the vault's chip row shows them", () => {
  assert.deepEqual(KIND_IDS, ["id", "card", "pass", "photo", "file"]);
  assert.deepEqual(KINDS.map((k) => k.label), ["IDs", "Cards", "Passes", "Photos", "Files"]);
  assert.deepEqual(TAG_IDS, ["identity", "health", "money", "home", "personal"], "the 1.x category ids, minus the two that weren't subjects");
  assert.ok(TAGS.every((t) => t.icon && t.label));
});

test("a sealed kind is kept; an old entry without one is classified from its contents", () => {
  assert.equal(inferKind({ kind: "photo", idInfo: { kind: "passport" } }), "photo", "the sealed kind wins");
  assert.equal(inferKind({ kind: "bogus", cardInfo: {} }), "card", "an unknown kind is ignored");
  assert.equal(inferKind({ idInfo: { kind: "passport" }, type: "application/vnd.humid.id+json", category: "identity" }), "id");
  assert.equal(inferKind({ cardInfo: { last4: "1111" }, type: "application/vnd.humid.card+json", category: "money" }), "card");
  assert.equal(inferKind({ passInfo: { style: "eventTicket" }, type: "application/vnd.apple.pkpass", category: "passes" }), "pass");
  assert.equal(inferKind({ type: "image/jpeg", name: "Photo 1/2/2026.jpg", category: "other" }), "photo");
  assert.equal(inferKind({ type: "application/pdf", name: "lease.pdf", category: "home" }), "file");
  assert.equal(inferKind({ name: "Unreadable item", type: "" }), "file");
  assert.equal(inferKind({ type: "application/vnd.humid.id+json" }), "id", "by media type alone, when a summary is missing");
});

test("kindFromType: what a new file is sealed as", () => {
  assert.equal(kindFromType("image/png"), "photo");
  assert.equal(kindFromType("application/octet-stream", "Concert.pkpass"), "pass", "by extension when the browser gives no type");
  assert.equal(kindFromType("text/plain", "notes.txt"), "file");
  assert.equal(kindFromType("", ""), "file");
});

test("the 1.x category becomes a tag on read; tags already sealed are kept and checked", () => {
  assert.deepEqual(inferTags({ category: "home" }), ["home"]);
  assert.deepEqual(inferTags({ category: "other" }), [], "other was never a subject");
  assert.deepEqual(inferTags({ category: "passes" }), [], "passes is a kind now");
  assert.deepEqual(inferTags({ tags: ["money", "nonsense", "home"], category: "identity" }), ["money", "home"]);
  assert.deepEqual(inferTags({}), []);
});

test("classify settles kind and tags, drops category and says when the kind was inferred", () => {
  const old = classify({ name: "lease.pdf", type: "application/pdf", size: 3, category: "home", addedAt: "2025-01-01T00:00:00Z" });
  assert.deepEqual(old, { name: "lease.pdf", type: "application/pdf", size: 3, addedAt: "2025-01-01T00:00:00Z", kind: "file", tags: ["home"], kindInferred: true });
  const fresh = classify({ name: "x", type: "image/jpeg", kind: "photo", tags: [] });
  assert.equal(fresh.kindInferred, false);
  assert.equal(fresh.kind, "photo");
});

test("common documents get a sensible tag suggested from their name", () => {
  const cases = {
    "lease.pdf": "home", "Apartment lease 2026.pdf": "home", "mortgage-statement.pdf": "money", "car registration.jpg": "home",
    "passport scan.jpg": "identity", "Drivers License front.png": "identity", "ID card.jpeg": "identity", "birth_certificate.pdf": "identity",
    "lab results March.pdf": "health", "Insurance card.png": "health", "vaccination record.pdf": "health",
    "W-2 2025.pdf": "money", "bank statement.pdf": "money", "receipt.jpg": "money",
    "Emergency contacts.txt": "personal", "Last will.pdf": "personal", "diploma.pdf": "personal",
  };
  for (const [name, want] of Object.entries(cases)) assert.equal(guessTag(name), want, name);
});

test("no match means no tag, and words inside other words don't match", () => {
  for (const n of ["IMG_2041.jpg", "scan.pdf", "current.pdf", "label.png", "subtitle.srt", "", undefined]) assert.equal(guessTag(n), null, String(n));
});

test("suggestTags: IDs and cards have a natural tag; files and photos follow their name; passes none", () => {
  assert.deepEqual(suggestTags("id", "anything"), ["identity"]);
  assert.deepEqual(suggestTags("card", "Travel card"), ["money"]);
  assert.deepEqual(suggestTags("pass", "Concert ticket"), []);
  assert.deepEqual(suggestTags("file", "lease.pdf"), ["home"]);
  assert.deepEqual(suggestTags("photo", "IMG_2041.jpg"), []);
});
