// The Add sheet's category suggestion: nothing defaults to Identity any more.
import { test } from "node:test";
import assert from "node:assert/strict";
import { guessCategory } from "../apps/mobile/src/core/categories.js";

test("common documents land in a sensible category", () => {
  const cases = {
    "lease.pdf": "home", "Apartment lease 2026.pdf": "home", "mortgage-statement.pdf": "money", "car registration.jpg": "home",
    "passport scan.jpg": "identity", "Drivers License front.png": "identity", "ID card.jpeg": "identity", "birth_certificate.pdf": "identity",
    "lab results March.pdf": "health", "Insurance card.png": "health", "vaccination record.pdf": "health",
    "W-2 2025.pdf": "money", "bank statement.pdf": "money", "receipt.jpg": "money",
    "Emergency contacts.txt": "personal", "Last will.pdf": "personal", "diploma.pdf": "personal",
  };
  for (const [name, want] of Object.entries(cases)) assert.equal(guessCategory(name), want, name);
});

test("no match means Other, and words inside other words don't match", () => {
  for (const n of ["IMG_2041.jpg", "scan.pdf", "current.pdf", "label.png", "subtitle.srt", "", undefined]) assert.equal(guessCategory(n), "other", String(n));
});
