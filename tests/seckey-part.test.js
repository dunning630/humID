// The security-key part of two-proof recovery (4.0, docs/SECURITY-KEY.md): four parts,
// any two different ones rebuild the seed, and the key part opens only with the key's secret.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, hkdfSync } from "node:crypto";
import {
  quorumParts, combineQuorum, encodeQuorumPart, decodeQuorumPart, QUORUM, QUORUM_KINDS,
  keyTag, sealKeyPart, openKeyPart, KEY_PART_BLOB_BYTES, KEY_SECRET_BYTES, CARD_PART_BLOB_BYTES,
  newCard, sealCardPart, openCardPart, quorumDelay, evidenceLabel,
} from "@humid/recovery";

const seed = new Uint8Array(randomBytes(64));
const account = "hid_" + "ab".repeat(20);
const secret = () => new Uint8Array(randomBytes(KEY_SECRET_BYTES));

test("four parts: every pair of different kinds rebuilds the seed; a part with itself doesn't", () => {
  assert.deepEqual(QUORUM_KINDS, ["witness", "anchor", "card", "key"]);
  const p = quorumParts(seed);
  for (let i = 0; i < 4; i++) for (let j = i + 1; j < 4; j++) {
    assert.deepEqual(combineQuorum([p[QUORUM_KINDS[i]], p[QUORUM_KINDS[j]]]), seed, `${QUORUM_KINDS[i]} + ${QUORUM_KINDS[j]}`);
  }
  assert.throws(() => combineQuorum([p.key, p.key]), /two different kinds/);
  for (const k of QUORUM_KINDS) assert.notDeepEqual(p[k].y, seed, "no part is the seed");
});

test("the parts follow the documented polynomial, so a card made by 3.x fits a key made by 4.0", () => {
  // Recomputed here from docs/CONTINUITY.md, independently of the package:
  // c = HKDF-SHA3-256(A, info "HUMID-QUORUM-v1 coefficient epoch 1"), part(x) = A + c·x over GF(2^8) (0x11b).
  const gmul = (a, b) => { let r = 0; while (b) { if (b & 1) r ^= a; a <<= 1; if (a & 0x100) a ^= 0x11b; b >>= 1; } return r; };
  const c = new Uint8Array(hkdfSync("sha3-256", seed, Buffer.alloc(0), "HUMID-QUORUM-v1 coefficient epoch 1", 64));
  const p = quorumParts(seed);
  for (const kind of QUORUM_KINDS) {
    const x = QUORUM[kind];
    assert.equal(p[kind].x, x);
    assert.deepEqual(p[kind].y, seed.map((a, i) => a ^ gmul(c[i], x)), kind);
  }
});

test("key part: round trip, a different secret or account doesn't open it, size is fixed", async () => {
  const s = secret();
  const part = quorumParts(seed).key;
  const blob = await sealKeyPart(s, part, account);
  assert.equal(blob.length, KEY_PART_BLOB_BYTES);
  assert.equal(KEY_PART_BLOB_BYTES, CARD_PART_BLOB_BYTES);
  const back = await openKeyPart(s, blob, account);
  assert.equal(back.x, QUORUM.key);
  assert.deepEqual(back.y, part.y);
  await assert.rejects(openKeyPart(secret(), blob, account), /doesn't open this vault/);
  await assert.rejects(openKeyPart(s, blob, "hid_" + "cd".repeat(20)), /doesn't open this vault/);
  const flipped = blob.slice(); flipped[20] ^= 1;
  await assert.rejects(openKeyPart(s, flipped, account), /doesn't open this vault/);
});

test("key part: only the key part can be sealed under a key, and only a key part comes out", async () => {
  const s = secret();
  await assert.rejects(sealKeyPart(s, quorumParts(seed).card, account), /isn't the key part/);
  // A card blob (domain HUMID-CARD-v2) never opens as a key blob, even with the same 32 bytes as material.
  const card = newCard();
  const cardBlob = await sealCardPart(card.secret, quorumParts(seed).card, account);
  await assert.rejects(openKeyPart(s, cardBlob, account), /doesn't open/);
  await assert.rejects(openCardPart(card.secret, await sealKeyPart(s, quorumParts(seed).key, account), account), /does not open/);
});

test("key tag: 26 base32 characters, stable for a secret, unrelated across secrets, and not the encryption key", async () => {
  const s = secret();
  assert.match(keyTag(s), /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(keyTag(s), keyTag(s.slice()));
  assert.notEqual(keyTag(s), keyTag(secret()));
  assert.throws(() => keyTag(new Uint8Array(31)), /32 bytes/);
});

test("waits: a key counts as a kind; the formula is the one the server uses", () => {
  const base = 72 * 3600_000;
  assert.equal(quorumDelay(["key"], { base }), null, "one proof never opens anything");
  assert.equal(quorumDelay(["key", "witness"], { base }), base);
  assert.equal(quorumDelay(["key", "card"], { base }), Math.round(base * 7 / 3));
  assert.equal(quorumDelay(["key", "anchor"], { base, anchorMode: "remote" }), Math.round(base * 7 / 3));
  assert.equal(quorumDelay(["key", "anchor"], { base, anchorMode: "station" }), Math.round(base / 3));
  assert.equal(quorumDelay(["key", "card"], { base, duress: true }), Math.round(base * 14 / 3));
  assert.equal(evidenceLabel(["key", "card"]), "seal card + security key");
});

test("encodeQuorumPart and decodeQuorumPart accept the key part and still refuse strangers", () => {
  const k = quorumParts(seed).key;
  assert.deepEqual(decodeQuorumPart(encodeQuorumPart(k)), k);
  const bad = encodeQuorumPart(k); bad[0] = 5;
  assert.throws(() => decodeQuorumPart(bad), /Unknown recovery part/);
});
