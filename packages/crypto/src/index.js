// @humid/crypto — suite registry. The app talks to a suite through this
// interface only, so a new suite (e.g. HUMID-PQ2) ships as an added file plus
// a registry line, while every envelope sealed under PQ1 keeps opening.

import * as PQ1 from "./suites/pq1.js";
import { unpack } from "@humid/codec";

const SUITES = new Map([[PQ1.ID, PQ1]]);

/** Suite new identities and seals use. Changing this never breaks old data. */
export const DEFAULT_SUITE = PQ1.ID;

export function suite(id = DEFAULT_SUITE) {
  const s = SUITES.get(id);
  if (!s) throw new Error(`Unsupported sealing suite "${id}". Update HumID to open this envelope.`);
  return s;
}

/** Pick the suite an existing envelope was sealed with. */
export const suiteForEnvelope = (envelope) => suite(unpack(envelope).manifest.suite);

export const supportedSuites = () => [...SUITES.keys()];

export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// Split keys: documents that also need a per-document key from the keyshare service.
export { splitWrap, splitUnwrap, isSplit, SPLIT_TYPE, SHARE_BYTES } from "./split.js";
