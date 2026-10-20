// How the Add camera decides where a photo goes (screens/add/index.jsx). Pure functions,
// so they're tested without a browser (tests/addroute.test.js).
//
// The camera never waits for a classification: it takes the photo as it always has,
// and these say what to try on it afterwards, cheapest first.
//
//   shape      from the straightened photo's proportions: "card" (ID-1, the shape of
//              every license, ID card and payment card), "page-td3" (a passport's photo
//              page, 1.42: an A4 sheet has the same proportion, so this only says the
//              MRZ reader is worth a try) or "page" (anything else)
//   label      what the live view says it sees, from the outline's shape and whether a
//              barcode stands out on it
//   mrzBand    does the bottom of a page carry two or three dense full-width lines of
//              print, the way an MRZ does? A cheap look before the OCR is loaded, so a
//              plain letter or a blank footer costs nothing. It errs towards yes: a
//              justified paragraph at the foot of a page passes, and then the OCR
//              finds no MRZ and the photo is a photo.
import { PAPER } from "./docfind.js";

/** "card" | "page-td3" | "page", from a straightened photo's width and height. */
export function shapeOf(width, height) {
  if (!(width > 0 && height > 0)) return "page";
  const r = Math.max(width, height) / Math.min(width, height);
  if (Math.abs(r / PAPER.id1 - 1) < 0.1) return "card";
  if (Math.abs(r / PAPER.td3 - 1) < 0.06) return "page-td3";
  return "page";
}

/**
 * The live label over the camera: { icon, text } or null while nothing is in view.
 *   look     { found, ratio } from docfind.lookAt
 *   barcode  a barcode stands out on the document
 */
export function liveLabel(look, { barcode = false } = {}) {
  if (!look?.found) return null;
  const r = look.ratio || 0;
  if (Math.abs(r / PAPER.id1 - 1) < 0.1) return barcode ? { icon: "barcode", text: "Looks like a driver's license" } : { icon: "card", text: "Looks like a card" };
  return { icon: "file", text: "Document" };
}

/**
 * A small grey image of the bottom band of a page ({ w, h, g }, g row-major 0–255).
 * True when it holds at least two separate runs of dark rows that each span nearly
 * the whole width and are dense the way OCR-B lines are.
 */
export function mrzBandLikely({ w, h, g }) {
  if (!w || !h || h < 12) return false;
  // what counts as ink here: clearly darker than the band's own paper
  let sum = 0;
  for (let i = 0; i < g.length; i++) sum += g[i];
  const paper = sum / g.length;
  const dark = paper - 45;
  if (dark < 20) return false;
  const rows = [];
  for (let y = 0; y < h; y++) {
    let first = -1, last = -1, n = 0;
    for (let x = 0; x < w; x++) {
      if (g[y * w + x] < dark) { n++; if (first < 0) first = x; last = x; }
    }
    const span = first < 0 ? 0 : (last - first + 1) / w;
    const density = n / w;
    rows.push(span >= 0.8 && density >= 0.12 && density <= 0.65);
  }
  // runs of MRZ-ish rows at least a few pixels tall, with gaps between them
  let runs = 0, run = 0;
  const minRun = Math.max(2, Math.round(h / 25));
  for (let y = 0; y <= h; y++) {
    if (y < h && rows[y]) { run++; continue; }
    if (run >= minRun) runs++;
    run = 0;
  }
  return runs >= 2;
}

/** Which ID kind a read names: a license barcode, or an MRZ's own document code. */
export function idKindFrom({ barcode = null, mrz = null } = {}) {
  if (barcode) return "driver_license";
  if (mrz?.kind === "passport" || mrz?.kind === "visa") return "passport";
  if (mrz?.kind) return mrz.kind;
  return null;
}

/* ---------------- choose first, then the camera ---------------- */

/** The lighting tip every pre-scan screen carries. */
export const LIGHT_TIP = "Good light helps most: face a window or a lamp, and keep your shadow and glare off it.";

/**
 * What the Add flow tells a person before the camera starts, for the kinds that open
 * the camera from Add itself (IDs have their own steps in the ID flow, from PLAN).
 * `mode` is the scan mode the camera is started with: "card" reads a payment card's
 * number, "photo" takes any document as it is. null for anything with no camera.
 */
export const GUIDE = {
  card: { mode: "card", shape: "id1", eyebrow: "Payment card", title: "Scan the card", hold: "Line the card up inside the outline on the screen, number side up. It tells you if it needs to be closer, steadier or less shiny, takes the photo by itself and reads the number, expiry and name." },
  photo: { mode: "photo", shape: "full", eyebrow: "Photo", title: "Photograph a document", hold: "Lay the page or card on a dark, flat surface and hold the phone above it. It finds the edges, straightens it and takes the photo by itself." },
};
export const guideFor = (kind) => GUIDE[kind] || null;

/** The scan mode for each kind picked in Add: license=barcode, passport=MRZ, card=card scan. */
export const SCAN_MODE = { driver_license: "barcode", passport: "mrz", id_card: "barcode+mrz", residence_permit: "mrz", card: "card", photo: "photo" };
