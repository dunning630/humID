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
//   idKind     which ID kind a read names (a license barcode, an MRZ's document code)
import { PAPER } from "./docfind.js";

/** "card" | "page-td3" | "page", from a straightened photo's width and height. */
export function shapeOf(width, height) {
  if (!(width > 0 && height > 0)) return "page";
  const r = Math.max(width, height) / Math.min(width, height);
  if (Math.abs(r / PAPER.id1 - 1) < 0.1) return "card";
  if (Math.abs(r / PAPER.td3 - 1) < 0.06) return "page-td3";
  return "page";
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
