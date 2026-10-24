// The document camera's outlines and words (5.0). What a frame looks like for each kind of
// document, and every instruction the camera can give. Shared by the native camera (whose
// events name a key of MESSAGES) and the web camera used in development and the browser tests.
// Pure data: nothing here sees a picture.

/** Real proportions (long side / short side): ID-1 is 85.6 × 54 mm, ID-3 (a passport's data page) 125 × 88 mm. */
export const RATIO = { id1: 85.6 / 54, td3: 125 / 88, page: 1.35 };
// page: a sheet of paper, standing up (height / width). 1.35 sits between US Letter (1.294) and A4 (1.414).

/** The document's width across the frame, in millimetres (for the zoom that keeps the phone far enough to focus). */
export const WIDTH_MM = { id1: 85.6, td3: 125, page: 216 };

/**
 * What each outline shows inside it, as faint dashed zones ([x, y, w, h] in percent of the outline)
 * so the person knows which way up and which side. Decoration only.
 */
const ZONES = {
  "id-front": [["photo", 5, 22, 28, 60], ["line", 40, 28, 50, 8], ["line", 40, 46, 42, 8], ["line", 40, 64, 46, 8]],
  "id-back": [["bar", 6, 38, 88, 36], ["line", 6, 12, 60, 8]],
  "id-back-mrz": [["line", 6, 12, 60, 8], ["mrz", 4, 62, 92, 30]],
  "passport": [["photo", 4, 18, 24, 52], ["line", 34, 20, 56, 8], ["line", 34, 36, 48, 8], ["mrz", 3, 72, 94, 22]],
  "pay-front": [["chip", 7, 30, 15, 20], ["num", 7, 56, 86, 12], ["line", 7, 78, 50, 8]],
  "pay-back": [["stripe", 0, 12, 100, 18], ["sign", 7, 44, 58, 16]],
  "page": [["line", 9, 7, 44, 3], ["line", 9, 15, 82, 2.4], ["line", 9, 20.5, 82, 2.4], ["line", 9, 26, 64, 2.4]],
  "plain": [],
};

/**
 * The template for a document: { id, shape ("id1" | "td3" | "page"), noun, side, expect ({ barcode, mrz }), zones }.
 *   kind  the kind picked on "What are you adding?" (driver_license, passport, id_card, residence_permit, other, card, page)
 *   side  "front" | "back"
 *   read  what the camera is to read ({ barcode, mrz })
 */
export function templateFor({ kind = "other", side = "front", shape = "id1", read = {} } = {}) {
  if (kind === "page" || shape === "page") {
    return { id: "page", kind: "page", side: "front", shape: "page", ratio: RATIO.page, noun: "page", expect: { barcode: false, mrz: false }, zones: ZONES.page.map(([k, x, y, w, h]) => ({ k, x, y, w, h })) };
  }
  const td3 = shape === "td3" || kind === "passport";
  const back = side === "back";
  const noun = td3 ? "passport page" : kind === "driver_license" ? "license" : "card";
  let zones = "plain";
  if (td3) zones = "passport";
  else if (kind === "card") zones = back ? "pay-back" : "pay-front";
  else if (!back) zones = "id-front";
  else zones = read.mrz && !read.barcode ? "id-back-mrz" : read.barcode ? "id-back" : "plain";
  return {
    id: `${kind}-${side}`, kind, side, shape: td3 ? "td3" : "id1", ratio: td3 ? RATIO.td3 : RATIO.id1, noun,
    expect: { barcode: !!read.barcode, mrz: !!read.mrz },
    zones: ZONES[zones].map(([k, x, y, w, h]) => ({ k, x, y, w, h })),
  };
}

/**
 * Everything the camera can ask the person to change, by key. The native camera's `look`
 * events name one of these keys (plugins/humid-docscan, GuideKey); the words live here only.
 */
export const MESSAGES = {
  dark: { title: "Too dark", detail: "Turn on the light, or move somewhere brighter." },
  glare: { title: "Too much glare", detail: "Tilt the document a little so the shine moves off it." },
  bright: { title: "Too bright", detail: "Move out of direct light." },
  closer: { title: "Move closer", detail: "Fill the frame with the document." },
  fill: { title: "Fill the frame", detail: "Bring it a little closer, edge to edge." },
  far: { title: "Move closer", detail: "Let the document fill more of the screen." },
  back: { title: "Move back a little", detail: "The whole document has to fit inside the frame." },
  tooclose: { title: "Move back a little", detail: "Too close for the camera to focus. Hold the phone a little farther away." },
  shift: { title: "Line it up", detail: "Move it so its edges meet the frame." },
  tilt: { title: "Straighten the card", detail: "Turn it until its edges run along the frame." },
  flat: { title: "Hold the phone flat", detail: "Hold it straight above the document, not at an angle." },
  hold: { title: "Hold still", detail: "It's moving a little. Keep the phone and the document still." },
  shape: { title: "Show just the document", detail: "Nothing else in the picture." },
  showback: { title: "Show the back", detail: "Turn it to the side with the barcode, or press the round button." },
  showfront: { title: "Show the front", detail: "The side with your photo." },
  showpage: { title: "Show the photo page", detail: "The page with your photo and the two lines of <<<." },
};

/** The keys a camera may send. Anything else is ignored. */
export const KEYS = new Set(Object.keys(MESSAGES));
