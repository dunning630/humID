// When a document was sealed, as the app shows it.
//
// Two clocks know: the phone's (the time written into the sealed envelope, which the
// holder can set) and the vault server's (when it received the document, which the
// holder can't). The live check and the upload are one step, and the server refuses a
// request whose clock is more than two minutes off, so the two normally agree to the
// second. The app shows the server's time; the phone's only when it disagrees, as
// "the phone's clock said", never as the seal time. Pure; tests/sealtime.test.js.

/** How far apart the clocks may be before the phone's time is shown beside the server's. */
export const CLOCK_GAP_MS = 2 * 60 * 1000;

/**
 * item: { uploadedAt (server), sealedAt (phone) }. Returns
 *   { at, by: "server" | "phone", phoneAt (only when it disagrees), gapMs }
 * or null when neither time is known.
 */
export function sealTime(item) {
  const server = Date.parse(item?.uploadedAt), phone = Date.parse(item?.sealedAt);
  if (!Number.isFinite(server)) return Number.isFinite(phone) ? { at: item.sealedAt, by: "phone", phoneAt: null, gapMs: null } : null;
  const gapMs = Number.isFinite(phone) ? phone - server : null;
  return { at: item.uploadedAt, by: "server", phoneAt: gapMs !== null && Math.abs(gapMs) > CLOCK_GAP_MS ? item.sealedAt : null, gapMs };
}
