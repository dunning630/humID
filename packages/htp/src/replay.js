// Sliding replay window (like IPsec/DTLS). Accepts each sequence number at
// most once, tolerates out-of-order arrival within WINDOW, rejects anything
// older. Lets the app issue concurrent requests on one session.

export const WINDOW = 256;

export class ReplayWindow {
  constructor() {
    this.highest = 0;
    this.seen = new Set();
  }

  /** True and records the seq if it is fresh; false if replayed or too old. */
  accept(seq) {
    if (!Number.isSafeInteger(seq) || seq < 1) return false;
    if (seq <= this.highest - WINDOW) return false;
    if (this.seen.has(seq)) return false;
    this.seen.add(seq);
    if (seq > this.highest) {
      this.highest = seq;
      for (const s of this.seen) if (s <= this.highest - WINDOW) this.seen.delete(s);
    }
    return true;
  }
}
