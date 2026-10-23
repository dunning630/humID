// The one writer of this device's identity record (`identity/self` in the store). APP-11:
// each module used to write `{ ...snapshot, change }` from a snapshot taken before an await,
// so a write that finished late (the public-log check after a network round trip) could put
// back the record as it was before a newer write, and silently undo it: turn duress on while
// Activity checks the log, and the next forced unlock was a normal one.
//
// updateIdentity(mutator) serialises every write through one promise chain. Each turn
// re-reads the newest record from the store, applies the mutator to a copy, writes it once
// and publishes it to S.identity. The mutator may return a new record, change the copy in
// place, or return null to write nothing. It must be quick and must not await the network.
// With no record in the store it writes nothing: a late write can't bring back an identity
// that erase, reset or a cancelled join has just removed. A new identity is made with
// createIdentity, and removed with clearIdentity, on the same chain.
//
// The recovery-mode pin (modePin, core/recmode.js) only goes forward (V74B-03): whatever a
// mutator returns, a record never leaves here with a pin at a lower version or epoch than the
// one already stored, or with none. A writer working from an older copy can't undo it.
import * as S from "./state.js";
import { R } from "./runtime.js";

let chain = Promise.resolve();
const queue = (fn) => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };

/** Change the identity record. Resolves to the record as written (or as it was, if nothing changed). */
export function updateIdentity(mutator) {
  return queue(async () => {
    const latest = await R.store.getIdentity();
    if (!latest) return null; // erased, reset or cancelled meanwhile: nothing to change
    const draft = structuredClone(latest);
    const out = await mutator(draft);
    if (out === null) return latest;
    const record = out && typeof out === "object" ? out : draft;
    keepPin(latest, record);
    const schema = record.schema ?? latest.schema ?? 4;
    delete record.schema; // the store stamps its own schema version
    await R.store.putIdentity(record);
    const shown = { ...record, schema };
    S.identity.value = shown;
    return shown;
  });
}

/**
 * A record's pin may only stay or move forward: same or higher version AND same or higher epoch
 * (the chain never lowers either, @humid/recovery followsMode). Anything else, a lower one or
 * none, is replaced by the stored pin.
 */
function keepPin(latest, record) {
  const had = latest.modePin;
  if (!had?.version) return;
  const now = record.modePin;
  if (now?.version >= had.version && (now.epoch ?? 1) >= (had.epoch ?? 1)) return;
  record.modePin = { ...had };
  record.recoveryMode = had.mode;
}

/** Write a brand-new identity record (setting up, or starting to join). Resolves to it as shown. */
export function createIdentity(record) {
  return queue(async () => {
    const rec = { ...record };
    delete rec.schema;
    await R.store.putIdentity(rec);
    const shown = { ...rec, schema: 4 };
    S.identity.value = shown;
    return shown;
  });
}

/** Remove the identity record, after every write queued before it. */
export const clearIdentity = () => queue(() => R.store.clearIdentity());
