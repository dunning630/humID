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
import * as S from "./state.js";
import { R } from "./runtime.js";

let chain = Promise.resolve();

/** Change the identity record. Resolves to the record as written (or as it was, if nothing changed). */
export function updateIdentity(mutator) {
  const run = chain.then(async () => {
    const latest = (await R.store.getIdentity()) || S.identity.value;
    if (!latest) return null;
    const draft = structuredClone(latest);
    const out = await mutator(draft);
    if (out === null) return latest;
    const record = out && typeof out === "object" ? out : draft;
    const schema = record.schema ?? latest.schema ?? 4;
    delete record.schema; // the store stamps its own schema version
    await R.store.putIdentity(record);
    const shown = { ...record, schema };
    S.identity.value = shown;
    return shown;
  });
  chain = run.catch(() => {}); // a failed write doesn't block the next one
  return run;
}
