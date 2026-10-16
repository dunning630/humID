// @humid/store — persistence behind a small interface. Records carry a schema
// number and are upgraded on read, one step at a time, so a release never
// needs a bulk data conversion and old builds' data keeps loading.

import { idbBackend } from "./adapters/idb.js";
import { memoryBackend } from "./adapters/memory.js";
import { migrateIdentity, IDENTITY_SCHEMA } from "./migrations.js";

export { IDENTITY_SCHEMA };

export async function openStore() {
  const backend = (await idbBackend()) || memoryBackend();
  return {
    persistent: backend.persistent,

    async getIdentity() {
      const raw = await backend.get("identity", "self");
      if (!raw) return null;
      const { record, changed } = migrateIdentity(raw);
      if (changed) await backend.put("identity", "self", record);
      return record;
    },
    putIdentity: (rec) => backend.put("identity", "self", { ...rec, schema: IDENTITY_SCHEMA }),
    clearIdentity: () => backend.clear("identity"),

    listVault: () => backend.all("vault"),
    putItem: (item) => backend.put("vault", item.id, item),
    delItem: (id) => backend.del("vault", id),
    clearVault: () => backend.clear("vault"),

    // The offline copy: what the app shows when it can't reach the vault. Sealed
    // under a key from the identity seed (opens only after a live check), and kept
    // in "vault", so every path that erases this device's vault erases it too.
    getOffline: () => backend.get("vault", "offline").then((r) => (r?.blob ? r : null)),
    putOffline: (blob, account) => backend.put("vault", "offline", { id: "offline", v: 1, account, blob }),
    clearOffline: () => backend.del("vault", "offline"),

    // An access pass between buying and spending it (docs/ANONYMITY.md). Survives
    // clearIdentity on purpose: it was paid for. Removed once the account exists.
    getPass: () => backend.get("wallet", "pass").then((p) => p || null),
    putPass: (p) => backend.put("wallet", "pass", p),
    clearPass: () => backend.del("wallet", "pass"),
  };
}
