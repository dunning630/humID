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
  };
}
