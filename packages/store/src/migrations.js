// Identity record migrations. Each step upgrades one schema number.
// Add a step, bump IDENTITY_SCHEMA, ship. Never edit a released step.

export const IDENTITY_SCHEMA = 3;

const steps = {
  // 1 -> 2: original single-file app stored WebAuthn/demo fields at the top
  // level; gates are now pluggable, so move them under `gate`.
  1(r) {
    const { credId, prfSalt, demoSecret, mode, ...rest } = r;
    const gate = mode === "demo"
      ? { adapter: "demo", handle: { id: credId, demoSecret } }
      : { adapter: "webauthn-prf", handle: { credId, prfSalt } };
    return { ...rest, mode, bindingId: credId, gate, schema: 2 };
  },
  // 2 -> 3: identities become server-registered. Older local-only identities
  // carry server: null and are offered registration on next unlock.
  2(r) {
    return { ...r, server: r.server ?? null, schema: 3 };
  },
};

export function migrateIdentity(raw) {
  let record = raw;
  let changed = false;
  let v = record.schema || 1;
  if (v > IDENTITY_SCHEMA) throw new Error("This identity was saved by a newer HumID. Update the app to open it.");
  while (v < IDENTITY_SCHEMA) {
    record = steps[v](record);
    v = record.schema;
    changed = true;
  }
  return { record, changed };
}
