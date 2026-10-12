// Identity record migrations. Each step upgrades one schema number.
// Add a step, bump IDENTITY_SCHEMA, ship. Never edit a released step.

export const IDENTITY_SCHEMA = 4;

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
  // 3 -> 4: accounts have many devices. The wrapped secret becomes
  // account seed ‖ device seed, and the record names its device. A schema-3
  // record has no device key, so it must be set up again (POC only).
  // `pending` holds a device that is joining an account and not finished yet.
  3(r) {
    return { ...r, device: r.device ?? null, pending: r.pending ?? null, schema: 4 };
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
