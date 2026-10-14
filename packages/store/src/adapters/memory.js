// In-memory backend, used when IndexedDB is unavailable (private windows,
// tests). Nothing survives a restart; the UI says so.

export function memoryBackend() {
  const stores = { identity: new Map(), vault: new Map() };
  return {
    persistent: false,
    get: async (s, k) => stores[s].get(k),
    put: async (s, k, v) => { stores[s].set(k, v); },
    del: async (s, k) => { stores[s].delete(k); },
    all: async (s) => [...stores[s].values()],
    clear: async (s) => { stores[s].clear(); },
  };
}
