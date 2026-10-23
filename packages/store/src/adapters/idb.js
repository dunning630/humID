// IndexedDB backend. Every webview HumID ships in (WKWebView, WebView2,
// WebKitGTK, Android WebView) persists IndexedDB in the app's data directory.
// Database layout: "humid" v3, stores "identity" (out-of-line key), "vault"
// (keyPath "id"), "wallet" (v2: an access pass not yet spent; kept apart
// from "identity" so erasing an identity never throws away a paid-for pass),
// and "msg" (v3, HumID 4.0 messaging: sealed contact list, sealed conversations,
// ciphertext waiting to be read; keyPath "id").

export async function idbBackend() {
  const db = await new Promise((resolve) => {
    try {
      const req = indexedDB.open("humid", 3);
      req.onupgradeneeded = () => {
        const have = req.result.objectStoreNames;
        if (!have.contains("identity")) req.result.createObjectStore("identity");
        if (!have.contains("vault")) req.result.createObjectStore("vault", { keyPath: "id" });
        if (!have.contains("wallet")) req.result.createObjectStore("wallet");
        if (!have.contains("msg")) req.result.createObjectStore("msg", { keyPath: "id" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
  if (!db) return null;

  const run = (store, mode, fn) => new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const req = fn(tx.objectStore(store));
    tx.oncomplete = () => resolve(req?.result);
    tx.onerror = () => reject(tx.error);
  });

  return {
    persistent: true,
    get: (s, k) => run(s, "readonly", (o) => o.get(k)),
    put: (s, k, v) => run(s, "readwrite", (o) => (o.keyPath ? o.put(v) : o.put(v, k))),
    del: (s, k) => run(s, "readwrite", (o) => o.delete(k)),
    all: (s) => run(s, "readonly", (o) => o.getAll()).then((r) => r || []),
    clear: (s) => run(s, "readwrite", (o) => o.clear()),
  };
}
