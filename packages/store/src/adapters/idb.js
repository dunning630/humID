// IndexedDB backend. Every webview HumID ships in (WKWebView, WebView2,
// WebKitGTK, Android WebView) persists IndexedDB in the app's data directory.
// Database layout matches the original web app: "humid" v1, stores
// "identity" (out-of-line key) and "vault" (keyPath "id").

export async function idbBackend() {
  const db = await new Promise((resolve) => {
    try {
      const req = indexedDB.open("humid", 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("identity");
        req.result.createObjectStore("vault", { keyPath: "id" });
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
