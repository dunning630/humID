// Service worker for the installable web app. Caches only the app shell so HumID opens
// offline. Never caches /htp/*: vault traffic is always live, end-to-end encrypted, and must
// not sit in a cache.
//
// 3.0: every file under /assets/ has a content hash in its name, so those are cache-first
// and kept until the next release's worker activates; the shell (/, index.html, sw.js,
// the manifest) is always fetched fresh, so a new release is picked up on the next open.
const VERSION = "__HUMID_VERSION__";
const SHELL = __HUMID_SHELL__;

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: "no-cache" })))).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || url.pathname.startsWith("/htp/") || url.pathname.startsWith("/tlog/") || e.request.method !== "GET") return;
  const hashed = url.pathname.startsWith("/assets/");
  if (hashed) {
    // immutable: serve from the cache, fetch once, keep it
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(e.request, copy)); }
      return res;
    })));
    return;
  }
  // the shell: network first (fresh), the cached copy when offline
  e.respondWith(fetch(new Request(e.request, { cache: "no-cache" })).then((res) => {
    if (res.ok && SHELL.includes(url.pathname)) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(e.request, copy)); }
    return res;
  }).catch(() => caches.match(e.request).then((r) => r || caches.match("/"))));
});
