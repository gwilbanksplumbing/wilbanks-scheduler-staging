// cache-bust: 20260613-0700 wc-v283: fix empty-state Estimate row overlap on iPhone — added flex-wrap so the Create Estimate button wraps full-width below the label on narrow viewports (sm:grow-0 keeps it inline on wide). New JS index-2wR7gTIu.js, CSS index-DtCwdFQF.css.
const CACHE = "wc-v283";
// GitHub Pages serves this site under /wilbanks-scheduler-staging/ so plain
// "/" and "/index.html" 404. We try to precache them best-effort but DO NOT
// fail the install if they're unreachable. Without this, install rejection
// kept the previous SW active and stuck the PWA on an old bundle.
const OFFLINE = ["./", "./index.html"];
self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(c =>
      Promise.all(OFFLINE.map(u => c.add(u).catch(err => {
        try { console.warn("[sw] precache miss", u, err && err.message); } catch (_) {}
      })))
    )
  );
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  // wc-v270s: clone the response SYNCHRONOUSLY, before any await. The old code
  // called res.clone() inside the async caches.open(...).then() callback, by
  // which point the body returned to the page could already be consumed,
  // throwing "Failed to execute 'clone' on 'Response': Response body is already
  // used" on every cacheable request. Clone first, then stash the copy.
  e.respondWith(
    fetch(e.request).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
      return res;
    }).catch(() => caches.match(e.request))
  );
});
