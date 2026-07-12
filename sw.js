// cache-bust: 20260712-222749 wc-staging-bookhours-20260712-222749 staging: Bookable-hours enforcement — calendar grid + New Job time picker obey Settings business_hours_start/end; out-of-window start slots hidden/disabled. Server guard already live. bundle index-DhWGYFdY.js.
const CACHE = "wc-staging-bookhours-20260712-222749";
const OFFLINE = ["/", "/index.html"];
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(OFFLINE)));
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  e.respondWith(
    fetch(e.request).then(res => { caches.open(CACHE).then(c => c.put(e.request, res.clone())); return res; })
      .catch(() => caches.match(e.request))
  );
});
