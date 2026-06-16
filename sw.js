// cache-bust: 20260614-160709 wc-prod-v4 prod promote: bundle index-ClK6eIvb.js / index-hvC_Rh4Z.css (from index-CoRKHDaa.js). auth-layer.js untouched.
const CACHE = "wc-prod-v4";
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
