// cache-bust: 20260702-173500 wc-v305-thresh-all staging: Settings Billing dropdown adds "All" option (value=1) so outstanding tile shows every sent-but-unpaid invoice regardless of age. Server whitelist ALLOWED_THRESHOLDS=[1,15,30,45,60,90,120] on GET+PUT. Outstanding pill and drawer header render "All" instead of "1d+" when threshold=1. bundle index-Dpastdue04.js.
const CACHE = "wc-v305-thresh-all";
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
