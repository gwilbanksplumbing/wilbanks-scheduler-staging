// cache-bust: wc-staging-spanoverride-edit-20260727-190500 staging: EDIT screen now sends spanOverride too, so editing an appt to 8:00 AM-12:00 PM saves the full span instead of re-clamping to 2h. bundle index-CupxxRJi.js.
const CACHE = "wc-staging-spanoverride-edit-20260727-190500";
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
