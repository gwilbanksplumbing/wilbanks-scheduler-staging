// cache-bust: 20260619-171700 wc-v298-custtype staging: New Contact form now has a required Residential/Commercial type picker. Commercial = company name is primary identity (required, top) + contact/bill-to person below (required); residential = person name is identity source. Sends explicit customer_type so the server scopes the duplicate check by type (a commercial bill-to can also exist as their own residential customer). Plus prior wc-v297 commercial-first card ordering. bundle index-CZXHMJLP.js / index-hvC_Rh4Z.css. auth-layer.js untouched.
const CACHE = "wc-v298-custtype";
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
