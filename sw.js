// cache-bust: 20260619-174400 wc-v299-addnew staging: New Job customer search now always shows a "+ Add a new customer" row at the bottom of the results list (not only on zero matches), so a person who is a commercial bill-to (e.g. Tommy Pratt under Gardner Landscaping) can still be added as their own customer. Opens the Residential/Commercial type popup and pre-fills the typed text (person name for residential, company name for commercial). Plus prior wc-v298 New Contact type picker + wc-v297 commercial-first card ordering. bundle index-UKGB5QQ0.js / index-hvC_Rh4Z.css. auth-layer.js untouched.
const CACHE = "wc-v299-addnew";
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
