// cache-bust: 20260619-182400 wc-v301-invrelink staging: Convert to Invoice now self-heals when the QB invoice already exists. On invoice_already_exists, the app calls POST /api/qb-invoice-relink to resolve the existing QB invoice by its number, stamp the full QB linkage + status back onto the appointment (so the job leaves "Ready to Invoice"), and opens that exact invoice via a working "Open Invoice" toast link. No duplicate is ever created; the stuck job moves out of the list. Plus prior v300 popup-safe success toast. bundle index-Br4IR-yq.js / index-hvC_Rh4Z.css. auth-layer.js untouched.
const CACHE = "wc-v301-invrelink";
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
