// cache-bust: 20260619-181500 wc-v300-invoicefix staging: Convert to Invoice no longer dead-ends when an invoice already exists. If a prior attempt created the QB invoice but the QB tab was popup-blocked, retrying now opens the EXISTING invoice (via /api/qb-invoice-detail) instead of showing a dead-end "invoice_already_exists" error — no duplicate is ever created. The normal success path also attaches a clickable "Open in QuickBooks" toast action so a blocked auto-popup is never a dead end. bundle index-DUZIRd95.js / index-hvC_Rh4Z.css. auth-layer.js untouched.
const CACHE = "wc-v300-invoicefix";
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
