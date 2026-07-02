// cache-bust: 20260702-172100 wc-v304-pastdue-drawer staging: Outstanding drawer gets Send Past Due Invoice button next to Record Payment. Both pills restyled: transparent bg + subtle border + white text → solid blue on hover. past_due_sent_at persisted server-side (SQLite column + /api/outstanding-invoices returns it + /send-gmail stamps NOW() on pastDue). Row shows Past due sent: MMM D, h:mm A when timestamp exists. bundle index-Dpastdue03.js / index-WxGDSTn6.css.
const CACHE = "wc-v304-pastdue-drawer";
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
