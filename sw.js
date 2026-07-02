// cache-bust: 20260702-170000 wc-v303-pastdue-btns staging: Invoice-row buttons unified to variant=outline (transparent bg, white text, subtle border) with hover:bg-blue-600 hover:text-white hover:border-blue-600. Removes solid green Resend Invoice and amber Send Past Due Notice — all three invoice-row buttons (View Invoice, Resend Invoice, Send Past Due Notice; Plumbing gets View Invoice, Resend via QuickBooks, Send Past Due Notice) now share the neutral outline style with blue hover. Icons kept. Prior v302: Print button in preview modals + past-due preview+send flow + QB TxnDate rendering. bundle index-Dpastdue02.js / index-WxGDSTn6.css. auth-layer.js untouched.
const CACHE = "wc-v303-pastdue-btns";
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
