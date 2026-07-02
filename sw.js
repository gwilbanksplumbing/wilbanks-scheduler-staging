// cache-bust: 20260702-161500 wc-v302-pastdue-b staging: Invoice/Estimate preview modals now include Print button (iframe.contentWindow.print()). Invoice card gains "Send Past Due Notice" button (both HVAC and Plumbing branches) when invoice exists and isn't paid. Past-due opens the same HvacSendInvoiceFlow preview+send with pastDue=true — server renders amber Payment Reminder banner in preview HTML, uses PAST DUE subject line and QB TxnDate for original invoice date. Fix: qb-invoice-paid Gmail HTML now uses TxnDate (was Date.now()). bundle index-Dpastdue01.js / index-hvC_Rh4Z.css. auth-layer.js untouched.
const CACHE = "wc-v302-pastdue-b";
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
