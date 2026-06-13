// cache-bust: 20260613-1330 wc-v290: SINGLE INVOICE DOOR. Removed every invoice create/send door outside Ready-to-Invoice. Card: no create (v289), View + Resend only once an invoice exists. Builder: removed Plumbing Convert-to-Invoice link, HVAC Send-Invoice link on Saved Estimates row, and the editor Preview Invoice / Send Invoice buttons. Builder is now estimate-only (Save/Update + Preview & Send estimate). Invoices minted ONLY via Ready-to-Invoice. New JS index-Cm6ju20R.js, CSS index-DtCwdFQF.css.
const CACHE = "wc-v290";
// GitHub Pages serves this site under /wilbanks-scheduler-staging/ so plain
// "/" and "/index.html" 404. We try to precache them best-effort but DO NOT
// fail the install if they're unreachable. Without this, install rejection
// kept the previous SW active and stuck the PWA on an old bundle.
const OFFLINE = ["./", "./index.html"];
self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(c =>
      Promise.all(OFFLINE.map(u => c.add(u).catch(err => {
        try { console.warn("[sw] precache miss", u, err && err.message); } catch (_) {}
      })))
    )
  );
  self.skipWaiting();
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  // wc-v270s: clone the response SYNCHRONOUSLY, before any await. The old code
  // called res.clone() inside the async caches.open(...).then() callback, by
  // which point the body returned to the page could already be consumed,
  // throwing "Failed to execute 'clone' on 'Response': Response body is already
  // used" on every cacheable request. Clone first, then stash the copy.
  e.respondWith(
    fetch(e.request).then(res => {
      const copy = res.clone();
      caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
      return res;
    }).catch(() => caches.match(e.request))
  );
});
