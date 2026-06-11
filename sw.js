// cache-bust: 20260611-1155 wc-v270v: fix appointment Edit hiding a stored end time. The Multi-Day/Multi-Hour toggle + its End Date/End Time fields were driven ONLY by editData.endDate, AND editData was never seeded with the record's endDate/endTime on entering edit mode. So a same-day record with only an endTime saved (e.g. appt #440, 1:00-4:00 PM) showed the toggle OFF with no End Time field, leaving the stored end invisible/uneditable - and a Save could drop it. Now: (1) edit state seeds endDate/endTime from the record; (2) the toggle + fields key off endDate OR endTime. New JS index-CQ7w5eih.js (CSS index-D4OTVTTE.css unchanged).
const CACHE = "wc-v270v";
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
