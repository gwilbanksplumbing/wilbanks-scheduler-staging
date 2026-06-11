// cache-bust: 20260611-0907 wc-v270q: CRASH FIX. Dashboard List view + global search crashed the whole app ("Something went wrong / Cannot read properties of null (reading 'replace')") when any appointment had a null field (customer_phone especially). The globalSearchResults filter called a.customerPhone.replace(...) and other raw .toLowerCase()/.includes() on fields that can be null in the DB, throwing outside the list's local error boundary so it escaped to the app-root boundary. Now every raw appointment field in both the globalSearchResults filter/sort and the list-view filteredActive search is null-coalesced (?? ""). New JS index-iv6_S_-5.js (CSS index-D4OTVTTE.css unchanged).
const CACHE = "wc-v270q";
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
  e.respondWith(
    fetch(e.request).then(res => { caches.open(CACHE).then(c => c.put(e.request, res.clone())); return res; })
      .catch(() => caches.match(e.request))
  );
});
