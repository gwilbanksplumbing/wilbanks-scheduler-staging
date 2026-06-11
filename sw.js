// cache-bust: 20260610-2125 wc-v270n: Multi-tenant / SaaS prep refactor. ASSETS_PUBLIC_URL in src/lib/techAvatar.ts is now a build-time config (VITE_ASSETS_PUBLIC_URL) with assets.wilbankscompany.com as the fallback, so the asset host is a one-line flip when the platform brand domain is registered. Tenancy stays in the object PATH (tenants/{slug}/...), host is platform-shared. ZERO behavior change: the built bundle is byte-identical to wc-v270m (same JS index-BQvWtoWJ.js / CSS index-D4OTVTTE.css md5), so pin faces and all avatars are unaffected. SW version bumped only to keep the milestone marker in sync across repos.
const CACHE = "wc-v270n";
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
