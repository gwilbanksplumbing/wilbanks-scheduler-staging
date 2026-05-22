// STAGING build — combined offline cache + push notification SW
const CACHE = "wc-v97";
// Use scope-relative paths so this works at /wilbanks-scheduler-staging/preview-prodlike/
// NOT at site root. addAll() rejects install if any URL 404s.
// self.location.href is /wilbanks-scheduler-staging/preview-prodlike/sw.js
// strip the filename to get the scope directory.
const SCOPE_PATH = new URL("./", self.location.href).pathname;
const OFFLINE = [SCOPE_PATH, SCOPE_PATH + "index.html"];

const BADGE_KEY = "wilbanks_badge_count";

self.addEventListener("install", e => {
  // Don't let cache pre-population block activation. Cache opportunistically;
  // if it fails, log and proceed so the SW still becomes active for push.
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(OFFLINE))
      .catch(err => { console.warn("[sw] precache failed, continuing:", err); })
  );
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== "wilbanks-badge").map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  // Only cache GETs with successful, basic (same-origin) responses.
  if (e.request.method !== "GET") return;
  e.respondWith(
    fetch(e.request).then(res => {
      // Clone BEFORE returning — the original body can only be consumed once.
      try {
        if (res && res.ok && (res.type === "basic" || res.type === "cors")) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
        }
      } catch (_) { /* swallow */ }
      return res;
    }).catch(() => caches.match(e.request))
  );
});

// ── Push notifications (mirrors prod sw.js, staging icon paths) ─────────────

async function getBadgeCount() {
  const cache = await caches.open("wilbanks-badge");
  const resp = await cache.match(BADGE_KEY);
  if (!resp) return 0;
  const text = await resp.text();
  return parseInt(text) || 0;
}

async function setBadgeCount(n) {
  const cache = await caches.open("wilbanks-badge");
  await cache.put(BADGE_KEY, new Response(String(n)));
  if (navigator.setAppBadge) {
    if (n > 0) await navigator.setAppBadge(n);
    else await navigator.clearAppBadge();
  }
}

self.addEventListener("push", function (event) {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "Wilbanks Company", body: event.data ? event.data.text() : "" };
  }

  // Silent badge-reset push (sent when user clears notifications elsewhere).
  if (data && data.silent === true) {
    event.waitUntil(setBadgeCount(typeof data.badgeCount === "number" ? data.badgeCount : 0));
    return;
  }

  const title = data.title || "Wilbanks Company";
  const options = {
    body: data.body || "",
    icon: "/wilbanks-scheduler-staging/apple-touch-icon.png",
    badge: "/wilbanks-scheduler-staging/icon-192.png",
    tag: data.appointmentId ? `appt-${data.appointmentId}` : "wilbanks-notification",
    requireInteraction: true,
    data: { appointmentId: data.appointmentId },
  };

  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const newCount = typeof data.badgeCount === "number" ? data.badgeCount : count + 1;
      await setBadgeCount(newCount);
      return self.registration.showNotification(title, options);
    })
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const remaining = Math.max(0, count - 1);
      await setBadgeCount(remaining);
    }).then(() => {
      return clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (clientList) {
        for (const client of clientList) {
          if (client.url && "focus" in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow("https://gwilbanksplumbing.github.io/wilbanks-scheduler-staging/preview-prodlike/");
        }
      });
    })
  );
});
