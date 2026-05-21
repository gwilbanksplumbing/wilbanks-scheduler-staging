// STAGING build — combined offline cache + push notification SW
const CACHE = "wc-v89";
const OFFLINE = ["/", "/index.html"];

const BADGE_KEY = "wilbanks_badge_count";

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(OFFLINE)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== "wilbanks-badge").map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/") || e.request.url.includes("/uploads/")) return;
  e.respondWith(
    fetch(e.request).then(res => { caches.open(CACHE).then(c => c.put(e.request, res.clone())); return res; })
      .catch(() => caches.match(e.request))
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
