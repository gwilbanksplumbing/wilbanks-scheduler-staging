// cache-bust: 20260526-162938
// STAGING build — separate cache namespace
// Wilbanks Company — Push Notification Service Worker
const BADGE_KEY = "wilbanks_badge_count";

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

  const title = data.title || "Wilbanks Company";
  const options = {
    body: data.body || "",
    icon: "/wilbanks-scheduler/apple-touch-icon.png",
    badge: "/wilbanks-scheduler/icon-192.png",
    tag: data.appointmentId ? `appt-${data.appointmentId}` : "wilbanks-notification",
    requireInteraction: true,
    data: { appointmentId: data.appointmentId },
  };

  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const newCount = count + 1;
      await setBadgeCount(newCount);
      return self.registration.showNotification(title, options);
    })
  );
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  // Clear badge when user taps the notification
  event.waitUntil(
    getBadgeCount().then(async (count) => {
      const notifications = await self.registration.getNotifications();
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
          return clients.openWindow("https://gwilbanksplumbing.github.io/wilbanks-scheduler/");
        }
      });
    })
  );
});
