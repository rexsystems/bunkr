// Bunkr service worker: shows a contentless notification when a push wakes
// it. Pushes carry no data at all; message content never leaves the
// encrypted channel and this worker has no keys.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (wins.some((c) => c.visibilityState === "visible")) return;
    await self.registration.showNotification("Bunkr", {
      body: "You have new encrypted messages",
      icon: "icon-192.png",
      badge: "icon-192.png",
      tag: "bunkr",
      renotify: false,
    });
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of wins) { if ("focus" in c) return c.focus(); }
    return self.clients.openWindow("./");
  })());
});
