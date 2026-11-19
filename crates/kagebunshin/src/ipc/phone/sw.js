// The approval page's service worker: it shows the notification the
// daemon sends when a request starts waiting, and opens the page on that
// request when the notification is tapped. It keeps nothing and serves
// nothing: the page works only while the computer answers.
'use strict';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let said = {};
  try { said = e.data.json(); } catch { /* not one of ours: said plainly below */ }
  const id = Number.isSafeInteger(said.id) ? said.id : null;
  e.waitUntil(self.registration.showNotification(String(said.title || 'A command asks for sensitive values'), {
    body: String(said.body || 'It waits for you to approve or deny it.'),
    // One notification for each request.
    tag: id === null ? 'request' : `request-${id}`,
    data: { id },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const id = e.notification.data && e.notification.data.id;
  const url = Number.isSafeInteger(id) ? `/?req=${id}` : '/';
  e.waitUntil((async () => {
    const open = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const page of open) {
      try { await page.navigate(url); return await page.focus(); } catch { /* not this worker's to steer: opened below */ }
    }
    return self.clients.openWindow(url);
  })());
});
