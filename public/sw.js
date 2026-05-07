// ClawGuard Web Push service worker.
// Receives approval requests pushed by the gateway and surfaces them as
// native OS notifications. Action buttons call back into ClawGuard with a
// signed token so we don't need PIN auth from the SW context.

const RESPOND_URL = '/__admin/api/webpush/respond';
const DASHBOARD_URL = '/__admin/';

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  if (!event.data) return;

  let payload;
  try {
    payload = event.data.json();
  } catch (err) {
    return;
  }

  if (payload.kind === 'cancel' && payload.requestId) {
    event.waitUntil(closeNotificationsForRequest(payload.requestId));
    return;
  }

  if (payload.kind !== 'approval' || !payload.requestId) return;

  const title = `ClawGuard: ${payload.method} ${payload.service}`;
  const body = `${payload.path}\nfrom ${payload.agentIp}`;

  // macOS Safari supports up to 2 actions reliably; we keep the most useful pair
  // and let the user open the dashboard for richer choices.
  const actions = [
    { action: 'approve_1h', title: '✅ Approve 1h' },
    { action: 'deny',       title: '❌ Deny' },
  ];

  const options = {
    body,
    tag: `clawguard:${payload.requestId}`,   // collapses repeat pushes for the same request
    renotify: true,
    requireInteraction: payload.requireInteraction !== false,
    actions,
    data: {
      requestId: payload.requestId,
      actions: payload.actions, // signed HMAC tokens, one per action name
      service: payload.service,
      method: payload.method,
      path: payload.path,
    },
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  const data = event.notification.data || {};
  const action = event.action;

  event.notification.close();

  if (!action) {
    // Body click — just open the dashboard so the user can approve manually
    event.waitUntil(focusOrOpen(DASHBOARD_URL));
    return;
  }

  if (!data.requestId || !data.actions || !data.actions[action]) {
    return;
  }

  event.waitUntil(
    fetch(RESPOND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requestId: data.requestId,
        action,
        signature: data.actions[action],
      }),
    })
      .then((res) => res.ok ? null : res.text().then((t) => { throw new Error(t); }))
      .catch((err) => {
        // Tell any open dashboard tab so it can show the error
        return broadcast({ type: 'webpush-error', message: String(err && err.message || err) });
      })
  );
});

async function closeNotificationsForRequest(requestId) {
  const tag = `clawguard:${requestId}`;
  const notifs = await self.registration.getNotifications({ tag });
  for (const n of notifs) n.close();
}

async function focusOrOpen(url) {
  const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of allClients) {
    if (c.url.includes('/__admin') && 'focus' in c) {
      return c.focus();
    }
  }
  if (self.clients.openWindow) return self.clients.openWindow(url);
}

async function broadcast(message) {
  const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of allClients) c.postMessage(message);
}
