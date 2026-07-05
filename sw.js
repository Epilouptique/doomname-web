// sw.js — Service Worker DoomName
// Doit être à la racine du projet

importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey:            "AIzaSyDRpPdZvAwL9LGFvgXZzsthJZL-7vwO5e4",
  authDomain:        "domainwatch-7da80.firebaseapp.com",
  projectId:         "domainwatch-7da80",
  storageBucket:     "domainwatch-7da80.firebasestorage.app",
  messagingSenderId: "427491746475",
  appId:             "1:427491746475:web:391c2d064a6cb024c94dee"
});

const messaging = firebase.messaging();

// Gère les notifications reçues en arrière-plan
messaging.onBackgroundMessage(function(payload) {
  console.log('[sw.js] Message reçu en arrière-plan:', payload);

  // Messages data-only : titre/corps sont dans payload.data
  // (repli sur payload.notification pour toute compatibilité).
  const data = payload.data || {};
  const notif = payload.notification || {};

  self.registration.showNotification(data.title || notif.title || 'DoomName', {
    body:  data.body || notif.body || 'Un domaine que vous surveillez est disponible !',
    icon:  notif.icon || '/icon-192.png',
    badge: '/icon-192.png',
    data:  data
  });
});

// Clic sur la notification → ouvre l'app
self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
      for (const client of clientList) {
        if (client.url === url && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
