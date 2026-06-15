const CACHE_NAME = 'moc-v1';

self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('fetch', event => {
  event.respondWith(fetch(event.request));
});

self.addEventListener('activate', event => {
  event.waitUntil(clients.claim());
});