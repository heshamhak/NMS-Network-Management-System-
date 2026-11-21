const CACHE_NAME = 'nms-console-v9';
const SHELL_ASSETS = [
  '/pro/index.html',
  '/pro/styles.css',
  '/pro/lab.css',
  '/pro/app.js',
  '/pro/noc-tools.js',
  '/pro/noc-search.js',
  '/pro/noc-topology.js',
  '/pro/netchart.js',
  '/pro/nms-i18n.js?v=9',
  '/pro/chart.umd.min.js',
  '/pro/manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.pathname.startsWith('/api') || url.pathname.startsWith('/cgi-bin')) {
    return;
  }
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(event.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});
