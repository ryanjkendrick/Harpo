// Harpo service worker.
//
// Deliberately conservative: it pre-caches ONLY the static offline-vault shell
// and PWA assets. It never caches authenticated pages, API responses, or
// anything else — the online app always talks straight to the server. When a
// navigation fails because the server is unreachable, it serves the offline
// vault page instead.
// Bump this version whenever offline.html/offline.js or the PWA assets change —
// it is what makes installed service workers refresh their cached shell.
const CACHE = "harpo-v3";
const PRECACHE = [
    "/offline.html",
    "/offline.js",
    "/manifest.webmanifest",
    "/icons/harpo-192.png",
    "/icons/harpo-512.png",
    "/icons/harpo-180.png",
    "/icons/harpo-maskable-512.png",
];

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
    );
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET") {
        return;
    }
    const url = new URL(request.url);
    if (url.origin !== self.location.origin) {
        return;
    }

    // Static shell assets: cache-first (refreshed by bumping CACHE version).
    if (PRECACHE.includes(url.pathname)) {
        event.respondWith(
            caches.match(url.pathname).then((cached) => cached || fetch(request))
        );
        return;
    }

    // Page navigations: network-first, offline vault as the fallback.
    // The network response is never cached (it may contain vault data).
    if (request.mode === "navigate") {
        event.respondWith(
            fetch(request).catch(() => caches.match("/offline.html"))
        );
    }
    // Everything else (APIs, SignalR negotiate, fingerprinted assets): untouched.
});
