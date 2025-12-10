const CACHE_NAME = 'zeno-gas-v1.0.1';
const APP_PREFIX = 'ZENO_';

// Assets to cache immediately
const STATIC_ASSETS = [
  '/',
  '/static/js/bundle.js',
  '/static/css/main.css',
  '/site.webmanifest',
  '/favicon.ico',
  '/favicon-96x96.png',
  '/favicon.svg',
  '/apple-touch-icon.png',
  '/android-chrome-192x192.png',
  '/android-chrome-512x512.png',
  '/web-app-manifest-192x192.png',
  '/web-app-manifest-512x512.png'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log(`${APP_PREFIX} Service Worker: Installing...`);
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log(`${APP_PREFIX} Service Worker: Caching static assets`);
        return cache.addAll(STATIC_ASSETS.map(url => new Request(url, { credentials: 'same-origin' })));
      })
      .then(() => {
        console.log(`${APP_PREFIX} Service Worker: Installation complete`);
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error(`${APP_PREFIX} Service Worker: Installation failed:`, error);
      })
  );
});

// Activate event - cleanup old caches
self.addEventListener('activate', (event) => {
  console.log(`${APP_PREFIX} Service Worker: Activating...`);
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log(`${APP_PREFIX} Service Worker: Deleting old cache:`, cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      console.log(`${APP_PREFIX} Service Worker: Activation complete`);
      return self.clients.claim();
    })
  );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then((cachedResponse) => {
        // Return cached version if available
        if (cachedResponse) {
          return cachedResponse;
        }

        // Otherwise fetch from network
        return fetch(event.request)
          .then((networkResponse) => {
            // Check if we received a valid response
            if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
              return networkResponse;
            }

            // Clone the response before using it
            const responseToCache = networkResponse.clone();

            // Cache the new response
            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(event.request, responseToCache);
              });

            return networkResponse;
          })
          .catch((error) => {
            console.error(`${APP_PREFIX} Fetch failed:`, error);
            
            // If both cache and network fail, return offline response
            if (event.request.destination === 'document') {
              return caches.match('/offline.html');
            }
            
            // For images, return a placeholder
            if (event.request.destination === 'image') {
              return new Response(
                '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="#f3f4f6"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="14" fill="#9ca3af">Image not available</text></svg>',
                { 
                  headers: { 
                    'Content-Type': 'image/svg+xml',
                    'Cache-Control': 'no-cache'
                  } 
                }
              );
            }
          });
      })
  );
});

// Background sync for offline actions
self.addEventListener('sync', (event) => {
  if (event.tag === 'zeno-background-sync') {
    console.log(`${APP_PREFIX} Service Worker: Background sync triggered`);
    event.waitUntil(doBackgroundSync());
  }
});

async function doBackgroundSync() {
  try {
    const pendingData = await getPendingActions();
    console.log(`${APP_PREFIX} Syncing ${pendingData.length} pending actions`);
    
    for (const action of pendingData) {
      await syncAction(action);
    }
  } catch (error) {
    console.error(`${APP_PREFIX} Background sync failed:`, error);
  }
}

// Utility functions
async function getPendingActions() {
  return JSON.parse(localStorage.getItem('zeno-pending-actions') || '[]');
}

async function syncAction(action) {
  try {
    const response = await fetch(action.url, {
      method: action.method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(action.data)
    });
    
    if (response.ok) {
      const pendingActions = await getPendingActions();
      const updatedActions = pendingActions.filter(a => a.id !== action.id);
      localStorage.setItem('zeno-pending-actions', JSON.stringify(updatedActions));
    }
  } catch (error) {
    console.error(`${APP_PREFIX} Sync action failed:`, error);
  }
}