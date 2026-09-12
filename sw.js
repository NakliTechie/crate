// SPDX-License-Identifier: AGPL-3.0-or-later
// Service worker: makes Crate installable and opens offline.
//
// What it caches: this origin's static files — the page, lib/, vendor,
// icons, the guide. What it never touches: bucket / carrier traffic
// (other origins) and anything that is not a GET. Ciphertext, manifests
// and credentials do not pass through here; the "last seen" folder for
// offline reads lives in IndexedDB (lib/offline.js), sealed as it came
// off the wire.
//
// Strategy: network first with a short timeout, then cache — so a
// deploy propagates on the next load while a dead network still opens
// the app. VERSION is bumped by the release step; activating a new
// version drops the old cache.

const VERSION = "crate-static-v1.2.0-dev";
const PRECACHE = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./guide/",
  "./guide/index.html",
  "./lib/anchor.js",
  "./lib/bucket.js",
  "./lib/clipboard.js",
  "./lib/crate.js",
  "./lib/cratejson.js",
  "./lib/credsfile.js",
  "./lib/crypto.js",
  "./lib/dialog.js",
  "./lib/entropy.js",
  "./lib/entrypoint.js",
  "./lib/export.js",
  "./lib/folder.js",
  "./lib/icons.js",
  "./lib/idb.js",
  "./lib/manifest-flush.js",
  "./lib/manifest.js",
  "./lib/offline.js",
  "./lib/onboarding.js",
  "./lib/passphrase.js",
  "./lib/qr.js",
  "./lib/recovery.js",
  "./lib/share.js",
  "./lib/shell.js",
  "./lib/sigv4.js",
  "./lib/sync-client.js",
  "./lib/vault.js",
  "./lib/wordlist.js",
  "./lib/read.js",
  "./lib/search.js",
  "./lib/vendor/client-zip/index.js",
  "./lib/vendor/zxcvbn-ts/core.umd.min.js",
  "./lib/vendor/zxcvbn-ts/language-common.umd.min.js",
  "./lib/vendor/zxcvbn-ts/language-en.umd.min.js",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/maskable-192.png",
  "./icons/maskable-512.png",
  "./icons/apple-touch-icon.png",
  "./icons/icon.svg",
];
const NETWORK_TIMEOUT_MS = 3500;

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    // Precache best-effort: one missing file must not block install.
    await Promise.all(PRECACHE.map(async (url) => {
      try { await cache.add(new Request(url, { cache: "reload" })); } catch (e) { /* skipped */ }
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key !== VERSION) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // bucket, carrier, fonts: not ours
  if (url.pathname.startsWith("/.claude/")) return;   // local dev scratch
  event.respondWith(networkFirst(req));
});

async function networkFirst(req) {
  const cache = await caches.open(VERSION);
  // Navigations resolve to the app shell whatever the path (the wizard
  // and share links live in the hash), so an offline start still opens.
  const key = req.mode === "navigate" ? new Request("./index.html") : req;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
    const res = await fetch(req, { signal: controller.signal });
    clearTimeout(timer);
    if (res.ok) cache.put(key, res.clone()).catch(() => {});
    return res;
  } catch (e) {
    const hit = await cache.match(key) || (req.mode === "navigate" ? await cache.match("./") : null);
    if (hit) return hit;
    throw e;
  }
}
