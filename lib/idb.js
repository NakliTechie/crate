// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal promise-wrapped IndexedDB helper. One database (`crate-session`)
// with two stores: `prefs` (UI preferences) and `onboarding` (in-flight
// wizard state minus secrets — passphrase never touches disk).
//
// Additional stores get added in `openDB()`'s upgrade callback as new
// modules need them.

const DB_NAME = "crate-session";
// v2: added `anchors` store for manifest rollback-detection state. See
// lib/anchor.js + 2026-05 security audit, finding H2.
const DB_VERSION = 2;
const STORES = ["prefs", "onboarding", "anchors"];

let _dbPromise = null;

function openDB() {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      for (const name of STORES) {
        if (!db.objectStoreNames.contains(name)) {
          db.createObjectStore(name);
        }
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return _dbPromise;
}

function transact(storeName, mode) {
  return openDB().then((db) => db.transaction(storeName, mode).objectStore(storeName));
}

function asPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function get(storeName, key) {
  const store = await transact(storeName, "readonly");
  return asPromise(store.get(key));
}

export async function set(storeName, key, value) {
  const store = await transact(storeName, "readwrite");
  return asPromise(store.put(value, key));
}

export async function del(storeName, key) {
  const store = await transact(storeName, "readwrite");
  return asPromise(store.delete(key));
}

export async function clearStore(storeName) {
  const store = await transact(storeName, "readwrite");
  return asPromise(store.clear());
}
