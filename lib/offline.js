// SPDX-License-Identifier: AGPL-3.0-or-later
// Last-seen folder for offline opens.
//
// Every successful fetch of .crate/crate.json and the manifest is copied
// here, keyed by bucket base, exactly as it arrived — sealed. With no
// network, Crate.open falls back to these bytes: the passphrase still
// unwraps the key, the manifest still verifies, the folder lists as last
// seen. Reads and writes need the bucket, so the session is marked
// offline and the folder says so. Nothing here is more sensitive than
// what the bucket already holds; it is cleared on Lock.

import * as idb from "./idb.js";

const STORE = "offline";

export async function remember(bucketBase, { crateJson, manifest, manifestETag } = {}) {
  try {
    const cur = (await idb.get(STORE, bucketBase)) || {};
    const next = { ...cur, ts: Date.now() };
    if (crateJson) next.crateJson = crateJson;
    if (manifest) { next.manifest = manifest; next.manifestETag = manifestETag || null; }
    await idb.set(STORE, bucketBase, next);
  } catch (e) {
    // IndexedDB unavailable (private mode, quota): offline opens are off.
  }
}

export async function recall(bucketBase) {
  try {
    const v = await idb.get(STORE, bucketBase);
    if (!v || !(v.crateJson instanceof Uint8Array) || !(v.manifest instanceof Uint8Array)) return null;
    return v;
  } catch {
    return null;
  }
}

export async function forget(bucketBase) {
  try { await idb.del(STORE, bucketBase); } catch {}
}
