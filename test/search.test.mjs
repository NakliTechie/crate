// SPDX-License-Identifier: AGPL-3.0-or-later
// Search inside files: tokeniser, candidate selection, incremental build
// over an in-memory bucket, ranking, staleness. IndexedDB is absent in
// node, so persistence is exercised through an in-memory idb shim.

import assert from "node:assert/strict";
import * as cryptoLib from "../lib/crypto.js";
import { Manifest, createEvent, deleteEvent, updateEvent } from "../lib/manifest.js";

// shim IndexedDB-backed helpers before importing search.js
const mem = new Map();
// lib/idb.js opens IndexedDB lazily; a minimal fake gives it a store.
globalThis.indexedDB = {
  open() {
    const req = {};
    setTimeout(() => {
      const db = {
        objectStoreNames: { contains: () => true },
        transaction: (name) => ({ objectStore: () => ({
          get: (k) => { const r = {}; setTimeout(() => { r.result = mem.get(name + ":" + k); r.onsuccess?.(); }, 0); return r; },
          put: (v, k) => { const r = {}; setTimeout(() => { mem.set(name + ":" + k, v); r.onsuccess?.(); }, 0); return r; },
          delete: (k) => { const r = {}; setTimeout(() => { mem.delete(name + ":" + k); r.onsuccess?.(); }, 0); return r; },
          clear: () => { const r = {}; setTimeout(() => { mem.clear(); r.onsuccess?.(); }, 0); return r; },
        }) }),
      };
      req.result = db; req.onsuccess?.();
    }, 0);
    return req;
  },
};
const search = await import("../lib/search.js");

assert.deepEqual([...search.tokenise("Invoice #2026 — paid, PAID; o'clock")].sort(), ["2026", "invoice", "o'clock", "paid"]);

// an owner session with three files on an in-memory bucket
const masterKey = cryptoLib.randomBytes(32);
const store = new Map();
globalThis.fetch = async (url) => { const hit = store.get(String(url)); return hit ? new Response(hit, { status: 200 }) : new Response("", { status: 404 }); };
const m = new Manifest();
const base = "https://acct.r2.cloudflarestorage.com/bkt/";
async function put(path, text, mime = "text/plain") {
  const uuid = "01H" + path.replace(/[^A-Z0-9]/gi, "").toUpperCase().padEnd(23, "0").slice(0, 23);
  const dk = cryptoLib.randomBytes(32);
  const sealed = await cryptoLib.sealObject(dk, new TextEncoder().encode(text), uuid, 1024);
  const w = await cryptoLib.wrapDataKey(masterKey, dk, uuid);
  store.set(base + "objects/" + uuid, sealed.body);
  await m.append(createEvent({ uuid, path, size: text.length, mime, dataKeyIv: w.iv, dataKeyCt: w.ciphertext, contentIv: sealed.body.subarray(0, 12), chunkSize: 1024 }), masterKey);
  return uuid;
}
await put("/notes/invoice-march.md", "Invoice for March: paid in full, thanks Priya");
await put("/notes/todo.txt", "buy milk\ncall the plumber about the invoice");
const img = await put("/photo.jpg", "binarybinary", "image/jpeg");
const session = { bucketBase: base, region: "auto", accessKey: "A", secretKey: "s", masterKey, manifest: m };

assert.equal(search.candidates(m).length, 2, "images are not text candidates");
assert.equal(await search.loadIndex(session), null);
assert.equal(search.staleCount(null, m), 2);

const progress = [];
const idx = await search.buildIndex(session, { onProgress: (p) => progress.push(p.done) });
assert.deepEqual(progress, [1, 2]);
assert.equal(Object.keys(idx.files).length, 2);
assert.equal(search.staleCount(idx, m), 0);

// every word must match; prefix matching; exact beats prefix
assert.deepEqual(search.queryIndex(idx, "invoice").map((h) => h.path).sort(), ["/notes/invoice-march.md", "/notes/todo.txt"]);
assert.deepEqual(search.queryIndex(idx, "invoice priya").map((h) => h.path), ["/notes/invoice-march.md"]);
assert.deepEqual(search.queryIndex(idx, "plumb").map((h) => h.path), ["/notes/todo.txt"]);
assert.deepEqual(search.queryIndex(idx, "nothinghere"), []);
assert.ok(search.queryIndex(idx, "invoice")[0].snippet.length > 0);

// persisted encrypted; loads back with the key, not without
const loaded = await search.loadIndex(session);
assert.equal(Object.keys(loaded.files).length, 2);
const stored = [...mem.values()][0];
assert.ok(stored.ct instanceof Uint8Array && !new TextDecoder().decode(stored.ct).includes("invoice"));
assert.equal(await search.loadIndex({ ...session, masterKey: cryptoLib.randomBytes(32) }), null);

// incremental: a changed file is re-read, an unchanged one is not; a deleted one drops
const todoUuid = "01H" + "/notes/todo.txt".replace(/[^A-Z0-9]/gi, "").toUpperCase().padEnd(23, "0").slice(0, 23);
const dk2 = cryptoLib.randomBytes(32);
const sealed2 = await cryptoLib.sealObject(dk2, new TextEncoder().encode("buy milk\nplumber came"), todoUuid, 1024);
const tree = m.materialise();
const todoEntry = tree.get("/notes/todo.txt");
// simulate Crate.write's update path: new data key + update event
const w2 = await cryptoLib.wrapDataKey(masterKey, dk2, todoUuid);
store.set(base + "objects/" + todoUuid, sealed2.body);
await m.append({ op: "create", uuid: todoUuid, path: "/notes/todo.txt", size: 21, mime: "text/plain", data_key_iv: cryptoLib.toBase64(w2.iv), data_key_ct: cryptoLib.toBase64(w2.ciphertext), content_iv: cryptoLib.toBase64(sealed2.body.subarray(0, 12)), chunk_size: 1024 }, masterKey);
await m.append(deleteEvent({ uuid: tree.get("/notes/invoice-march.md").uuid }), masterKey);
assert.equal(search.staleCount(loaded, m), 1);
const reads = [];
const origFetch = globalThis.fetch;
globalThis.fetch = async (url) => { reads.push(String(url)); return origFetch(url); };
const idx2 = await search.buildIndex(session, { previous: loaded });
assert.equal(reads.length, 1, "only the changed file was read");
assert.deepEqual(search.queryIndex(idx2, "invoice"), [], "deleted file and stale term are gone");
assert.deepEqual(search.queryIndex(idx2, "came").map((h) => h.path), ["/notes/todo.txt"]);

console.log("OK: search — tokenise, candidates, encrypted per-device index, ranking, incremental rebuild");
