// SPDX-License-Identifier: AGPL-3.0-or-later
// Trash with retention: a delete keeps the object and moves the entry to
// the trash side of the manifest; restore is a plain create with the same
// uuid (every reader understands it); purge drops it for good. Unknown
// ops stay ignored by the tree, so a v1.1.0 reader sees the same folder.

import assert from "node:assert/strict";
import { Manifest, createEvent, deleteEvent, purgeEvent, restoreEvent, moveEvent } from "../lib/manifest.js";

const key = new Uint8Array(32).fill(7);
const m = new Manifest();
const mk = (uuid, path) => createEvent({ uuid, path, size: 10, mime: "text/plain", dataKeyIv: new Uint8Array(12), dataKeyCt: new Uint8Array(48), contentIv: new Uint8Array(12), chunkSize: 8 << 20 });
await m.append(mk("u1", "/a.txt"), key);
await m.append(mk("u2", "/b.txt"), key);
await m.append(moveEvent({ uuid: "u2", newPath: "/docs/b.txt" }), key);
await m.append(deleteEvent({ uuid: "u2" }), key);

// tree hides it; trash shows it with the path at deletion time and the keys
assert.deepEqual([...m.materialise().keys()].sort(), ["/a.txt"]);
let t = m.materialiseTrash();
assert.deepEqual([...t.keys()], ["u2"]);
assert.equal(t.get("u2").path, "/docs/b.txt");
assert.equal(typeof t.get("u2").deleted_ts, "number");
assert.equal(t.get("u2").chunk_size, 8 << 20);

// restore = create with the same uuid; both sides agree
await m.append(restoreEvent(t.get("u2")), key);
assert.deepEqual([...m.materialise().keys()].sort(), ["/a.txt", "/docs/b.txt"]);
assert.equal(m.materialise().get("/docs/b.txt").uuid, "u2");
assert.equal(m.materialiseTrash().size, 0);

// restore to a new path when the old one is taken
await m.append(deleteEvent({ uuid: "u2" }), key);
await m.append(mk("u3", "/docs/b.txt"), key);
await m.append(restoreEvent(m.materialiseTrash().get("u2"), "/docs/b (restored).txt"), key);
assert.equal(m.materialise().get("/docs/b (restored).txt").uuid, "u2");
assert.equal(m.materialise().get("/docs/b.txt").uuid, "u3");

// purge drops a trashed entry; the tree never saw it anyway
await m.append(deleteEvent({ uuid: "u1" }), key);
assert.equal(m.materialiseTrash().size, 1);
await m.append(purgeEvent({ uuid: "u1" }), key);
assert.equal(m.materialiseTrash().size, 0);
assert.deepEqual([...m.materialise().keys()].sort(), ["/docs/b (restored).txt", "/docs/b.txt"]);

// the chain still verifies with the new op in it, and survives a round trip
assert.equal((await m.verify(key)).ok, true);
const bytes = await m.encryptToBytes(key);
const back = await Manifest.loadFromBytes(bytes, key);
assert.equal(back.events.length, m.events.length);
assert.equal(back.materialiseTrash().size, 0);

// shape: purge without uuid is refused on append
await assert.rejects(m.append({ op: "purge" }, key), /requires string uuid/);

console.log("OK: trash — delete keeps metadata, restore is a create, purge drops it, chain verifies");
