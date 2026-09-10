// SPDX-License-Identifier: AGPL-3.0-or-later
// chunk_size is carried through the signed manifest: present on v2
// entries, absent on v1, per-version on update, validated on load.

import assert from "node:assert/strict";

import { Manifest, ManifestError, createEvent, updateEvent } from "../lib/manifest.js";
import { randomIV, randomDataKey } from "../lib/crypto.js";

const masterKey = crypto.getRandomValues(new Uint8Array(32));
const base = { dataKeyIv: randomIV(), dataKeyCt: randomDataKey() };

// v1 event stays byte-identical: no chunk_size key at all
assert.equal("chunk_size" in createEvent({ uuid: "A", path: "/a", size: 1, contentIv: randomIV(), ...base }), false);
assert.equal("chunk_size" in updateEvent({ uuid: "A", size: 1, contentIv: randomIV() }), false);

const m = new Manifest();
await m.append(createEvent({ uuid: "V2", path: "/big.bin", size: 10, contentIv: randomIV(), chunkSize: 8, ...base }), masterKey);
await m.append(createEvent({ uuid: "V1", path: "/old.bin", size: 10, contentIv: randomIV(), ...base }), masterKey);

const loaded = await Manifest.loadFromBytes(await m.encryptToBytes(masterKey), masterKey);
let tree = loaded.materialise();
assert.equal(tree.get("/big.bin").chunk_size, 8, "v2 entry carries chunk_size after sign→seal→load");
assert.equal(tree.get("/old.bin").chunk_size, undefined, "v1 entry has none");

// update is per-version: a v1 writer's update clears it; a v2 update sets it
await loaded.append(updateEvent({ uuid: "V2", size: 12, contentIv: randomIV() }), masterKey);
await loaded.append(updateEvent({ uuid: "V1", size: 12, contentIv: randomIV(), chunkSize: 4 }), masterKey);
tree = loaded.materialise();
assert.equal(tree.get("/big.bin").chunk_size, undefined, "update without chunk_size reverts entry to v1");
assert.equal(tree.get("/old.bin").chunk_size, 4, "update with chunk_size promotes entry to v2");

// shape validation runs on append (writer) and on load (reader); an
// invalid chunk_size is rejected at the first gate it meets
for (const bad of [0, -1, 1.5, "8"]) {
  const t = new Manifest();
  await assert.rejects(
    t.append(createEvent({ uuid: "X", path: "/x", size: 1, contentIv: randomIV(), chunkSize: bad, ...base }), masterKey),
    (e) => e instanceof ManifestError && /chunk_size must be a positive integer/.test(e.message),
    `chunk_size=${JSON.stringify(bad)} rejected at append`,
  );
}
// …and a reader still rejects it if a same-key writer bypassed append
{
  const t = new Manifest();
  await t.append(createEvent({ uuid: "X", path: "/x", size: 1, contentIv: randomIV(), chunkSize: 8, ...base }), masterKey);
  const sealed = await Manifest.loadFromBytes(await t.encryptToBytes(masterKey), masterKey);
  sealed.events[0].chunk_size = 0; // tamper post-sign: sig now mismatches too
  await assert.rejects(
    Manifest.loadFromBytes(await sealed.encryptToBytes(masterKey), masterKey),
    (e) => e instanceof ManifestError,
    "tampered chunk_size rejected on load",
  );
}

console.log("OK: manifest carries chunk_size per version and validates it");
