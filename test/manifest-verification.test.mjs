// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";

import { Manifest, ManifestError } from "../lib/manifest.js";

const masterKey = crypto.getRandomValues(new Uint8Array(32));
const manifest = new Manifest();
await manifest.append({ op: "mkdir", path: "/safe/" }, masterKey);

const validBytes = await manifest.encryptToBytes(masterKey);
const loaded = await Manifest.loadFromBytes(validBytes, masterKey);
assert.equal(loaded.size(), 1, "a valid signed manifest should load");

// Model a same-key producer that changes an event and re-encrypts the
// manifest without updating its HMAC. The JSONL chain remains structurally
// valid, so loadFromBytes must inspect verify()'s result and fail closed.
manifest.events[0].path = "/tampered/";
const tamperedBytes = await manifest.encryptToBytes(masterKey);

await assert.rejects(
  Manifest.loadFromBytes(tamperedBytes, masterKey),
  (error) => (
    error instanceof ManifestError
    && /signature verification failed at event 0 \(sig mismatch\)/.test(error.message)
  ),
  "a manifest with an invalid event HMAC must be rejected",
);

console.log("OK: manifest signature verification fails closed");
