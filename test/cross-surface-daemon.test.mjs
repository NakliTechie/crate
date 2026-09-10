// SPDX-License-Identifier: AGPL-3.0-or-later
// The browser must OPEN a v2 object the daemon SEALED. Fixture from
// `CRATE_WRITE_FIXTURE=1 go test ./internal/payload/ -run TestWritesDaemonFixture`
// in crate-agent, copied to test/fixtures/daemon-v2.json.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

import { openObject, fromBase64 } from "../lib/crypto.js";

const f = JSON.parse(await readFile(new URL("./fixtures/daemon-v2.json", import.meta.url), "utf8"));
const entry = { uuid: f.uuid, size: f.size, content_iv: f.content_iv, chunk_size: f.chunk_size };
const key = fromBase64(f.data_key);

const pt = await openObject(key, fromBase64(f.body), entry);
assert.equal(pt.length, f.size, "plaintext length");
assert.equal(createHash("sha256").update(pt).digest("hex"), f.plaintext_sha256, "plaintext sha256");

// the daemon's IV_0 anchors the body on this side too
const body = fromBase64(f.body); body[0] ^= 1;
await assert.rejects(() => openObject(key, body, entry), /does not match manifest content_iv/, "flipped IV_0 rejected");

console.log(`OK: browser opens daemon-sealed v2 object (${f.producer})`);
