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

// Compressed fixture (crate-agent ≥ 1.4): the browser inflates what the
// daemon deflated.
{
  const { existsSync } = await import("node:fs");
  const p = new URL("./fixtures/daemon-v2-compressed.json", import.meta.url);
  if (existsSync(p)) {
    const g = JSON.parse(await readFile(p, "utf8"));
    const e = { uuid: g.uuid, size: g.size, content_iv: g.content_iv, chunk_size: g.chunk_size, compression: g.compression, stored_size: g.stored_size };
    const out = await openObject(fromBase64(g.data_key), fromBase64(g.body), e);
    assert.equal(out.length, g.size);
    assert.equal(createHash("sha256").update(out).digest("hex"), g.plaintext_sha256);
    console.log(`OK: browser opens daemon-sealed compressed object (${g.producer})`);
  } else {
    console.log("skip: no daemon compressed fixture yet");
  }
}
