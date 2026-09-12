// SPDX-License-Identifier: AGPL-3.0-or-later
// Emits a v2 object sealed by the BROWSER implementation, for the daemon's
// cross-surface test (crate-agent/internal/payload/testdata/browser-v2.json).
// Deterministic inputs are NOT possible (fresh random IVs), so the fixture
// is regenerated and committed, never compared byte-for-byte; the daemon
// proves it can OPEN what the browser SEALED, which is the contract.
//
//   node test/gen-cross-surface-fixture.mjs > ../crate-agent/internal/payload/testdata/browser-v2.json

import { sealObject, sealFile, randomDataKey, toBase64, newULID } from "../lib/crypto.js";
import { createHash } from "node:crypto";

const chunkSize = 1024;
const size = 3 * chunkSize + 17; // four chunks, ragged tail
const plaintext = new Uint8Array(size);
for (let i = 0; i < size; i++) plaintext[i] = (i * 31 + 7) & 0xff;

const uuid = newULID();
const dataKey = randomDataKey();
const sealed = await sealObject(dataKey, plaintext, uuid, chunkSize);

// Second fixture: the same bytes made compressible (repeating text), sealed
// through sealFile so the daemon proves it inflates what the browser
// deflated. Written next to the first when an output directory is given.
const text = new TextEncoder().encode("the quick brown fox jumps over the lazy dog\n".repeat(120));
const uuid2 = newULID();
const dataKey2 = randomDataKey();
const sealed2 = await sealFile(dataKey2, text, uuid2, { name: "fox.txt", mime: "text/plain", chunkSize });
if (sealed2.compression !== "deflate-raw") throw new Error("fixture text did not compress");
const compressedFixture = JSON.stringify({
  producer: "crate browser lib/crypto.js sealFile (deflate-raw)",
  uuid: uuid2,
  data_key: toBase64(dataKey2),
  size: text.length,
  chunk_size: chunkSize,
  content_iv: toBase64(sealed2.contentIv),
  compression: sealed2.compression,
  stored_size: sealed2.storedSize,
  body: toBase64(sealed2.body),
  plaintext_sha256: createHash("sha256").update(text).digest("hex"),
}, null, 2) + "\n";
if (process.argv[2]) {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(process.argv[2] + "/browser-v2-compressed.json", compressedFixture);
}

process.stdout.write(JSON.stringify({
  producer: "crate browser lib/crypto.js sealObject",
  uuid,
  data_key: toBase64(dataKey),
  size,
  chunk_size: chunkSize,
  content_iv: toBase64(sealed.contentIv),
  body: toBase64(sealed.body),
  plaintext_sha256: createHash("sha256").update(plaintext).digest("hex"),
}, null, 2) + "\n");
