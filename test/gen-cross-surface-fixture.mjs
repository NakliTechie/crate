// SPDX-License-Identifier: AGPL-3.0-or-later
// Emits a v2 object sealed by the BROWSER implementation, for the daemon's
// cross-surface test (crate-agent/internal/payload/testdata/browser-v2.json).
// Deterministic inputs are NOT possible (fresh random IVs), so the fixture
// is regenerated and committed, never compared byte-for-byte; the daemon
// proves it can OPEN what the browser SEALED, which is the contract.
//
//   node test/gen-cross-surface-fixture.mjs > ../crate-agent/internal/payload/testdata/browser-v2.json

import { sealObject, randomDataKey, toBase64, newULID } from "../lib/crypto.js";
import { createHash } from "node:crypto";

const chunkSize = 1024;
const size = 3 * chunkSize + 17; // four chunks, ragged tail
const plaintext = new Uint8Array(size);
for (let i = 0; i < size; i++) plaintext[i] = (i * 31 + 7) & 0xff;

const uuid = newULID();
const dataKey = randomDataKey();
const sealed = await sealObject(dataKey, plaintext, uuid, chunkSize);

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
