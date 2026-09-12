// SPDX-License-Identifier: AGPL-3.0-or-later
// Compression (v1.2): compressible files are deflated before sealing;
// the manifest carries compression + stored_size; openObject inflates;
// already-compressed formats and tiny files are stored as-is; a tampered
// stored_size or size fails closed; the Crate API round-trips.

import assert from "node:assert/strict";
import * as cryptoLib from "../lib/crypto.js";
import { Manifest, createEvent } from "../lib/manifest.js";

const uuid = "01HCOMPRESS0000000000000001";
const key = cryptoLib.randomBytes(32);
const text = new TextEncoder().encode("lorem ipsum ".repeat(2000));

// decisions
assert.equal(cryptoLib.compressible("notes.md", "text/markdown", 5000), true);
assert.equal(cryptoLib.compressible("photo.jpg", "image/jpeg", 5000), false);
assert.equal(cryptoLib.compressible("archive.zip", "application/zip", 5000), false);
assert.equal(cryptoLib.compressible("x.bin", "application/octet-stream", 100), false, "tiny files are not worth it");
assert.equal(cryptoLib.compressible("x.bin", "application/octet-stream", 5000), true);

// sealFile deflates and reports stored_size; openObject gives the text back
const s = await cryptoLib.sealFile(key, text, uuid, { name: "notes.md", mime: "text/markdown", chunkSize: 1024 });
assert.equal(s.compression, "deflate-raw");
assert.ok(s.storedSize < text.length * 0.2, `stored ${s.storedSize} of ${text.length}`);
const entry = { uuid, size: text.length, content_iv: cryptoLib.toBase64(s.contentIv), chunk_size: 1024, compression: s.compression, stored_size: s.storedSize };
const back = await cryptoLib.openObject(key, s.body, entry);
assert.equal(Buffer.from(back).toString(), Buffer.from(text).toString());

// incompressible data stays uncompressed even when "compressible" by type
const noise = cryptoLib.randomBytes(4000);
const s2 = await cryptoLib.sealFile(key, noise, uuid, { name: "noise.bin", mime: "application/octet-stream" });
assert.equal(s2.compression, undefined);
assert.equal(Buffer.from(await cryptoLib.openObject(key, s2.body, { uuid, size: noise.length, content_iv: cryptoLib.toBase64(s2.contentIv), chunk_size: s2.chunkSize })).toString("hex"), Buffer.from(noise).toString("hex"));

// fail closed: wrong stored_size, wrong size, unknown compression, or a reader that ignores the flag
await assert.rejects(cryptoLib.openObject(key, s.body, { ...entry, stored_size: s.storedSize + 1 }), /does not match manifest/);
await assert.rejects(cryptoLib.openObject(key, s.body, { ...entry, size: text.length + 1 }), /inflated .* manifest size/);
await assert.rejects(cryptoLib.openObject(key, s.body, { ...entry, compression: "brotli" }), /unknown compression/);
await assert.rejects(cryptoLib.openObject(key, s.body, { uuid, size: text.length, content_iv: entry.content_iv, chunk_size: 1024 }), /does not match manifest/, "a pre-1.2 reader fails closed");

// manifest: fields validated and carried through materialise
const m = new Manifest();
await m.append(createEvent({ uuid, path: "/notes.md", size: text.length, mime: "text/markdown", dataKeyIv: new Uint8Array(12), dataKeyCt: new Uint8Array(48), contentIv: s.contentIv, chunkSize: 1024, compression: s.compression, storedSize: s.storedSize }), key);
const e = m.materialise().get("/notes.md");
assert.equal(e.compression, "deflate-raw"); assert.equal(e.stored_size, s.storedSize); assert.equal(e.size, text.length);
await assert.rejects(m.append({ op: "create", uuid: "u", path: "/x", size: 1, data_key_iv: "a", data_key_ct: "b", content_iv: "c", compression: "deflate-raw" }, key), /requires stored_size/);
await assert.rejects(m.append({ op: "create", uuid: "u", path: "/x", size: 1, data_key_iv: "a", data_key_ct: "b", content_iv: "c", compression: "lzma", stored_size: 1 }, key), /unknown compression/);

console.log("OK: compression — deflate before seal, stored_size framed, inflated size checked, incompressible left alone, old readers fail closed");
