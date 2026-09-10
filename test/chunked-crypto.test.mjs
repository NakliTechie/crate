// SPDX-License-Identifier: AGPL-3.0-or-later
// Chunked object framing (v2) — round-trips plus every tamper class the
// per-chunk AAD is designed to reject. Also proves v1 single-blob objects
// still open through the same entry point.

import assert from "node:assert/strict";

import {
  sealObject, openObject, chunkCount, chunkAAD, CHUNK_SIZE,
  encrypt, randomDataKey, toBase64, newULID, randomIV,
} from "../lib/crypto.js";

const CS = 1024; // small chunk so multi-chunk cases stay fast
const key = randomDataKey();
const key2 = randomDataKey();

function bytes(n, seed = 7) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}
function entryFor(uuid, sealed, size) {
  return { uuid, size, content_iv: toBase64(sealed.contentIv), chunk_size: sealed.chunkSize };
}
async function rejects(fn, re, label) {
  await assert.rejects(fn, (e) => re.test(e.message), label);
}

// --- chunkCount --------------------------------------------------------------

assert.equal(chunkCount(0, CS), 1, "empty file is one chunk");
assert.equal(chunkCount(1, CS), 1);
assert.equal(chunkCount(CS, CS), 1, "exact multiple does not spill");
assert.equal(chunkCount(CS + 1, CS), 2);
assert.equal(chunkCount(5 * CS, CS), 5);
assert.throws(() => chunkCount(-1, CS));
assert.throws(() => chunkCount(10, 0));
assert.ok(CHUNK_SIZE >= 5 * 1024 * 1024, "default chunk clears R2's 5 MiB minimum part size");

// --- round-trips ---------------------------------------------------------------

for (const n of [0, 1, CS - 1, CS, CS + 1, 3 * CS, 3 * CS + 17]) {
  const uuid = newULID();
  const pt = bytes(n);
  const sealed = await sealObject(key, pt, uuid, CS);
  const total = chunkCount(n, CS);
  assert.equal(sealed.body.length, n + total * 28, `body length for n=${n}`);
  assert.deepEqual(sealed.body.subarray(0, 12), sealed.contentIv, "leading IV is contentIv");
  const out = await openObject(key, sealed.body, entryFor(uuid, sealed, n));
  assert.deepEqual(out, pt, `round-trip n=${n}`);
}

// Distinct IVs per chunk within one object.
{
  const uuid = newULID();
  const sealed = await sealObject(key, bytes(3 * CS), uuid, CS);
  const ivs = [0, 1, 2].map((i) => toBase64(sealed.body.subarray(i * (CS + 28), i * (CS + 28) + 12)));
  assert.equal(new Set(ivs).size, 3, "three chunks, three distinct IVs");
}

// --- tamper classes ------------------------------------------------------------

const uuid = newULID();
const N = 4 * CS;
const pt = bytes(N);
const sealed = await sealObject(key, pt, uuid, CS);
const entry = entryFor(uuid, sealed, N);
const STRIDE = CS + 28;
const chunk = (body, i) => body.subarray(i * STRIDE, (i + 1) * STRIDE);

// reorder: swap chunks 1 and 2
{
  const b = sealed.body.slice();
  const c1 = chunk(sealed.body, 1).slice(), c2 = chunk(sealed.body, 2).slice();
  b.set(c2, 1 * STRIDE); b.set(c1, 2 * STRIDE);
  await rejects(() => openObject(key, b, entry), /chunk 1 of 4 failed authentication/, "reorder");
}

// truncate: drop the last chunk (length check fires first)
await rejects(
  () => openObject(key, sealed.body.subarray(0, 3 * STRIDE), entry),
  /object length .* does not match manifest/, "truncate",
);

// truncate + lie about size: manifest size is signed, but prove the AAD
// alone would catch it — seal 3 chunks under n=3, present as chunk 0..2 of 4
{
  const three = await sealObject(key, bytes(3 * CS), uuid, CS);
  const lying = { ...entry, size: 3 * CS, content_iv: toBase64(three.contentIv) };
  // same bytes, honest entry: opens
  assert.deepEqual(await openObject(key, three.body, lying), bytes(3 * CS));
  // now graft chunk 3 from the 4-chunk object on the end and claim size 4*CS
  const grafted = new Uint8Array(4 * STRIDE);
  grafted.set(three.body, 0); grafted.set(chunk(sealed.body, 3), 3 * STRIDE);
  await rejects(
    () => openObject(key, grafted, { ...lying, size: N }),
    /chunk 0 of 4 failed authentication/, "total is bound: chunks sealed under n=3 fail under n=4",
  );
}

// extend: append a stray byte
{
  const b = new Uint8Array(sealed.body.length + 1); b.set(sealed.body);
  await rejects(() => openObject(key, b, entry), /object length .* does not match manifest/, "extend");
}

// bit-flip inside chunk 2 ciphertext
{
  const b = sealed.body.slice(); b[2 * STRIDE + 12 + 5] ^= 0x01;
  await rejects(() => openObject(key, b, entry), /chunk 2 of 4 failed authentication/, "bit flip");
}

// cross-file splice: chunk 1 from another file at the same index
{
  const other = await sealObject(key, bytes(N, 99), newULID(), CS);
  const b = sealed.body.slice(); b.set(chunk(other.body, 1), 1 * STRIDE);
  await rejects(() => openObject(key, b, entry), /chunk 1 of 4 failed authentication/, "cross-file splice");
}

// cross-VERSION splice: same uuid, same key, same index, older version.
// This is the case single-blob AAD=uuid never had to defend and the
// reason IV_0 is inside every chunk's AAD.
{
  const older = await sealObject(key, bytes(N, 3), uuid, CS);
  const b = sealed.body.slice(); b.set(chunk(older.body, 2), 2 * STRIDE);
  await rejects(() => openObject(key, b, entry), /chunk 2 of 4 failed authentication/, "cross-version splice");
}

// full rollback: entire older body under the current manifest entry
{
  const older = await sealObject(key, bytes(N, 3), uuid, CS);
  await rejects(() => openObject(key, older.body, entry), /does not match manifest content_iv/, "rollback anchor");
}

// wrong key
await rejects(() => openObject(key2, sealed.body, entry), /chunk 0 of 4 failed authentication/, "wrong key");

// wrong uuid in entry
await rejects(() => openObject(key, sealed.body, { ...entry, uuid: newULID() }), /failed authentication/, "wrong uuid");

// manifest lies about chunk_size
await rejects(() => openObject(key, sealed.body, { ...entry, chunk_size: CS * 2 }), /does not match manifest/, "wrong chunk_size");

// malformed entries
await rejects(() => openObject(key, sealed.body, { ...entry, content_iv: undefined }), /missing content_iv/, "v2 requires content_iv");
await rejects(() => openObject(key, sealed.body, { ...entry, chunk_size: 0 }), /chunk_size invalid/, "chunk_size 0");
await rejects(() => openObject(key, sealed.body, { ...entry, chunk_size: 1.5 }), /chunk_size invalid/, "chunk_size fractional");
await rejects(() => openObject(key, new Uint8Array(5), entry), /too short/, "body shorter than an IV");

// --- v1 single-blob still opens through openObject ---------------------------

{
  const u = newULID();
  const p = bytes(3000);
  const s = await encrypt(key, p, new TextEncoder().encode(u));
  const body = new Uint8Array(12 + s.ciphertext.length); body.set(s.iv); body.set(s.ciphertext, 12);
  const v1 = { uuid: u, size: p.length, content_iv: toBase64(s.iv) }; // no chunk_size
  assert.deepEqual(await openObject(key, body, v1), p, "v1 opens");
  // v1 rollback anchor still enforced
  const s2 = await encrypt(key, p, new TextEncoder().encode(u));
  const body2 = new Uint8Array(12 + s2.ciphertext.length); body2.set(s2.iv); body2.set(s2.ciphertext, 12);
  await rejects(() => openObject(key, body2, v1), /does not match manifest content_iv/, "v1 rollback");
  // pre-audit v1 entry with no content_iv: tolerated (matches existing behaviour)
  assert.deepEqual(await openObject(key, body, { uuid: u, size: p.length }), p, "v1 without content_iv");
  // a v1 body presented as v2 is rejected by the length check
  await rejects(() => openObject(key, body, { ...v1, chunk_size: CS }), /does not match manifest/, "v1 body under v2 entry");
}

// --- AAD canonical form (cross-surface contract) -------------------------------

{
  const iv = randomIV();
  const aad = new TextDecoder().decode(chunkAAD("01ABC", iv, 3, 7));
  assert.equal(aad, `01ABC:${toBase64(iv)}:3:7`, "AAD is uuid:base64(IV_0):index:total");
}

console.log("OK: chunked object framing — round-trips, 14 tamper classes rejected, v1 compatible");
