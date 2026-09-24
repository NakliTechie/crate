// SPDX-License-Identifier: AGPL-3.0-or-later
// Concurrent write()s on one Crate must all land, in one valid chain,
// without tripping the rollback anchor. Live defect 2026-09-24 (naklios.dev,
// Anvil writing several files + a run record in quick succession):
//   manifest rollback detected (truncation): loaded count 21 < anchor count 22
// Cause: two flushes shared one Manifest. The first PUT to win advanced the
// anchor to the in-memory tail — which already held the second write's event,
// not yet on the bucket — so the second flush's 412 re-GET read a manifest
// shorter than the anchor. Runs against an in-memory bucket (fetch stub) with
// a sessionStorage stub so the anchor is live (node has no IndexedDB).

import assert from "node:assert/strict";
import { Crate } from "../lib/crate.js";
import { Manifest, MANIFEST_PATH } from "../lib/manifest.js";
import * as anchor from "../lib/anchor.js";

const ss = new Map();
globalThis.sessionStorage = {
  getItem: (k) => (ss.has(k) ? ss.get(k) : null),
  setItem: (k, v) => ss.set(k, String(v)),
  removeItem: (k) => ss.delete(k),
};

const store = new Map(); // url → { body, etag }
const log = [];
let n = 0;
const tick = () => new Promise((r) => setTimeout(r, Math.random() * 4));
globalThis.fetch = async (url, init = {}) => {
  const method = (init.method || "GET").toUpperCase();
  const key = String(url);
  await tick(); // network latency — lets requests overlap and reorder
  if (method === "PUT") {
    const body = init.body instanceof Uint8Array ? init.body : new Uint8Array(init.body);
    const h = init.headers || {};
    const ifMatch = h["if-match"] || h["If-Match"] || null;
    if (ifMatch && store.get(key)?.etag !== ifMatch) {
      log.push(`412 ${key.split("/").pop()}`);
      return new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 });
    }
    const etag = `"e${++n}"`;
    store.set(key, { body, etag });
    return new Response(null, { status: 200, headers: { etag } });
  }
  const hit = store.get(key);
  if (!hit) return new Response("<Error><Code>NoSuchKey</Code></Error>", { status: 404, headers: { "content-type": "application/xml" } });
  return new Response(hit.body, { status: 200, headers: { etag: hit.etag } });
};

const bucketConfig = { provider: "r2", accountId: "0".repeat(32), name: "concurrent-test", region: "auto" };
const credentials = { accessKey: "AKIAEXAMPLEKEY000000", secretKey: "secretkeysecretkeysecretkey" };
const PASS = "sphere-cancel-scan-blanket-interest";

const ROUNDS = 20;
const FILES = 6;
const c = await Crate.bootstrap({ bucketConfig, credentials, passphrase: PASS });
const base = c._bucketBase;
for (let r = 0; r < ROUNDS; r++) {
  const paths = Array.from({ length: FILES }, (_, i) => `/r${r}/f${i}.txt`);
  // one of the writes is an overwrite of an existing file (update path)
  if (r > 0) paths[0] = `/r${r - 1}/f1.txt`;
  const results = await Promise.allSettled(
    paths.map((p) => c.write(p, new TextEncoder().encode(`${p}@${r}`))),
  );
  const failed = results.filter((x) => x.status === "rejected");
  assert.equal(failed.length, 0, `round ${r}: ${failed.length} write(s) failed: ${failed.map((f) => f.reason?.message).join(" | ")}`);
}

// The remote manifest holds every event, in one valid chain, and the
// anchor this device saved matches the remote tail (never ahead of it).
const remote = await Manifest.loadFromBytes(store.get(base + MANIFEST_PATH).body, c._masterKey);
const ver = await remote.verify(c._masterKey);
assert.ok(ver.ok, `remote chain invalid: ${ver.reason}`);
assert.equal(remote.events.length, c._manifest.events.length, "remote manifest lost events that the in-memory one holds");
const creates = remote.events.filter((e) => e.op === "create").map((e) => e.uuid);
assert.equal(new Set(creates).size, creates.length, "a create event was replayed twice");
const saved = await anchor.loadAnchor(base);
assert.equal(saved.count, remote.events.length, "anchor count != remote count");

const tree = remote.materialise();
for (let r = 0; r < ROUNDS; r++) {
  for (let i = 1; i < FILES; i++) assert.ok(tree.get(`/r${r}/f${i}.txt`), `missing /r${r}/f${i}.txt`);
}
c.close();

// A fresh open on the same device passes the anchor and reads the files.
const again = await Crate.open({ bucketConfig, credentials, passphrase: PASS });
assert.equal(new TextDecoder().decode(await again.read(`/r${ROUNDS - 1}/f5.txt`)), `/r${ROUNDS - 1}/f5.txt@${ROUNDS - 1}`);
again.close();

console.log(`OK: ${ROUNDS}x${FILES} concurrent writes land in one valid chain; anchor == remote tail (${log.length} 412s seen)`);
