// SPDX-License-Identifier: AGPL-3.0-or-later
// The carrier transport in lib/bucket.js must produce exactly what
// crate-carrier/src/lib.js verifies. The canonical form is restated here
// (not imported) so this test pins the contract, not a shared file.

import assert from "node:assert/strict";
import { carrierCanonical, carrierHeaders, resolveBase, endpoints, CARRIER_REGION, CARRIER_ACCESS_KEY } from "../lib/bucket.js";
import { pack, unpack } from "../lib/credsfile.js";

const SECRET = "test-secret";

// canonical form — identical string to crate-carrier's test
assert.equal(
  carrierCanonical({ method: "put", path: "/o/a", query: "b=2&a=1", ts: 5, nonce: "z" }),
  "PUT\n/o/a\na=1&b=2\n5\nz",
);

// headers verify under an independent HMAC (what the Worker computes)
{
  const url = "https://w.example.workers.dev/o/objects/01ABC?mpu=part&uploadId=u1&n=3";
  const h = await carrierHeaders({ method: "PUT", url, secretKey: SECRET, ts: 1700000000000, nonce: "n1" });
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const canon = "PUT\n/o/objects/01ABC\nmpu=part&n=3&uploadId=u1\n1700000000000\nn1";
  const sig = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canon))), (b) => b.toString(16).padStart(2, "0")).join("");
  assert.deepEqual(h, { "x-crate-ts": "1700000000000", "x-crate-nonce": "n1", "x-crate-sig": sig });
  // fresh nonce per call by default
  const a = await carrierHeaders({ method: "GET", url, secretKey: SECRET });
  const b = await carrierHeaders({ method: "GET", url, secretKey: SECRET });
  assert.notEqual(a["x-crate-nonce"], b["x-crate-nonce"]);
}

// resolveBase — both providers
assert.equal(endpoints.Carrier("https://w.example.workers.dev/"), "https://w.example.workers.dev/o/");
assert.equal(resolveBase({ provider: "carrier", url: "https://w.example.workers.dev" }), "https://w.example.workers.dev/o/");
assert.equal(resolveBase({ region: CARRIER_REGION, url: "https://w.example.workers.dev" }), "https://w.example.workers.dev/o/");
assert.equal(resolveBase({ accountId: "ABCDEF", name: "my-bucket" }), "https://abcdef.r2.cloudflarestorage.com/my-bucket/");
assert.throws(() => resolveBase({ provider: "carrier" }), /carrier url required/);

// creds file round-trips a carrier provider and still round-trips r2
{
  const c = { provider: "carrier", bucket: { name: "w.example.workers.dev", accountId: "carrier", url: "https://w.example.workers.dev" }, credentials: { accessKey: CARRIER_ACCESS_KEY, secretKey: SECRET } };
  const back = await unpack(await pack(c, "pw"), "pw");
  assert.deepEqual(back, { provider: "carrier", bucket: { name: "w.example.workers.dev", accountId: "carrier", region: "carrier", url: "https://w.example.workers.dev" }, credentials: { accessKey: "carrier", secretKey: SECRET } });
  await assert.rejects(pack({ ...c, bucket: { name: "x", accountId: "carrier" } }, "pw"), /carrier creds need bucket.url/);
  const r2 = { provider: "r2", bucket: { name: "b", accountId: "a" }, credentials: { accessKey: "k", secretKey: "s" } };
  const r2back = await unpack(await pack(r2, "pw"), "pw");
  assert.equal(r2back.bucket.region, "auto"); assert.equal("url" in r2back.bucket, false, "r2 creds carry no url");
}

console.log("OK: carrier transport signs what crate-carrier verifies; creds file carries the provider");

// weak/quoted ETags are normalised to the bare strong value
{
  const { cleanEtag } = await import("../lib/bucket.js");
  assert.equal(cleanEtag('W/"abc"'), "abc"); assert.equal(cleanEtag('"abc"'), "abc"); assert.equal(cleanEtag("abc"), "abc"); assert.equal(cleanEtag(null), "");
}
console.log("OK: ETag normalisation");
