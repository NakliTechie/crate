// SPDX-License-Identifier: AGPL-3.0-or-later
// Share links: mint from an owner session, parse on the recipient side,
// decrypt the object with only what the link carries. Two transports.

import assert from "node:assert/strict";
import * as cryptoLib from "../lib/crypto.js";
import { mintShare, parseShare, fetchShared, objectShareUrl } from "../lib/share.js";

// an owner's file: sealed v2 object + manifest entry, as Crate.write does
const masterKey = cryptoLib.randomBytes(32);
const uuid = "01HSHARE00000000000000001";
const dataKey = cryptoLib.randomBytes(32);
const plaintext = new TextEncoder().encode("shared bytes " + "x".repeat(5000));
const sealed = await cryptoLib.sealObject(dataKey, plaintext, uuid, 1024);
const wrapped = await cryptoLib.wrapDataKey(masterKey, dataKey, uuid);
const entry = {
  uuid, path: "/notes/hello.txt", size: plaintext.length, mime: "text/plain",
  data_key_iv: cryptoLib.toBase64(wrapped.iv), data_key_ct: cryptoLib.toBase64(wrapped.ciphertext),
  content_iv: cryptoLib.toBase64(sealed.body.subarray(0, 12)), chunk_size: 1024,
};

// serve the object at any URL that names it (query auth is the transport's business)
globalThis.fetch = async (url) => {
  const u = new URL(url);
  if (!u.pathname.endsWith(uuid)) return new Response("nope", { status: 404 });
  if (u.searchParams.get("expired") === "1") return new Response("", { status: 403 });
  return new Response(sealed.body, { status: 200 });
};

for (const region of ["auto", "carrier"]) {
  const session = {
    bucketBase: region === "carrier" ? "https://w.example.workers.dev/o/" : "https://acct.r2.cloudflarestorage.com/bkt/",
    region, accessKey: region === "carrier" ? "carrier" : "AKIAEXAMPLE", secretKey: "s3cr3t", masterKey,
  };
  const { link, exp } = await mintShare({ session, entry, name: "hello.txt", seconds: 3600, origin: "https://crate.naklios.dev" });
  assert.ok(link.startsWith("https://crate.naklios.dev/#share="));
  assert.ok(exp > Date.now() + 3500_000 && exp <= Date.now() + 3600_000);

  const share = parseShare(new URL(link).hash);
  assert.equal(share.name, "hello.txt");
  assert.equal(share.uuid, uuid);
  assert.equal(share.size, plaintext.length);
  assert.equal(share.chunkSize, 1024);
  const u = new URL(share.url);
  if (region === "carrier") {
    assert.equal(u.searchParams.get("share"), "1");
    assert.equal(u.searchParams.get("exp"), String(exp));
    assert.equal(u.searchParams.get("sig")?.length, 64);
  } else {
    assert.equal(u.searchParams.get("X-Amz-Expires"), "3600");
    assert.ok(u.searchParams.get("X-Amz-Signature"));
  }
  const out = await fetchShared(share);
  assert.equal(Buffer.from(out).toString(), Buffer.from(plaintext).toString(), region);
  // the master key is not in the link
  assert.ok(!link.includes(cryptoLib.toBase64(masterKey).replace(/=+$/, "")));
}

// wrong key in the link → clear error, not garbage
{
  const session = { bucketBase: "https://acct.r2.cloudflarestorage.com/bkt/", region: "auto", accessKey: "A", secretKey: "s", masterKey };
  const { link } = await mintShare({ session, entry, name: "hello.txt", seconds: 60, origin: "https://x" });
  const share = parseShare(new URL(link).hash);
  share.key = cryptoLib.randomBytes(32);
  await assert.rejects(fetchShared(share), /doesn't match this link/);
  // expired by clock
  const s2 = parseShare(new URL(link).hash); s2.exp = Date.now() - 1;
  await assert.rejects(fetchShared(s2), /expired/);
  // refused by storage
  const s3 = parseShare(new URL(link).hash); s3.url += "&expired=1";
  await assert.rejects(fetchShared(s3), /expired or was revoked/);
}
assert.throws(() => parseShare("#share=!!"), /not a share link/);
assert.throws(() => parseShare("#share=aGVsbG8"), /damaged/);

// presign helper caps at 7 days
await assert.rejects(objectShareUrl({ bucketBase: "https://a.r2.cloudflarestorage.com/b/", region: "auto", accessKey: "A", secretKey: "s", uuid, seconds: 8 * 86400 }), /604800/);

console.log("OK: share links — mint (R2 presign / carrier query-sig), parse, decrypt with only the link; wrong key, expiry and revocation are clear errors");
