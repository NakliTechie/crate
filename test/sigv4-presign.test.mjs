// SPDX-License-Identifier: AGPL-3.0-or-later
// presignUrl against the AWS reference vector for query-string auth:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
// (GET examplebucket/test.txt, 86400 s, 2013-05-24, us-east-1).

import assert from "node:assert/strict";
import { presignUrl } from "../lib/sigv4.js";

const url = await presignUrl({
  method: "GET",
  url: "https://examplebucket.s3.amazonaws.com/test.txt",
  region: "us-east-1",
  accessKey: "AKIAIOSFODNN7EXAMPLE",
  secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  expiresSeconds: 86400,
  date: new Date("2013-05-24T00:00:00Z"),
});
const u = new URL(url);
assert.equal(u.searchParams.get("X-Amz-Signature"), "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404");
assert.equal(u.searchParams.get("X-Amz-Credential"), "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request");
assert.equal(u.searchParams.get("X-Amz-Expires"), "86400");
assert.equal(u.searchParams.get("X-Amz-SignedHeaders"), "host");
assert.ok(url.startsWith("https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"));

// expiry bounds
await assert.rejects(presignUrl({ url: "https://x.example/a", region: "auto", accessKey: "a", secretKey: "b", expiresSeconds: 0 }), /1\.\.604800/);
await assert.rejects(presignUrl({ url: "https://x.example/a", region: "auto", accessKey: "a", secretKey: "b", expiresSeconds: 604801 }), /1\.\.604800/);

console.log("OK: sig-v4 presigned URL matches the AWS reference signature");
