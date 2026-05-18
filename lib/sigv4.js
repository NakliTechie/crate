// SPDX-License-Identifier: AGPL-3.0-or-later
// AWS Signature Version 4 — hand-rolled per spec §"S3 sig-v4 implementation"
// ("Don't reach for a library. The auth header is ~100 lines of HMAC-SHA256.").
// Pure Web Crypto (crypto.subtle.digest + crypto.subtle.sign with HMAC keys);
// no aws-sdk, no external deps.
//
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//
// Public surface: signRequest({ method, url, headers, body, region, service,
//                              accessKey, secretKey, date })
// Returns the headers object with `Authorization`, `Host`, `X-Amz-Date`, and
// `X-Amz-Content-Sha256` added (existing headers preserved). The caller
// then passes the headers straight to fetch().

const ALGORITHM = "AWS4-HMAC-SHA256";
// SHA-256 of the empty string — used as the payload hash for HEAD/GET
// without a body. Some S3-compatible providers (Hetzner in particular)
// reject "UNSIGNED-PAYLOAD" for HEAD; the empty-body hash is universally
// accepted, so we prefer it for max cross-provider compatibility.
const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const encoder = new TextEncoder();

function toHex(buf) {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

async function sha256Hex(data) {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(buf);
}

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const sig = await crypto.subtle.sign("HMAC", key, bytes);
  return new Uint8Array(sig);
}

// AWS sig-v4 URI encoding: RFC 3986 unreserved characters only;
// path-segment slashes preserved.
function uriEncodeSegment(s) {
  return s.replace(/[^A-Za-z0-9_\-~.]/g, (c) => {
    // Already-encoded triples like %20 should be left alone, but in practice
    // bucket / key segments don't carry those — encode every offending byte.
    const bytes = encoder.encode(c);
    let out = "";
    for (const b of bytes) out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    return out;
  });
}

function canonicalPath(pathname) {
  if (!pathname || pathname === "") return "/";
  return pathname.split("/").map(uriEncodeSegment).join("/");
}

function canonicalQuery(searchParams) {
  // Sort by name (then by value); URI-encode both sides.
  const pairs = [];
  for (const [k, v] of searchParams.entries()) {
    pairs.push([uriEncodeSegment(k), uriEncodeSegment(v ?? "")]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

function canonicalHeaders(headers) {
  // Lowercase header names; collapse runs of whitespace in values; sort by name.
  const lower = Object.entries(headers).map(([k, v]) => [
    k.toLowerCase(),
    String(v).trim().replace(/\s+/g, " "),
  ]);
  lower.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canonical = lower.map(([k, v]) => `${k}:${v}\n`).join("");
  const signed = lower.map(([k]) => k).join(";");
  return { canonical, signed };
}

function isoDateTime(d) {
  // Returns "YYYYMMDDTHHMMSSZ" — sig-v4's `x-amz-date` format.
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/**
 * Sign an HTTP request with AWS Signature V4.
 *
 * @param {object} opts
 * @param {string} opts.method                  e.g. "HEAD" / "GET" / "PUT"
 * @param {string} opts.url                     full URL incl. query string
 * @param {Record<string,string>} [opts.headers] caller-supplied headers
 * @param {string|ArrayBuffer|Uint8Array} [opts.body] request body (default empty)
 * @param {string} opts.region                  e.g. "auto" (R2), "us-east-1" (AWS)
 * @param {string} [opts.service]               default "s3"
 * @param {string} opts.accessKey               AKIA... or R2-style key
 * @param {string} opts.secretKey               secret access key
 * @param {Date} [opts.date]                    for testing — default now
 *
 * @returns {Promise<Record<string,string>>} the headers to send with fetch()
 */
export async function signRequest(opts) {
  const {
    method = "GET",
    url,
    headers = {},
    body,
    region,
    service = "s3",
    accessKey,
    secretKey,
    date = new Date(),
  } = opts;
  if (!url) throw new Error("signRequest: url is required");
  if (!region) throw new Error("signRequest: region is required");
  if (!accessKey || !secretKey) throw new Error("signRequest: accessKey + secretKey required");

  const u = new URL(url);
  const amzDate = isoDateTime(date);          // "YYYYMMDDTHHMMSSZ"
  const dateStamp = amzDate.slice(0, 8);      // "YYYYMMDD"

  // Payload hash.
  let payloadHash;
  if (body == null || body === "") {
    payloadHash = EMPTY_BODY_SHA256;
  } else {
    payloadHash = await sha256Hex(body);
  }

  // Headers the caller supplied + the three we always add.
  const merged = {
    ...headers,
    host: u.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
  };

  // Canonical request.
  const { canonical: canonHeaders, signed: signedHeaders } = canonicalHeaders(merged);
  const canonRequest = [
    method.toUpperCase(),
    canonicalPath(u.pathname),
    canonicalQuery(u.searchParams),
    canonHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  // String to sign.
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    ALGORITHM,
    amzDate,
    scope,
    await sha256Hex(canonRequest),
  ].join("\n");

  // Signing key (4-iteration HMAC chain).
  const kDate    = await hmac(encoder.encode("AWS4" + secretKey), dateStamp);
  const kRegion  = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, "aws4_request");

  const signature = toHex(await hmac(kSigning, stringToSign));

  const authorization =
    `${ALGORITHM} Credential=${accessKey}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    ...merged,
    Authorization: authorization,
  };
}
