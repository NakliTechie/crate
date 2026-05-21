// SPDX-License-Identifier: AGPL-3.0-or-later
// Provider-agnostic S3-compatible HTTP client. Uses lib/sigv4.js for
// AWS Signature V4 signing. Targets R2 (launch surface) + Hetzner +
// B2 + AWS S3.
//
// Public surface (M2):
//   signedHead({ url, region, accessKey, secretKey, signal })
//     → { ok, status, code, message }  — authenticated HEAD; the workhorse
//       for "does bucket exist + do credentials work" together.
//   unauthHead({ url, signal })
//     → { reachable, status, message } — unauthenticated probe; tells you
//       if the URL resolves to a real S3 bucket. R2 returns 401 if the
//       bucket exists, 404 if not.
//   corsPreflight({ url, origin, signal })
//     → { ok, allowedOrigin, allowedMethods, message } — explicit OPTIONS
//       request to verify the bucket allows our origin.
//   endpoints — provider URL builders:
//     R2(accountId, bucket)
//     Hetzner(datacenter, bucket)   // e.g. ('nbg1', 'my-bucket')
//     B2(region, bucket)             // e.g. ('us-west-002', 'my-bucket')
//     AWS(region, bucket)            // e.g. ('us-east-1', 'my-bucket')
//
// The wizard uses R2 + corsPreflight. The other endpoints exist so the
// devtools smoke recipe (docs/README.md) can exercise the abstraction
// against Hetzner per spec §"S3 sig-v4 implementation".

import { signRequest } from "./sigv4.js";

// --- Endpoint templates ------------------------------------------------

export const endpoints = Object.freeze({
  // R2: path-style under https://{accountId}.r2.cloudflarestorage.com/
  R2(accountId, bucket) {
    return `https://${accountId}.r2.cloudflarestorage.com/${encodeURIComponent(bucket)}/`;
  },
  // Hetzner: virtual-host-style under https://{bucket}.{datacenter}.your-objectstorage.com/
  // Datacenter examples: nbg1, fsn1, hel1.
  Hetzner(datacenter, bucket) {
    return `https://${encodeURIComponent(bucket)}.${datacenter}.your-objectstorage.com/`;
  },
  // B2 S3-compatible: virtual-host under https://{bucket}.s3.{region}.backblazeb2.com/
  // Region examples: us-west-002, us-east-005.
  B2(region, bucket) {
    return `https://${encodeURIComponent(bucket)}.s3.${region}.backblazeb2.com/`;
  },
  // AWS S3: virtual-host under https://{bucket}.s3.{region}.amazonaws.com/
  AWS(region, bucket) {
    return `https://${encodeURIComponent(bucket)}.s3.${region}.amazonaws.com/`;
  },
});

// --- Error helpers -----------------------------------------------------

// `TypeError: Failed to fetch` is what the browser throws when CORS
// blocks a response OR when the network is unreachable. We can't always
// distinguish those, but the AbortError case is detectable separately.
export function isAbortError(err) {
  return err && (err.name === "AbortError" || err.code === 20);
}

// CORS-blocked responses surface as TypeError in fetch. Network errors
// also surface as TypeError. The caller should layer this with prior
// unauth-probe context to disambiguate: if unauth succeeded but signed
// failed with TypeError, CORS is the likely culprit (the unauth probe
// doesn't include an Authorization header, so it's a "simple request"
// and slips past CORS preflight requirements).
export function isLikelyCorsError(err) {
  return err && err.name === "TypeError" && /fetch|Network|CORS/i.test(err.message ?? "");
}

// Parse an S3-style error response body. R2 / Hetzner / B2 / AWS all
// return XML like <Error><Code>...</Code><Message>...</Message></Error>.
async function parseS3Error(response) {
  try {
    const text = await response.clone().text();
    const code = (text.match(/<Code>([^<]+)<\/Code>/) || [])[1];
    const message = (text.match(/<Message>([^<]+)<\/Message>/) || [])[1];
    return { code, message, raw: text };
  } catch {
    return { code: undefined, message: undefined, raw: "" };
  }
}

// --- Public API --------------------------------------------------------

/**
 * Unauthenticated HEAD against a bucket URL. R2 returns 401 if the
 * bucket exists (auth required), 404 if it doesn't. Used in the
 * wizard's Bucket stage to verify the URL resolves before the user
 * has entered credentials.
 *
 * Note: this is a "simple" CORS request (HEAD with no custom headers),
 * so it doesn't trigger a preflight. R2 returns CORS headers on the
 * 401, which is enough for fetch to surface the status to us.
 */
export async function unauthHead({ url, signal } = {}) {
  if (!url) throw new Error("unauthHead: url required");
  try {
    const res = await fetch(url, { method: "HEAD", signal, mode: "cors" });
    return { reachable: true, status: res.status, message: res.statusText };
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      reachable: false,
      status: 0,
      message: err.message ?? "fetch failed",
      networkError: true,
    };
  }
}

/**
 * Signed HEAD against a bucket URL. Returns the HTTP status + parsed
 * error code/message. Combines "does bucket exist" + "do credentials
 * work" into one call:
 *   200 → bucket + creds both fine
 *   403 (SignatureDoesNotMatch, InvalidAccessKeyId, AccessDenied) → creds bad
 *   404 → bucket missing
 *   network/TypeError → likely CORS not configured (see isLikelyCorsError)
 */
export async function signedHead({ url, region, accessKey, secretKey, signal } = {}) {
  if (!url) throw new Error("signedHead: url required");
  const signed = await signRequest({
    method: "HEAD",
    url,
    region,
    accessKey,
    secretKey,
  });
  // Browser blocks setting `Host` from JS — strip it; fetch sets it.
  delete signed.host;
  let res;
  try {
    res = await fetch(url, { method: "HEAD", headers: signed, signal, mode: "cors" });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      ok: false,
      status: 0,
      code: isLikelyCorsError(err) ? "CORS_OR_NETWORK" : "NETWORK_ERROR",
      message: err.message ?? "fetch failed",
      networkError: true,
    };
  }
  if (res.ok) {
    return { ok: true, status: res.status, code: undefined, message: res.statusText };
  }
  // HEAD has no body — fall back to status only.
  const { code, message } = await parseS3Error(res);
  return {
    ok: false,
    status: res.status,
    code: code ?? `HTTP_${res.status}`,
    message: message ?? res.statusText,
  };
}

/**
 * Explicit CORS preflight. Sends an OPTIONS request with the same
 * Access-Control-Request-* headers the browser would send before a
 * real signed HEAD/GET. Verifies the response advertises our origin.
 *
 * Note: fetch can't always see preflight responses cleanly — browsers
 * fold preflight into the actual request. So we make an EXPLICIT
 * OPTIONS request as a plain fetch, which the bucket should answer
 * with CORS headers regardless of whether the underlying API would.
 */
export async function corsPreflight({ url, origin, signal } = {}) {
  if (!url) throw new Error("corsPreflight: url required");
  if (!origin) throw new Error("corsPreflight: origin required");
  let res;
  try {
    res = await fetch(url, {
      method: "OPTIONS",
      signal,
      mode: "cors",
      headers: {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,x-amz-content-sha256,x-amz-date",
      },
    });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      ok: false,
      allowedOrigin: null,
      allowedMethods: null,
      message: err.message ?? "preflight fetch failed",
    };
  }
  // The browser hides response headers across origins unless the bucket
  // explicitly exposes them — but CORS headers themselves are always
  // visible to fetch, since they govern its own behaviour.
  const acao = res.headers.get("access-control-allow-origin");
  const acam = res.headers.get("access-control-allow-methods");
  const originAllowed = acao === "*" || acao === origin;
  const methodsAllowed = acam && /\b(GET|HEAD|PUT|DELETE)\b/i.test(acam);
  const ok = res.ok && originAllowed && !!methodsAllowed;
  let message = "";
  if (!res.ok) message = `Preflight returned HTTP ${res.status}`;
  else if (!acao) message = "Response has no Access-Control-Allow-Origin header — CORS not configured";
  else if (!originAllowed) message = `Origin ${origin} not in allowed origins (got "${acao}")`;
  else if (!methodsAllowed) message = `Required methods not allowed (got "${acam ?? "none"}")`;
  return {
    ok,
    allowedOrigin: acao,
    allowedMethods: acam,
    message: ok ? "Preflight OK" : message,
  };
}

// --- Object operations (M3+) -------------------------------------------
//
// signedPut / signedGet / signedDelete are the read/write surface for
// /objects/{uuid} (file ciphertext) and /.crate/{crate.json,manifest.jsonl.enc}
// (metadata). All take a full object URL — callers concatenate the bucket
// base URL with the object key.
//
// Bodies for PUT are Uint8Array or string; sig-v4 needs the SHA-256 of the
// body to be included in the canonical request (R2 + Hetzner reject
// UNSIGNED-PAYLOAD for browser fetch since the browser can't always set
// `x-amz-content-sha256` reliably across providers). For HEAD/GET/DELETE we
// use the empty-body SHA-256.

/**
 * Authenticated PUT. Body MUST be a Uint8Array, string, or ArrayBuffer.
 * Returns { ok, status, etag, code?, message? }. The etag (with surrounding
 * quotes stripped) is what the manifest binds to for change detection.
 */
// signedPut signs and PUTs `body` to `url`. Optional `ifMatch` carries an
// R2/S3 ETag value — when set, R2 will return HTTP 412 (Precondition
// Failed) if the current object's ETag differs. The wildcard "*" means
// "any ETag must exist" (= "object must already exist"); a specific
// quoted-or-unquoted ETag string means "the current ETag must match this
// exact value." Used by SyncClient + crate.js _flushManifest for
// concurrent-write safety.
//
// On 412, callers should treat it as a non-fatal "your view is stale";
// re-GET, replay local events on top of the fresh manifest, retry.
//
// To opt in, pass `ifMatch`; pass `null` or omit to leave unconditional.
export async function signedPut({
  url, body, contentType, ifMatch, region, accessKey, secretKey, signal,
} = {}) {
  if (!url) throw new Error("signedPut: url required");
  if (body == null) throw new Error("signedPut: body required");
  const bodyBytes = body instanceof Uint8Array
    ? body
    : (typeof body === "string"
        ? new TextEncoder().encode(body)
        : new Uint8Array(body));
  const headers = {};
  if (contentType) headers["content-type"] = contentType;
  if (ifMatch) {
    // Tolerate either a quoted "etag" or a bare etag; R2 accepts both but
    // is strict about whitespace.
    const q = /^".*"$/.test(ifMatch) ? ifMatch : `"${ifMatch}"`;
    headers["if-match"] = q;
  }
  const signed = await signRequest({
    method: "PUT",
    url,
    region,
    accessKey,
    secretKey,
    body: bodyBytes,
    headers,
  });
  delete signed.host;
  let res;
  try {
    res = await fetch(url, {
      method: "PUT",
      headers: signed,
      body: bodyBytes,
      signal,
      mode: "cors",
    });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      ok: false, status: 0,
      code: isLikelyCorsError(err) ? "CORS_OR_NETWORK" : "NETWORK_ERROR",
      message: err.message ?? "fetch failed", networkError: true,
    };
  }
  if (res.ok) {
    const etag = (res.headers.get("etag") || "").replace(/^"|"$/g, "");
    return { ok: true, status: res.status, etag };
  }
  if (res.status === 412) {
    // Surface explicitly so callers can branch on "precondition failed"
    // without sniffing the error code.
    return {
      ok: false, status: 412,
      code: "PRECONDITION_FAILED",
      message: "If-Match precondition failed — manifest changed under us",
      preconditionFailed: true,
    };
  }
  const { code, message } = await parseS3Error(res);
  return {
    ok: false, status: res.status,
    code: code ?? `HTTP_${res.status}`,
    message: message ?? res.statusText,
  };
}

/**
 * Authenticated GET. Returns { ok, status, body (Uint8Array), etag, code?, message? }.
 * Body is loaded fully into memory — fine for v1.0 (typical crate files are
 * small; large-file streaming is a later concern).
 */
export async function signedGet({
  url, region, accessKey, secretKey, signal,
} = {}) {
  if (!url) throw new Error("signedGet: url required");
  const signed = await signRequest({
    method: "GET", url, region, accessKey, secretKey,
  });
  delete signed.host;
  let res;
  try {
    res = await fetch(url, { method: "GET", headers: signed, signal, mode: "cors" });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      ok: false, status: 0,
      code: isLikelyCorsError(err) ? "CORS_OR_NETWORK" : "NETWORK_ERROR",
      message: err.message ?? "fetch failed", networkError: true,
    };
  }
  if (res.ok) {
    const etag = (res.headers.get("etag") || "").replace(/^"|"$/g, "");
    const ab = await res.arrayBuffer();
    return { ok: true, status: res.status, etag, body: new Uint8Array(ab) };
  }
  const { code, message } = await parseS3Error(res);
  return {
    ok: false, status: res.status,
    code: code ?? `HTTP_${res.status}`,
    message: message ?? res.statusText,
  };
}

/**
 * Authenticated DELETE. Returns { ok, status, code?, message? }.
 * 204 = success; 404 = already gone (treated as success).
 */
export async function signedDelete({
  url, region, accessKey, secretKey, signal,
} = {}) {
  if (!url) throw new Error("signedDelete: url required");
  const signed = await signRequest({
    method: "DELETE", url, region, accessKey, secretKey,
  });
  delete signed.host;
  let res;
  try {
    res = await fetch(url, { method: "DELETE", headers: signed, signal, mode: "cors" });
  } catch (err) {
    if (isAbortError(err)) throw err;
    return {
      ok: false, status: 0,
      code: isLikelyCorsError(err) ? "CORS_OR_NETWORK" : "NETWORK_ERROR",
      message: err.message ?? "fetch failed", networkError: true,
    };
  }
  // 204 No Content or 200 OK or 404 Not Found = "the bytes are gone"
  if (res.status === 204 || res.status === 200 || res.status === 404) {
    return { ok: true, status: res.status };
  }
  const { code, message } = await parseS3Error(res);
  return {
    ok: false, status: res.status,
    code: code ?? `HTTP_${res.status}`,
    message: message ?? res.statusText,
  };
}
