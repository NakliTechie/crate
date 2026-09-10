// SPDX-License-Identifier: AGPL-3.0-or-later
// Provider-agnostic S3-compatible HTTP client. Uses lib/sigv4.js for
// AWS Signature V4 signing. Targets R2 (launch surface) + Hetzner +
// B2 + AWS S3.
//
// Wizard-stage helpers:
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
//
// Second transport — the carrier. `region === CARRIER_REGION` switches
// every signed call from sig-v4 to the crate-carrier request signature
// (github.com/NakliTechie/crate-carrier): the user's own Worker holding
// an R2 binding, so no API token, no CORS config, no account ID.
//   bucketBase  = endpoints.Carrier(workerUrl)   → "<workerUrl>/o/"
//   accessKey   = CARRIER_ACCESS_KEY (a label; the carrier has no key id)
//   secretKey   = CARRIER_SECRET as set on the Worker
// Call sites are unchanged: they already thread region/accessKey/secretKey.

import { signRequest } from "./sigv4.js";

export const CARRIER_REGION = "carrier";
export const CARRIER_ACCESS_KEY = "carrier";
// Single PUT stays under Cloudflare's 100 MB edge cap; larger bodies go
// through R2 multipart on the carrier. 16 MiB parts clear the 5 MiB minimum.
const CARRIER_SINGLE_PUT_MAX = 90 * 1024 * 1024;
const CARRIER_PART_SIZE = 16 * 1024 * 1024;

export function isCarrier(region) { return region === CARRIER_REGION; }

// cleanEtag strips quotes and a weak-validator prefix. An intermediary
// (Cloudflare's edge on compressed responses) may rewrite "abc" as
// W/"abc"; R2 only ever matches the bare strong value.
export function cleanEtag(raw) {
  return String(raw || "").replace(/^W\//i, "").replace(/^"|"$/g, "");
}

// resolveBase turns a bucketConfig into the base URL every object path
// hangs off. One place for both providers.
export function resolveBase(bucketConfig) {
  if (!bucketConfig) throw new Error("resolveBase: bucketConfig required");
  if (bucketConfig.provider === "carrier" || bucketConfig.region === CARRIER_REGION) {
    if (!bucketConfig.url) throw new Error("resolveBase: carrier url required");
    return endpoints.Carrier(bucketConfig.url);
  }
  if (!bucketConfig.accountId || !bucketConfig.name) throw new Error("resolveBase: accountId + name required");
  return endpoints.R2(bucketConfig.accountId.trim().toLowerCase(), bucketConfig.name.trim());
}

// --- carrier request signature ------------------------------------------
// Mirrors crate-carrier/src/lib.js byte-for-byte:
//   canonical = METHOD \n path \n sorted-query \n ts \n nonce
//   x-crate-sig = hex HMAC-SHA256(secret, canonical)
export function carrierCanonical({ method, path, query, ts, nonce }) {
  const q = query instanceof URLSearchParams ? query : new URLSearchParams(query || "");
  const pairs = [...q.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  return [String(method).toUpperCase(), path, pairs.map(([k, v]) => `${k}=${v}`).join("&"), String(ts), nonce].join("\n");
}

export async function carrierHeaders({ method, url, secretKey, ts = Date.now(), nonce } = {}) {
  const u = new URL(url);
  nonce = nonce || Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, "0")).join("");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secretKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(carrierCanonical({ method, path: u.pathname, query: u.searchParams, ts, nonce })));
  const hex = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
  return { "x-crate-ts": String(ts), "x-crate-nonce": nonce, "x-crate-sig": hex };
}

// authHeaders picks the transport. Returns the headers to send (sig-v4
// drops `host`, which the browser sets itself).
async function authHeaders({ method, url, region, accessKey, secretKey, body, headers }) {
  if (isCarrier(region)) return { ...(headers || {}), ...(await carrierHeaders({ method, url, secretKey })) };
  const signed = await signRequest({ method, url, region, accessKey, secretKey, body, headers });
  delete signed.host;
  return signed;
}

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
  // crate-carrier Worker: objects live under "<workerUrl>/o/<key>".
  Carrier(workerUrl) {
    return String(workerUrl).trim().replace(/\/+$/, "") + "/o/";
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
  const signed = await authHeaders({ method: "HEAD", url, region, accessKey, secretKey });
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

// --- Object operations -------------------------------------------------
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
  if (isCarrier(region) && bodyBytes.length > CARRIER_SINGLE_PUT_MAX) {
    return carrierMultipartPut({ url, bodyBytes, contentType, secretKey, signal });
  }
  const signed = await authHeaders({ method: "PUT", url, region, accessKey, secretKey, body: bodyBytes, headers });
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
    return { ok: true, status: res.status, etag: cleanEtag(res.headers.get("etag")) };
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
  const signed = await authHeaders({ method: "GET", url, region, accessKey, secretKey });
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
    const etag = cleanEtag(res.headers.get("etag"));
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
  const signed = await authHeaders({ method: "DELETE", url, region, accessKey, secretKey });
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

// --- carrier-only helpers -------------------------------------------------

// carrierMultipartPut uploads a body larger than the single-PUT cap as R2
// multipart parts through the carrier. Same return shape as signedPut.
async function carrierMultipartPut({ url, bodyBytes, contentType, secretKey, signal }) {
  const netErr = (err) => ({
    ok: false, status: 0,
    code: isLikelyCorsError(err) ? "CORS_OR_NETWORK" : "NETWORK_ERROR",
    message: err.message ?? "fetch failed", networkError: true,
  });
  const call = async (method, q, body, headers) => {
    const u = new URL(url); u.search = q;
    const h = { ...(headers || {}), ...(await carrierHeaders({ method, url: u.toString(), secretKey })) };
    const res = await fetch(u.toString(), { method, headers: h, body, signal, mode: "cors" });
    let json = null; try { json = await res.json(); } catch {}
    return { res, json };
  };
  let uploadId;
  try {
    const { res, json } = await call("POST", "mpu=create", null, contentType ? { "content-type": contentType } : {});
    if (!res.ok || !json?.uploadId) return { ok: false, status: res.status, code: `HTTP_${res.status}`, message: json?.error ?? "multipart create failed" };
    uploadId = json.uploadId;
    const parts = [];
    for (let n = 1, off = 0; off < bodyBytes.length; n++, off += CARRIER_PART_SIZE) {
      const slice = bodyBytes.subarray(off, Math.min(off + CARRIER_PART_SIZE, bodyBytes.length));
      const { res: pr, json: pj } = await call("PUT", `mpu=part&uploadId=${encodeURIComponent(uploadId)}&n=${n}`, slice);
      if (!pr.ok || !pj?.etag) throw Object.assign(new Error(pj?.error ?? `part ${n} failed`), { status: pr.status, carrier: true });
      parts.push({ partNumber: pj.partNumber, etag: pj.etag });
    }
    const { res: cr, json: cj } = await call("POST", `mpu=complete&uploadId=${encodeURIComponent(uploadId)}`, JSON.stringify(parts), { "content-type": "application/json" });
    if (!cr.ok) return { ok: false, status: cr.status, code: `HTTP_${cr.status}`, message: cj?.error ?? "multipart complete failed" };
    return { ok: true, status: cr.status, etag: cleanEtag(cj?.etag) };
  } catch (err) {
    if (isAbortError(err)) throw err;
    if (uploadId) { try { await call("POST", `mpu=abort&uploadId=${encodeURIComponent(uploadId)}`); } catch {} }
    if (err?.carrier) return { ok: false, status: err.status, code: `HTTP_${err.status}`, message: err.message };
    return netErr(err);
  }
}

// carrierProbe is the wizard's one-shot check: is the Worker up, does it
// have its secret and bucket, and does OUR secret match it. Returns
// { ok, ready, bucket, authorized, status, message }.
export async function carrierProbe({ url, secretKey, signal } = {}) {
  const base = endpoints.Carrier(url);
  const root = base.replace(/\/o\/$/, "/");
  let health;
  try {
    const res = await fetch(root, { signal, mode: "cors" });
    health = res.ok ? await res.json() : null;
    if (!health || health.service !== "crate-carrier") {
      return { ok: false, status: res.status, message: `Not a crate-carrier (${res.status})` };
    }
  } catch (err) {
    if (isAbortError(err)) throw err;
    return { ok: false, status: 0, message: isLikelyCorsError(err) ? "Can't reach the Worker from this origin" : (err.message ?? "fetch failed") };
  }
  if (!health.ready) return { ok: false, ...health, message: "Worker is up but CARRIER_SECRET is not set" };
  if (!health.bucket) return { ok: false, ...health, message: "Worker is up but has no R2 bucket binding" };
  // Signed HEAD of crate.json: 200 or 404 both prove the secret; 401 does not.
  const head = await signedHead({ url: base + ".crate/crate.json", region: CARRIER_REGION, accessKey: CARRIER_ACCESS_KEY, secretKey, signal });
  if (head.status === 401) return { ok: false, ...health, authorized: false, status: 401, message: "Secret does not match the Worker's CARRIER_SECRET" };
  if (!head.ok && head.status !== 404) return { ok: false, ...health, status: head.status, message: head.message };
  return { ok: true, ...health, authorized: true, status: head.status, existing: head.status === 200 };
}
